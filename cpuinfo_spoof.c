// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/utsname.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cpufreq.h>
#include <linux/rwsem.h>
#include <linux/build_bug.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/magic.h>
#include "kirin9020.h"

#define REVISION "qilin-r5-20261028"
#define TARGET_RELEASE "5.15.167-android13-8-o-01144-gb3f32e037fab"
#define MAX_PATCHES 12

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cpuinfo_spoof staged diagnostic " REVISION);
MODULE_VERSION(REVISION);
/* Removed by fix_vermagic.py after fitting the new .modinfo entries. */
MODULE_INFO(qilin_modinfo_reserve, "................................................................................................");

extern struct uts_namespace init_uts_ns;

/* Target-device BTF contract. Refuse a DDK layout that changes these fields. */
static_assert(sizeof(void *) == 8);
static_assert(sizeof(struct device_attribute) == 32);
static_assert(sizeof(struct freq_attr) == 32);
static_assert(offsetof(struct device_attribute, show) == 16);
static_assert(offsetof(struct freq_attr, show) == 16);
static_assert(offsetof(struct device, id) == 772);
static_assert(offsetof(struct uts_namespace, name) == 0);
static_assert(sizeof(struct inode) == 752);
static_assert(sizeof(struct proc_ops) == 96);
static_assert(offsetof(struct proc_ops, proc_open) == 8);
static_assert(offsetof(struct proc_ops, proc_read_iter) == 24);
static_assert(offsetof(struct proc_ops, proc_release) == 48);

/* Target private-proc ABI, obtained from supplied vmlinux.btf SHA256
 * bd86b36efe69b31db35774b33225de222b9716aa40f7089f7efe89741d46fb3a.
 * Never treat these offsets as a generic 5.15 ABI. Runtime identity guards
 * below must also match before this private entry pointer is ever written.
 */
#define PI_VFS_INODE_OFFSET 72
#define PI_PDE_OFFSET 24
#define PDE_BYTES 176
#define PDE_OPS_OFFSET 48
#define PDE_LOW_INO_OFFSET 92
#define PDE_PARENT_OFFSET 120
#define PDE_NAME_OFFSET 160
#define PDE_MODE_OFFSET 168
#define PDE_FLAGS_OFFSET 170

static char *stage = "inspect";
module_param(stage, charp, 0444);
static bool pointer_tests;
module_param(pointer_tests, bool, 0444);
/* Recognize old invocations but reject them rather than enable several paths. */
static int spoof_enable, spoof_uts, spoof_cpuinfo, spoof_online;
static int spoof_topology, spoof_cpufreq, spoof_related, spoof_affinity;
module_param(spoof_enable, int, 0444);
module_param(spoof_uts, int, 0444);
module_param(spoof_cpuinfo, int, 0444);
module_param(spoof_online, int, 0444);
module_param(spoof_topology, int, 0444);
module_param(spoof_cpufreq, int, 0444);
module_param(spoof_related, int, 0444);
module_param(spoof_affinity, int, 0444);

static unsigned long (*lookup_fn)(const char *);
static unsigned long data_start, data_end, ro_start, ro_end;
static struct rw_semaphore *target_uts_sem;
static struct proc_dir_entry *control;
static unsigned int planned, applied;
static int last_error;
static int check_uts = -EAGAIN, check_cpuinfo = -EAGAIN;
static int check_cpus = -EAGAIN, check_topology = -EAGAIN, check_cpufreq = -EAGAIN;
static bool pinned, wants_uts, wants_cpuinfo, uts_applied;
static struct path cpuinfo_path;
static bool cpuinfo_path_held;
static struct proc_ops cpuinfo_ops_clone;
static void *validated_cpuinfo_slot;
static char outcome[32] = "inspect_only";
static char original_release[__NEW_UTS_LEN + 1];

struct patch {
	void **slot;
	void *before;
	void *after;
	const char *name;
};
static struct patch patches[MAX_PATCHES];

/* register_kprobe yields a raw function entry, not a canonical CFI jump-table
 * pointer. Limit nocfi to this one precisely typed resolver call. Callback
 * type checks remain enabled; no kernel instructions or CFI tables are edited.
 */
static noinline unsigned long __nocfi resolve(const char *name)
{
	return lookup_fn(name);
}

static int resolver_init(void)
{
	struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&probe);

	if (ret)
		return ret;
	lookup_fn = (void *)probe.addr;
	unregister_kprobe(&probe);
	if (!lookup_fn)
		return -ENOENT;
	if (resolve("init_uts_ns") != (unsigned long)&init_uts_ns)
		return -ESTALE;
	data_start = resolve("_sdata");
	data_end = resolve("_edata");
	ro_start = resolve("__start_rodata");
	ro_end = resolve("__end_rodata");
	if (!data_start || data_end <= data_start || !ro_start || ro_end <= ro_start)
		return -EINVAL;
	pr_info("cpuinfo_spoof: data=[%px,%px) rodata=[%px,%px)\n",
		(void *)data_start, (void *)data_end, (void *)ro_start, (void *)ro_end);
	return 0;
}

static bool writable_profile(unsigned long address, size_t length)
{
	/* Conservative target-image range check, not a page-table permission test.
	 * No fallback to set_memory_rw, update_mapping_prot, or bind mounts.
	 */
	return length && address >= data_start && address < data_end &&
		length <= data_end - address &&
		!(address < ro_end && address + length > ro_start);
}

static int read_name(const char *source, char *dest, size_t capacity)
{
	size_t i;

	if (!source)
		return -EINVAL;
	for (i = 0; i < capacity; i++) {
		if (copy_from_kernel_nofault(dest + i, source + i, 1))
			return -EFAULT;
		if (!dest[i])
			return 0;
	}
	return -ENAMETOOLONG;
}

static bool callback_named(void *address, const char *expected)
{
	char symbol[160];
	snprintf(symbol, sizeof(symbol), "%ps", address);
	if (!strcmp(symbol, expected))
		return true;
	return !strncmp(symbol, expected, strlen(expected)) &&
		!strcmp(symbol + strlen(expected), ".cfi_jt");
}

static int plan_patch(void **slot, void *old, void *replacement,
		      const char *name, const char *callback)
{
	unsigned int i;

	if (planned >= MAX_PATCHES || !old || !replacement)
		return -EINVAL;
	for (i = 0; i < planned; i++)
		if (patches[i].slot == slot)
			return -EEXIST;
	if (!writable_profile((unsigned long)slot, sizeof(*slot)) ||
	    !IS_ALIGNED((unsigned long)slot, sizeof(*slot)))
		return -EACCES;
	if (!callback_named(old, callback)) {
		pr_err("cpuinfo_spoof: REJECT %s callback=%ps expected=%s\n",
			name, old, callback);
		return -EPROTOTYPE;
	}
	patches[planned++] = (struct patch) {
		.slot = slot, .before = old, .after = replacement, .name = name,
	};
	pr_info("cpuinfo_spoof: PREPARED %s original=%ps slot=%px\n", name, old, slot);
	return 0;
}

static ssize_t fake_cpu_mask(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	(void)dev; (void)attr;
	return sysfs_emit(buf, "0-%d\n", FAKE_N_CPUS - 1);
}

static ssize_t fake_topology(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	int cpu = dev->id;

	if (cpu < 0 || cpu >= FAKE_N_CPUS)
		return -EINVAL;
	if (!strcmp(attr->attr.name, "core_id"))
		return sysfs_emit(buf, "%d\n", fake_core_id[cpu]);
	if (!strcmp(attr->attr.name, "physical_package_id"))
		return sysfs_emit(buf, "%d\n", fake_pkg_id[cpu]);
	if (!strcmp(attr->attr.name, "die_id"))
		return sysfs_emit(buf, "%d\n", FAKE_DIE_ID);
	return -EINVAL;
}

/* These are freq_attr callbacks, not device_attribute callbacks. */
static ssize_t fake_available(struct cpufreq_policy *policy, char *buf)
{
	(void)policy;
	return sysfs_emit(buf, "%s\n", FAKE_AVAIL_FREQS);
}

static ssize_t fake_boost(struct cpufreq_policy *policy, char *buf)
{
	(void)policy;
	return sysfs_emit(buf, "%s\n", FAKE_BOOST_FREQS);
}

static_assert(__same_type(((struct freq_attr *)0)->show, &fake_available));
static_assert(__same_type(((struct freq_attr *)0)->show, &fake_boost));
static_assert(__same_type(((struct device_attribute *)0)->show, &fake_cpu_mask));
static_assert(__same_type(((struct device_attribute *)0)->show, &fake_topology));

/* One seq record per open, static operations: seq_release remains compatible
 * with both old cpuinfo_open FDs and new module-opened FDs. No single_open /
 * single_release allocation is introduced and no per-open allocation escapes.
 */
static void *fake_cpuinfo_start(struct seq_file *m, loff_t *pos)
{
	(void)m;
	return *pos == 0 ? (void *)1 : NULL;
}

static void *fake_cpuinfo_next(struct seq_file *m, void *record, loff_t *pos)
{
	(void)m; (void)record;
	++*pos;
	return NULL;
}

static void fake_cpuinfo_stop(struct seq_file *m, void *record)
{
	(void)m; (void)record;
}

static int fake_cpuinfo_show(struct seq_file *m, void *record)
{
	unsigned int cpu;

	(void)record;
	for (cpu = 0; cpu < FAKE_N_CPUS; cpu++) {
		seq_printf(m, "processor\t: %u\n", cpu);
		seq_printf(m, "BogoMIPS\t: %s\n", FAKE_BOGOMIPS);
		seq_printf(m, "Features\t: %s\n", FAKE_FEATURES);
		seq_printf(m, "CPU implementer\t: 0x%x\n", FAKE_IMPLEMENTER);
		seq_printf(m, "CPU architecture: %u\n", FAKE_ARCH);
		seq_printf(m, "CPU variant\t: 0x%x\n", FAKE_VARIANT);
		seq_printf(m, "CPU part\t: 0x%03x\n", fake_cpu_part[cpu]);
		seq_printf(m, "CPU revision\t: %u\n\n", FAKE_REVISION);
	}
	seq_printf(m, "Hardware\t: %s\n", FAKE_HARDWARE);
	return 0;
}

static const struct seq_operations fake_cpuinfo_seq_ops = {
	.start = fake_cpuinfo_start,
	.next = fake_cpuinfo_next,
	.stop = fake_cpuinfo_stop,
	.show = fake_cpuinfo_show,
};
static_assert(__same_type(((struct seq_operations *)0)->show, &fake_cpuinfo_show));
static_assert(__same_type(((struct seq_operations *)0)->start, &fake_cpuinfo_start));
static_assert(__same_type(((struct seq_operations *)0)->next, &fake_cpuinfo_next));
static_assert(__same_type(((struct seq_operations *)0)->stop, &fake_cpuinfo_stop));

static void (*arch_prepare_fn)(void);
static noinline void __nocfi prepare_cpuinfo_arch(void)
{
	arch_prepare_fn();
}

static int fake_cpuinfo_open(struct inode *inode, struct file *file)
{
	(void)inode;
	/* Preserve original cpuinfo_open's arch_freq_prepare_all side effect. */
	prepare_cpuinfo_arch();
	return seq_open(file, &fake_cpuinfo_seq_ops);
}
static_assert(__same_type(((struct proc_ops *)0)->proc_open, &fake_cpuinfo_open));

static void release_cpuinfo_path(void)
{
	if (cpuinfo_path_held) {
		path_put(&cpuinfo_path);
		cpuinfo_path_held = false;
	}
}

static int plan_cpuinfo(void)
{
	struct inode *inode;
	unsigned long inode_address, pde, original_ops;
	unsigned long parent, ops_address = resolve("cpuinfo_proc_ops");
	const char *name_ptr;
	struct proc_ops original;
	char name[24];
	u32 low_ino;
	umode_t mode;
	u8 flags;
	int ret;

	/* The private offsets above are target-specific. Check inode, PDE name,
	 * parent, inode number and exact operations identity before any write.
	 */
	ret = kern_path("/proc/cpuinfo", LOOKUP_FOLLOW, &cpuinfo_path);
	if (ret)
		return ret;
	cpuinfo_path_held = true;
	inode = d_inode(cpuinfo_path.dentry);
	if (!inode || inode->i_sb->s_magic != PROC_SUPER_MAGIC || !S_ISREG(inode->i_mode))
		return -EINVAL;
	inode_address = (unsigned long)inode;
	ret = copy_from_kernel_nofault(&pde,
		(void *)(inode_address - PI_VFS_INODE_OFFSET + PI_PDE_OFFSET), sizeof(pde));
	if (ret || !pde || !IS_ALIGNED(pde, sizeof(void *)))
		return ret ? ret : -EINVAL;
	if ((long)pde >= 0 || pde > ULONG_MAX - PDE_BYTES ||
	    (pde >= ro_start && pde < data_end))
		return -EACCES;
#define READ_PDE(field, offset) do { \
	ret = copy_from_kernel_nofault(&(field), (void *)(pde + (offset)), sizeof(field)); \
	if (ret) return ret; \
} while (0)
	READ_PDE(original_ops, PDE_OPS_OFFSET);
	READ_PDE(low_ino, PDE_LOW_INO_OFFSET);
	READ_PDE(parent, PDE_PARENT_OFFSET);
	READ_PDE(name_ptr, PDE_NAME_OFFSET);
	READ_PDE(mode, PDE_MODE_OFFSET);
	READ_PDE(flags, PDE_FLAGS_OFFSET);
#undef READ_PDE
	ret = read_name(name_ptr, name, sizeof(name));
	if (ret || strcmp(name, "cpuinfo") || low_ino != inode->i_ino ||
	    parent != resolve("proc_root") || !S_ISREG(mode))
		return ret ? ret : -ESTALE;
	if (!ops_address || original_ops != ops_address ||
	    ops_address < ro_start || ops_address >= ro_end ||
	    sizeof(original) > ro_end - ops_address)
		return -ESTALE;
	ret = copy_from_kernel_nofault(&original, (void *)original_ops, sizeof(original));
	if (ret)
		return ret;
	pr_info("cpuinfo_spoof: CPUINFO_ORIGINAL open=%ps read=%ps iter=%ps seek=%ps release=%ps ops_flags=%u pde_flags=%u\n",
		original.proc_open, original.proc_read, original.proc_read_iter,
		original.proc_lseek, original.proc_release, original.proc_flags, flags);
	if (!callback_named((void *)original.proc_open, "cpuinfo_open") ||
	    !callback_named((void *)original.proc_lseek, "seq_lseek") ||
	    !callback_named((void *)original.proc_release, "seq_release") ||
	    original.proc_write || original.proc_poll || original.proc_ioctl ||
	    original.proc_compat_ioctl || original.proc_mmap || original.proc_get_unmapped_area)
		return -EPROTOTYPE;
	/* Original inode dispatch was chosen at creation. Preserve read/read_iter
	 * shape and all flags, including the kernel's PERMANENT bit (numeric 1).
	 * PROC_ENTRY_PERMANENT is 0 when compiled as MODULE: never reconstruct it.
	 */
	if (original.proc_read_iter) {
		if (original.proc_read ||
		    !callback_named((void *)original.proc_read_iter, "seq_read_iter"))
			return -EPROTOTYPE;
	} else if (!callback_named((void *)original.proc_read, "seq_read")) {
		return -EPROTOTYPE;
	}
	if (!(flags & 1) || !(original.proc_flags & 1))
		return -ESTALE;
	arch_prepare_fn = (void *)resolve("arch_freq_prepare_all");
	if (!arch_prepare_fn)
		return -ENOENT;
	cpuinfo_ops_clone = original;
	cpuinfo_ops_clone.proc_open = fake_cpuinfo_open;
	if (planned >= MAX_PATCHES)
		return -E2BIG;
	validated_cpuinfo_slot = (void *)(pde + PDE_OPS_OFFSET);
	patches[planned++] = (struct patch) {
		.slot = validated_cpuinfo_slot, .before = (void *)original_ops,
		.after = &cpuinfo_ops_clone, .name = "cpuinfo_proc_ops_pointer",
	};
	pr_info("cpuinfo_spoof: CPUINFO_PREPARED pde=%px slot=%px original=%ps flags=%u read_iter=%d\n",
		(void *)pde, validated_cpuinfo_slot, (void *)original_ops, flags,
		original.proc_read_iter != NULL);
	return 0;
}

static int plan_device(struct device_attribute *object, const char *name,
		       const char *expected,
		       ssize_t (*replacement)(struct device *, struct device_attribute *, char *))
{
	struct device_attribute snapshot;
	char actual[64];
	int ret;

	if (!writable_profile((unsigned long)object, sizeof(snapshot)))
		return -EACCES;
	ret = copy_from_kernel_nofault(&snapshot, object, sizeof(snapshot));
	if (ret)
		return ret;
	ret = read_name(snapshot.attr.name, actual, sizeof(actual));
	if (ret || strcmp(actual, name))
		return ret ? ret : -EINVAL;
	return plan_patch((void **)&object->show, (void *)snapshot.show,
		(void *)replacement, name, expected);
}

static int plan_frequency(const char *symbol, const char *name,
			  const char *expected,
			  ssize_t (*replacement)(struct cpufreq_policy *, char *))
{
	struct freq_attr *object = (void *)resolve(symbol);
	struct freq_attr snapshot;
	char actual[64];
	int ret;

	if (!writable_profile((unsigned long)object, sizeof(snapshot)))
		return -EACCES;
	ret = copy_from_kernel_nofault(&snapshot, object, sizeof(snapshot));
	if (ret)
		return ret;
	ret = read_name(snapshot.attr.name, actual, sizeof(actual));
	if (ret || strcmp(actual, name))
		return ret ? ret : -EINVAL;
	return plan_patch((void **)&object->show, (void *)snapshot.show,
		(void *)replacement, name, expected);
}

static int plan_cpu_roots(void)
{
	/* Enumerate the CPU root group's real attribute objects. In this target,
	 * online/possible/present are entries of cpu_attrs (dev_ext_attribute),
	 * not the unrelated per-device dev_attr_online symbol.
	 */
	unsigned long array = resolve("cpu_root_attrs");
	unsigned int i, found = 0;

	if (!array)
		return -ENOENT;
	for (i = 0; i < 16; i++) {
		struct attribute *entry;
		struct attribute snapshot;
		char name[64];
		int ret;

		if (!writable_profile(array + i * sizeof(entry), sizeof(entry)))
			return -EACCES;
		ret = copy_from_kernel_nofault(&entry, (void *)(array + i * sizeof(entry)), sizeof(entry));
		if (ret)
			return ret;
		if (!entry)
			break;
		ret = copy_from_kernel_nofault(&snapshot, entry, sizeof(snapshot));
		if (ret)
			return ret;
		ret = read_name(snapshot.name, name, sizeof(name));
		if (ret)
			return ret;
		if (strcmp(name, "online") && strcmp(name, "possible") && strcmp(name, "present"))
			continue;
		/* Store a constant label, not a pointer to the stack-local name. */
		ret = plan_device((void *)entry,
			!strcmp(name, "online") ? "online" :
			!strcmp(name, "possible") ? "possible" : "present",
			"show_cpus_attr", fake_cpu_mask);
		if (ret)
			return ret;
		found++;
	}
	return found == 3 ? 0 : -ENOENT;
}

static int plan_topology(void)
{
	int ret;

	ret = plan_device((void *)resolve("dev_attr_core_id"), "core_id", "core_id_show", fake_topology);
	if (ret)
		return ret;
	ret = plan_device((void *)resolve("dev_attr_physical_package_id"),
		"physical_package_id", "physical_package_id_show", fake_topology);
	if (ret)
		return ret;
	return plan_device((void *)resolve("dev_attr_die_id"), "die_id", "die_id_show", fake_topology);
}

static int plan_cpufreq(void)
{
	int ret = plan_frequency("cpufreq_freq_attr_scaling_available_freqs",
		"scaling_available_frequencies", "scaling_available_frequencies_show", fake_available);
	if (ret)
		return ret;
	return plan_frequency("cpufreq_freq_attr_scaling_boost_freqs",
		"scaling_boost_frequencies", "scaling_boost_frequencies_show", fake_boost);
}

static void pin_before_publish(void)
{
	if (!pinned) {
		__module_get(THIS_MODULE);
		pinned = true;
	}
}

static int plan_uts(void)
{
	int ret = 0;

	target_uts_sem = (void *)resolve("uts_sem");
	if (!writable_profile((unsigned long)target_uts_sem, sizeof(*target_uts_sem)) ||
	    !writable_profile((unsigned long)&init_uts_ns.name, sizeof(init_uts_ns.name)))
		return -EACCES;
	down_read(target_uts_sem);
	if (strcmp(init_uts_ns.name.release, TARGET_RELEASE))
		ret = -ESTALE;
	up_read(target_uts_sem);
	return ret;
}

static int validate_pointer_snapshots(void)
{
	unsigned int i;

	for (i = 0; i < planned; i++) {
		void *observed_ptr;
		int ret = copy_from_kernel_nofault(&observed_ptr, patches[i].slot, sizeof(observed_ptr));

		if (ret)
			return ret;
		if (observed_ptr != patches[i].before)
			return -EBUSY;
	}
	return 0;
}

/* Preflight is read-only. Publishing several global pointers is NOT atomic.
 * A late conflict leaves a resident partial instance with an explicit status;
 * never return an init error after a callback has become reachable.
 */
static int publish_selected(void)
{
	unsigned int i;
	int ret;

	if (wants_uts)
		down_write(target_uts_sem);
	if (wants_uts && strcmp(init_uts_ns.name.release, TARGET_RELEASE)) {
		ret = -ESTALE;
		goto no_publish;
	}
	ret = validate_pointer_snapshots();
	if (ret)
		goto no_publish;
	pin_before_publish();
	for (i = 0; i < planned; i++) {
		struct patch *p = &patches[i];

		pr_info("cpuinfo_spoof: BEFORE_WRITE %s\n", p->name);
		if (cmpxchg(p->slot, p->before, p->after) != p->before) {
			last_error = -EBUSY;
			strscpy(outcome, "partial_conflict", sizeof(outcome));
			goto resident;
		}
		applied++;
		pr_info("cpuinfo_spoof: AFTER_WRITE %s\n", p->name);
	}
	if (wants_uts) {
		pr_info("cpuinfo_spoof: BEFORE_WRITE uts_release\n");
		strscpy(init_uts_ns.name.release, FAKE_UTS_RELEASE, sizeof(init_uts_ns.name.release));
		uts_applied = true;
		pr_info("cpuinfo_spoof: AFTER_WRITE uts_release\n");
	}
	strscpy(outcome, "active", sizeof(outcome));
resident:
	if (wants_uts)
		up_write(target_uts_sem);
	return 0;
no_publish:
	if (wants_uts)
		up_write(target_uts_sem);
	return ret;
}

static void inspect_symbols(void)
{
	unsigned long cpuinfo = resolve("cpuinfo_op");

	pr_info("cpuinfo_spoof: cpuinfo_op=%px in_rodata=%d; writes held\n",
		(void *)cpuinfo, cpuinfo >= ro_start && cpuinfo < ro_end);
	pr_info("cpuinfo_spoof: cpu_root_attrs=%px cpu_attrs=%px\n",
		(void *)resolve("cpu_root_attrs"), (void *)resolve("cpu_attrs"));
	pr_info("cpuinfo_spoof: callbacks retain CFI; affinity/related/getdents are held\n");
	if (!strcmp(stage, "inspect")) {
		check_uts = plan_uts();
		check_cpus = plan_cpu_roots();
		planned = 0;
		check_topology = plan_topology();
		planned = 0;
		check_cpufreq = plan_cpufreq();
		planned = 0;
		check_cpuinfo = plan_cpuinfo();
		planned = 0;
		release_cpuinfo_path();
		pr_info("cpuinfo_spoof: READ_ONLY_PREFLIGHT uts=%d cpus=%d topology=%d cpufreq=%d cpuinfo=%d\n",
			check_uts, check_cpus, check_topology, check_cpufreq, check_cpuinfo);
	}
}

static int status_show(struct seq_file *m, void *unused)
{
	(void)unused;
	seq_printf(m, "revision=%s\nstage=%s\nstate=%s\nplanned=%u\napplied=%u\nlast_error=%d\npinned=%d\noriginal_release=%s\n",
		REVISION, stage, outcome, planned + (wants_uts ? 1U : 0U),
		applied + (uts_applied ? 1U : 0U), last_error, pinned, original_release);
	seq_printf(m, "pointer_planned=%u\npointer_applied=%u\nuts_applied=%d\n",
		planned, applied, uts_applied);
	seq_printf(m, "preflight_uts=%d\npreflight_cpus=%d\npreflight_topology=%d\npreflight_cpufreq=%d\n",
		check_uts, check_cpus, check_topology, check_cpufreq);
	seq_printf(m, "preflight_cpuinfo=%d\ncpuinfo=%s\n", check_cpuinfo,
		wants_cpuinfo && applied == planned && planned ? "pde_pointer_active" : "not_active");
	seq_puts(m, "affinity=held\nrelated=held\nmounts=none\n");
	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	(void)inode;
	return single_open(file, status_show, NULL);
}

static const struct proc_ops status_ops = {
	.proc_open = status_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init spoof_init(void)
{
	int ret;
	bool pointer_stage, combo, full;
	bool wants_cpus, wants_topology, wants_cpufreq;

	pr_info("cpuinfo_spoof: BEGIN revision=%s stage=%s\n", REVISION, stage);
	if (spoof_enable || spoof_uts || spoof_cpuinfo || spoof_online ||
	    spoof_topology || spoof_cpufreq || spoof_related || spoof_affinity) {
		pr_err("cpuinfo_spoof: legacy multi-switch invocation rejected; use stage=inspect or stage=uts\n");
		return -EINVAL;
	}
	full = !strcmp(stage, "full");
	combo = full || !strcmp(stage, "combo");
	wants_cpuinfo = full || !strcmp(stage, "cpuinfo");
	wants_uts = combo || !strcmp(stage, "uts");
	wants_cpus = combo || !strcmp(stage, "cpus");
	wants_topology = combo || !strcmp(stage, "topology");
	wants_cpufreq = combo || !strcmp(stage, "cpufreq");
	pointer_stage = wants_cpus || wants_topology || wants_cpufreq || wants_cpuinfo;
	if (strcmp(stage, "inspect") && !wants_uts && !pointer_stage)
		return -EOPNOTSUPP;
	if (pointer_stage && !pointer_tests)
		return -EPERM;
	strscpy(original_release, init_uts_ns.name.release, sizeof(original_release));
	if (strcmp(original_release, TARGET_RELEASE))
		return -ESTALE;
	ret = resolver_init();
	if (ret)
		return ret;
	inspect_symbols();
	ret = 0;
	if (wants_uts) {
		check_uts = plan_uts();
		if (check_uts)
			ret = check_uts;
	}
	if (wants_cpus && !ret) {
		check_cpus = plan_cpu_roots();
		ret = check_cpus;
	}
	if (wants_topology && !ret) {
		check_topology = plan_topology();
		ret = check_topology;
	}
	if (wants_cpufreq && !ret) {
		check_cpufreq = plan_cpufreq();
		ret = check_cpufreq;
	}
	if (wants_cpuinfo && !ret) {
		check_cpuinfo = plan_cpuinfo();
		ret = check_cpuinfo;
	}
	if (!ret && combo && planned != (full ? 9U : 8U))
		ret = -EINVAL;
	if (ret) {
		pr_err("cpuinfo_spoof: PREFLIGHT_FAILED stage=%s rc=%d; no writes published\n", stage, ret);
		release_cpuinfo_path();
		return ret;
	}
	control = proc_create("cpuinfo_spoof", 0444, NULL, &status_ops);
	if (!control) {
		release_cpuinfo_path();
		return -ENOMEM;
	}
	if (wants_uts || pointer_stage) {
		ret = publish_selected();
		if (ret) {
			/* publish_selected returns an error only BEFORE pinning/writing. */
			proc_remove(control);
			release_cpuinfo_path();
			return ret;
		}
	}
	pr_info("cpuinfo_spoof: END state=%s planned=%u applied=%u error=%d\n",
		outcome, planned + (wants_uts ? 1U : 0U),
		applied + (uts_applied ? 1U : 0U), last_error);
	return 0;
}

static void __exit spoof_exit(void)
{
	/* A modified instance is pinned. No live callback code can be unloaded.
	 * This is a lifetime guard, not a claim about the historical crash cause.
	 * An inspect-only instance has never published callback pointers.
	 */
	proc_remove(control);
	release_cpuinfo_path();
}
module_init(spoof_init);
module_exit(spoof_exit);
