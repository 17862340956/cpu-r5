# r5：CPUINFO proc入口数据指针 + 已验证的r4组合

版本：qilin-r5-20261028。目标release仍为5.15.167-android13-8-o-01144-gb3f32e037fab。

## 本轮改动

r4已经在目标手机完成组合：8个展示回调+1个UTS release，三轮97项检查通过。r5保持这四个回调实现逐字节不变，只增加CPUINFO proc入口操作表指针，full总计9个数据指针+1项UTS=10项修改。

不再写只读cpuinfo_op，也不写只读cpuinfo_proc_ops。通过kern_path定位/proc/cpuinfo的真实inode，按所提供BTF取其proc_dir_entry；核对文件系统、inode类型、PDE名称/父目录/编号、原始操作表身份和每个原回调后，复制整张proc_ops到模块静态数据，仅替换副本的proc_open，再用cmpxchg切换PDE的表指针。

新open使用seq_open(file,&模块静态seq_operations)，保留原read/read_iter、lseek、seq_release和flags；保留原arch_freq_prepare_all调用。没有引入single_open/single_release配对变化，因此修改前打开的旧fd可继续使用原seq表，新fd使用模块seq表。发布前pin模块，保持两张表和回调有效到重启，不支持卸载/动态恢复。

新增CPUINFO显示12个processor、implementer=0x48、原项目4+6+2 part预设、Hardware=HUAWEI Kirin9020；Features沿用现有不含SVE的项目预设。显示预设不是新核实的华为硬件数据，也没有增加真实CPU。

## 证据与限制

目标BTF SHA256：bd86b36efe69b31db35774b33225de222b9716aa40f7089f7efe89741d46fb3a。

private proc布局：proc_inode.vfs_inode+72、pde+24；PDE.proc_ops+48、low_ino+92、parent+120、name+160、mode+168、flags+170，PDE大小176。

这些不是通用内核ABI，只适用于已提供的目标布局。编译期核对公开结构大小与关键偏移，运行时再核对对象身份；任何差异在发布前报错。PDE通常来自可写slab，但BTF不证明实时页权限；当前没有目标页表实值，因此这是经过核对的新候选路径，不能承诺运行稳定。

同设备系列OnePlus Android15公开源码支持原cpuinfo_open=arch_freq_prepare_all+seq_open，原表read_iter=seq_read_iter、release=seq_release。公开厂商分支不是精确目标提交的证明，运行时回调核对仍必须通过：

- https://raw.githubusercontent.com/OnePlusOSS/android_kernel_common_oneplus_sm8550/oneplus/sm8550_v_15.0.0_oneplus11/fs/proc/cpuinfo.c
- 同目录inode.c、generic.c、internal.h用于核对PDE分发和永久入口行为。

同分支hardening源码在cpuinfo_open上有kretprobe计数逻辑；目标运行模块的确切行为未验证。替换入口不应被描述为已排除所有厂商干预。

没有inline hook、挂载、修改页表/页权限；不改真实调度器cpumask；不创建cpu8-11；nproc/affinity/related仍关闭。完整topology mask/siblings仍未补齐。系统/GPU属性不混进内核实验，避免一次失败源头不明。

## 一次完整上传

上传本ZIP解压内容到仓库根目录，不套一层目录，更新全部7个根文件与workflow：

```
cpuinfo_spoof.c
kirin9020.h
Makefile
fix_vermagic.py
verify_module.py
test_build_tools.py
cpu_test.sh
.github/workflows/build.yml
```

Actions选择Build cpuinfo_spoof r5。DDK只编译/修vermagic；独立标准Python任务负责pip及ELF/DWARF校验。Fix vermagic步骤保留；正式校验新增CPUINFO open/show函数参数，旧版本不接受。

只下载最终cpuinfo_spoof-r5，不用intermediate-unverified-do-not-load。先将最终ZIP发来做实际二进制核对。

## 手机一次组合验证

无需重复r4单项测试。实际r5 KO核对后：

1. KO、build_report.json、cpu_test.sh三个文件一起放/data/adb/qilin_r5/。
2. 保持旧开机加载项禁用，重启清理r4驻留实例。
3. MT管理器对cpu_test.sh选择ROOT执行，选6（stage=full）。
4. 发送生成的qilin_r5_时间_编号.tar.gz。

如果仅想隔离新增CPUINFO，选8；选1仍是可选只读预检，不要求在full前另跑一轮。不再使用旧的verify/load_verify或stage_test all。

full预期：

```
revision=qilin-r5-20261028
stage=full
state=active
planned=10
applied=10
pointer_applied=9
uts_applied=1
preflight_cpuinfo=0
cpuinfo=pde_pointer_active
last_error=0
```

这次SH合并检查：

- 在insmod前保留一个CPUINFO fd，修改后读取并关闭，记录旧fd视图。
- 打开新fd，检查12核/0x48/Hardware。
- 同一新fd按1字节、7字节、4096字节和余量读完，结果与一次读完比较，再验证EOF。
- 重复三轮新打开读取，与r4展示结果一起验证。

短读测试同时覆盖输出超过页大小时的seq_file扩容行为，但只有真实上机结果能证明内核路径成功。SH本地隔离测试只使用普通文件和假的insmod，不声称替代内核验证。

r5实例和新打开的fd在本次启动内常驻；不卸载、不动态还原。若发布中发现并发冲突，报告partial_conflict并保持模块有效，不在仍有回调指针时释放代码；重启清理。

## 本地核验范围

19项Python测试含旧KO拦截、modinfo边界、两种依赖环境、r4回调指纹和新增CPUINFO约束；Android sh -n语法检查及隔离SH全流程普通文件模拟。不含目标内核编译、实际PDE写入、并发内核压力测试。未自动加载任何新模块。
