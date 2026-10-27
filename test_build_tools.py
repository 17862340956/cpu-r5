import struct
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import builtins
import importlib.util
import hashlib
import re

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fix_vermagic import TARGET, REVISION, SIGNATURE, entries, field, patched, section
from verify_module import verify


def sample(values=None, capacity=384, machine=183):
    values = values or [b"name=cpuinfo_spoof", b"depends=", b"version=" + REVISION,
                        b"vermagic=5.15.202-test SMP preempt mod_unload modversions aarch64"]
    strings = b"\0.shstrtab\0.modinfo\0.text\0"
    modinfo = b"\0".join(values) + b"\0"
    if len(modinfo) > capacity:
        raise ValueError("fixture overflow")
    data = bytearray(64 + len(strings) + capacity + 8)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    strings_at = 64
    info_at = strings_at + len(strings)
    text_at = info_at + capacity
    data[strings_at:info_at] = strings
    data[info_at:info_at + len(modinfo)] = modinfo
    data[text_at:text_at + 8] = b"TEXTMARK"
    headers_at = len(data)
    struct.pack_into("<HHI", data, 16, 1, machine, 1)
    struct.pack_into("<Q", data, 40, headers_at)
    struct.pack_into("<HHHHHH", data, 52, 64, 0, 0, 64, 4, 1)
    data.extend(b"\0" * (4 * 64))
    for idx, name, start, size, kind in [(1, 1, strings_at, len(strings), 3),
                                        (2, 11, info_at, capacity, 1),
                                        (3, 20, text_at, 8, 1)]:
        struct.pack_into("<IIQQQQIIQQ", data, headers_at + idx * 64,
                         name, kind, 0, 0, start, size, 0, 0, 1, 0)
    return bytes(data)


class BuildToolsTests(unittest.TestCase):
    def test_section_limited_and_idempotent(self):
        before = sample()
        after = patched(before)
        start, size = section(before, b".modinfo")
        self.assertEqual(before[:start], after[:start])
        self.assertEqual(before[start + size:], after[start + size:])
        self.assertEqual(len(before), len(after))
        self.assertEqual(after, patched(after))
        self.assertEqual(field(entries(after), b"name"), b"cpuinfo_spoof")
        self.assertTrue(field(entries(after), b"vermagic").startswith(TARGET + b" "))

    def test_unordered_fields_and_reserve(self):
        values = [b"qilin_modinfo_reserve=" + b"." * 96, b"depends=abc",
                  b"vermagic=x SMP preempt", b"name=cpuinfo_spoof", b"version=" + REVISION]
        after = entries(patched(sample(values)))
        self.assertEqual(field(after, b"depends"), b"abc")
        self.assertFalse(any(x.startswith(b"qilin_modinfo_reserve=") for x in after))

    def test_overflow_refused(self):
        with self.assertRaises(ValueError):
            patched(sample([b"name=cpuinfo_spoof", b"vermagic=x SMP"], capacity=40))

    def test_signed_module_refused(self):
        with self.assertRaises(ValueError):
            patched(sample() + SIGNATURE)

    def test_duplicate_vermagic_refused(self):
        with self.assertRaises(ValueError):
            patched(sample([b"name=cpuinfo_spoof", b"vermagic=x SMP", b"vermagic=y SMP"]))

    def test_unterminated_modinfo_refused(self):
        data = bytearray(sample())
        start, size = section(data, b".modinfo")
        data[start + size - 1] = ord('x')
        with self.assertRaisesRegex(ValueError, "unterminated"):
            patched(bytes(data))

    def test_architecture_refused(self):
        with self.assertRaises(ValueError):
            patched(sample(machine=62))

    def test_old_revision_refused(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample([b"name=cpuinfo_spoof", b"version=old", b"vermagic=x SMP"])))
            with self.assertRaisesRegex(ValueError, "revision"):
                verify(path, require_dwarf=False)

    def test_identity_fixture(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            report = verify(path, require_dwarf=False)
            self.assertEqual(report["revision"], REVISION.decode())
            self.assertEqual(report["dwarf"], "not_checked")

    def test_identity_never_imports_elftools(self):
        original_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name == "elftools" or name.startswith("elftools."):
                raise AssertionError("identity-only verification must not import pyelftools")
            return original_import(name, *args, **kwargs)
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            with patch("builtins.__import__", side_effect=guarded):
                self.assertEqual(verify(path, require_dwarf=False)["dwarf"], "not_checked")

    def test_strict_requires_elftools(self):
        original_import = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name == "elftools" or name.startswith("elftools."):
                raise ImportError("simulated missing pyelftools")
            return original_import(name, *args, **kwargs)
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            with patch("builtins.__import__", side_effect=unavailable):
                with self.assertRaisesRegex(RuntimeError, "pyelftools is required"):
                    verify(path)

    @unittest.skipUnless(importlib.util.find_spec("elftools"), "pyelftools not installed")
    def test_strict_rejects_fixture_without_dwarf(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            with self.assertRaisesRegex(ValueError, "DWARF missing"):
                verify(path)


class ComboSourceContractTests(unittest.TestCase):
    root = Path(__file__).resolve().parent

    def test_verified_callbacks_unchanged(self):
        source = (self.root / 'cpuinfo_spoof.c').read_text(encoding='utf-8')
        expected = {
            'fake_cpu_mask': '647ca532bdabd1a1164b7228e2e9cb112d33f1e218afa6bad6f89bc187922e2b',
            'fake_topology': '54c71e2d72b8441de76d440922d17402e31ceef082411ab297a8111f604cd72e',
            'fake_available': 'b5f335f29fa1d0222e658fbbea8bb84fb76b8bfb9705a862ef74b92fd212907b',
            'fake_boost': 'a863d94906cdc8f089034ba570f6ea489d614610f362801c66397f8a86167864',
        }
        for name, digest in expected.items():
            start = source.index('static ssize_t ' + name + '(')
            brace = source.index('{', start)
            depth, end = 1, brace + 1
            while depth:
                if source[end] == '{': depth += 1
                elif source[end] == '}': depth -= 1
                end += 1
            self.assertEqual(hashlib.sha256(source[start:end].encode()).hexdigest(), digest, name)

    def test_no_kernel_current_macro_collision(self):
        source = (self.root / 'cpuinfo_spoof.c').read_text(encoding='utf-8')
        # Linux defines current as get_current(); it is not a usable local name.
        self.assertNotRegex(source, r'\bcurrent\b')
        self.assertIn('copy_from_kernel_nofault(&observed_ptr,', source)

    def test_revision_agrees(self):
        c = (self.root / 'cpuinfo_spoof.c').read_text(encoding='utf-8')
        sh = (self.root / 'cpu_test.sh').read_text(encoding='utf-8')
        self.assertIn('#define REVISION "' + REVISION.decode() + '"', c)
        self.assertIn('REV=' + REVISION.decode(), sh)

    def test_sh_frequency_matches_header(self):
        h = (self.root / 'kirin9020.h').read_text(encoding='utf-8')
        body = h.split('#define FAKE_AVAIL_FREQS', 1)[1].split('#define FAKE_BOOST_FREQS', 1)[0]
        expected = ''.join(re.findall(r'"([^"]*)"', body))
        sh = (self.root / 'cpu_test.sh').read_text(encoding='utf-8')
        actual = re.search(r"^FREQS='([^']+)'", sh, re.M).group(1)
        self.assertEqual(actual, expected)

    def test_combo_contract_and_no_forbidden_sh_actions(self):
        c = (self.root / 'cpuinfo_spoof.c').read_text(encoding='utf-8')
        sh = (self.root / 'cpu_test.sh').read_text(encoding='utf-8')
        self.assertIn('combo && planned != (full ? 9U : 8U)', c)
        self.assertIn('full) TOTAL=10; POINTERS=9; UTS=1', sh)
        self.assertIn('check pointer_applied "$(value pointer_applied)" "$POINTERS"', sh)
        self.assertIn('for ITEM in uts cpus topology cpufreq cpuinfo', sh)
        self.assertNotRegex(sh, r'(?m)^\s*(rmmod|mount|umount|resetprop)\s')
        self.assertNotIn('.proc_write =', c)

    def test_cpuinfo_uses_static_seq_and_preserves_release(self):
        c = (self.root / 'cpuinfo_spoof.c').read_text(encoding='utf-8')
        self.assertIn('return seq_open(file, &fake_cpuinfo_seq_ops);', c)
        self.assertIn('cpuinfo_ops_clone = original;', c)
        self.assertIn('cpuinfo_ops_clone.proc_open = fake_cpuinfo_open;', c)
        cpuinfo_block = c[c.index('static int fake_cpuinfo_open('):c.index('static int plan_device(')]
        self.assertNotIn('single_open(file,', cpuinfo_block)
        self.assertNotIn('single_release,', cpuinfo_block)
        self.assertIn('original.proc_read_iter, "seq_read_iter"', c)
        self.assertIn('original.proc_release, "seq_release"', c)
        self.assertIn('original_ops != ops_address', c)
        self.assertIn('parent != resolve("proc_root")', c)

    def test_cpuinfo_private_layout_contract(self):
        c = (self.root / 'cpuinfo_spoof.c').read_text(encoding='utf-8')
        expected = {'PI_VFS_INODE_OFFSET':72, 'PI_PDE_OFFSET':24,
                    'PDE_BYTES':176, 'PDE_OPS_OFFSET':48, 'PDE_LOW_INO_OFFSET':92,
                    'PDE_PARENT_OFFSET':120, 'PDE_NAME_OFFSET':160,
                    'PDE_MODE_OFFSET':168, 'PDE_FLAGS_OFFSET':170}
        for key, value in expected.items():
            self.assertRegex(c, rf'#define {key}\s+{value}\b')
        self.assertIn('release_cpuinfo_path();', c)
        sh = (self.root / 'cpu_test.sh').read_text(encoding='utf-8')
        self.assertIn('exec 9</proc/cpuinfo', sh)
        self.assertIn('dd bs=7 count=1', sh)
        self.assertIn('cpuinfo_eof_bytes', sh)


if __name__ == "__main__":
    unittest.main()
