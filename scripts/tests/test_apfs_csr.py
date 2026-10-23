"""Exercise actual XNU DT policy code, including boot without /chosen/asmb."""
import ctypes
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get('APFS_CSR_XNU_SOURCE', ROOT / 'refer/xnu'))
SPEC = importlib.util.spec_from_file_location('csr_config', ROOT / 'scripts/prepare-apfs-csr-config.py')
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)

STUBS = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define SECURITY_READ_ONLY_LATE(type) type
#define __startup_func
#define STARTUP(...)
typedef void *DTEntry;
enum { kSuccess = 0 };
static bool present;
static uint64_t sip0;
static uint32_t sip1;
static unsigned bad_entry;
static int SecureDTLookupEntry(int zero, const char *path, DTEntry *entry) {
    (void)zero;
    if (present && strcmp(path, "/chosen/asmb") == 0) {
        *entry = (void *)1;
        return kSuccess;
    }
    *entry = (void *)2; // Deliberately not an asmb node on failure.
    return -1;
}
static int SecureDTGetProperty(DTEntry entry, const char *name, const void **out, unsigned *size) {
    if (entry != (void *)1) { ++bad_entry; return -1; }
    if (strcmp(name, "lp-sip0") == 0) { *out = &sip0; *size = sizeof(sip0); return kSuccess; }
    if (strcmp(name, "lp-sip1") == 0) { *out = &sip1; *size = sizeof(sip1); return kSuccess; }
    return -1;
}
static int PE_parse_boot_argn(const char *name, void *out, int size) {
    (void)name; (void)out; (void)size; return 0;
}
static void panic(const char *message, ...) { (void)message; abort(); }
'''


@unittest.skipUnless((SOURCE / 'bsd/kern/kern_csr.c').is_file(), 'supply immutable XNU source')
class ActualCSRTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='zeta-csr-')
        cls.out = Path(cls.temporary.name)
        source = cls.out / 'bsd/kern/kern_csr.c'
        source.parent.mkdir(parents=True)
        shutil.copyfile(SOURCE / 'bsd/kern/kern_csr.c', source)
        command = ['git', 'apply', '--unsafe-paths', '--directory', str(cls.out)]
        patch = ROOT / 'patches/xnu-12377/native-csr-missing-asmb.patch'
        subprocess.run(command + [str(patch)], cwd=cls.out, check=True, capture_output=True)
        subprocess.run(command + ['--reverse', '--check', str(patch)], cwd=cls.out, check=True, capture_output=True)
        text = source.read_text().split('#if CONFIG_CSR_FROM_DT\n', 1)[1].split(
            '\n#else\n\n/*\n * Old style CSR', 1)[0]
        text = re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)
        header = (SOURCE / 'bsd/sys/csr.h').read_text()
        flags = header.split('typedef uint32_t csr_config_t;', 1)[1].split('#ifdef PRIVATE', 1)[0]
        source = cls.out / 'actual-policy.c'
        source.write_text(STUBS + '\ntypedef uint32_t csr_config_t;\n' + flags + text + r'''
uint32_t boot_policy(int has_asmb, uint64_t requested, uint32_t allow_root) {
    present = has_asmb; sip0 = requested; sip1 = allow_root; bad_entry = 0;
    csr_bootstrap(); return csr_config;
}
unsigned invalid_property_lookups(void) { return bad_entry; }
''')
        cls.library = cls.out / 'policy.so'
        subprocess.run(['clang', '-std=gnu99', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-shared', '-fPIC', str(source), '-o', str(cls.library)],
                       check=True, capture_output=True, text=True)
        cls.lib = ctypes.CDLL(str(cls.library))
        cls.lib.boot_policy.argtypes = [ctypes.c_int, ctypes.c_uint64, ctypes.c_uint32]
        cls.lib.boot_policy.restype = ctypes.c_uint32
        cls.lib.csr_check.argtypes = [ctypes.c_uint32]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_missing_policy_is_restrictive_and_never_reads_failed_entry(self):
        self.assertEqual(self.lib.boot_policy(0, 0xffffffff, 1), 0)
        self.assertEqual(self.lib.invalid_property_lookups(), 0)
        self.assertEqual(self.lib.csr_check(0), 0)
        for bit in range(13):
            self.assertEqual(self.lib.csr_check(1 << bit), 1)  # EPERM

    def test_real_policy_masks_internal_and_synthesizes_root_separately(self):
        self.assertEqual(self.lib.boot_policy(1, (1 << 0) | (1 << 4) | (1 << 11), 0), 1)
        self.assertEqual(self.lib.csr_check(1 << 3), 0)  # Actual debugger implication.
        self.assertEqual(self.lib.csr_check(1 << 11), 1)
        self.assertEqual(self.lib.boot_policy(1, 0, 1), 1 << 11)
        self.assertEqual(self.lib.csr_check(1 << 11), 0)
        self.assertEqual(self.lib.csr_check(1), 1)

    def test_generated_master_keeps_reference_immutable(self):
        src = self.out / 'config-source'
        src.mkdir()
        name = 'MASTER.arm64.bcm2837'
        old = '#  SECURITY_BASE =    [ config_macf kernel_integrity config_secure_bsd_root reslide_shared_cache ]'
        (src / name).write_text(old + '\n')
        (src / 'MASTER').write_text('options CONFIG_CSR # <config_csr>\n')
        CONFIG.prepare(src, self.out / 'masters')
        self.assertEqual((src / name).read_text(), old + '\n')
        self.assertIn('config_csr config_csr_from_dt', (self.out / 'masters' / name).read_text())
        self.assertEqual((self.out / 'masters/MASTER').read_bytes(), (src / 'MASTER').read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
