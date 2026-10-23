"""Host-only qualification of the real ML-DSA APIs imported by KDK AppleImage4.

Set APFS_MLDSA_SOURCE to an immutable official apple/corecrypto checkout at
REVISION. Source and known-answer bytes remain external; none are embedded here.
This does not register a second crypto provider or change a kernel build.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

REVISION = '9612a959abb6eac0aac3ee6a7245c46365c9d81b'
PUBLIC = {'ccmldsa87', 'ccmldsa_import_pubkey', 'ccmldsa_verify'}
ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('APFS_MLDSA_SOURCE'), 'supply pinned official corecrypto source')
class ActualMLDSASource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(os.environ['APFS_MLDSA_SOURCE']).resolve()
        cls.temporary = tempfile.TemporaryDirectory(prefix='zeta-mldsa-source-')
        cls.out = Path(cls.temporary.name)
        actual = subprocess.check_output(['git', '-C', cls.source, 'rev-parse', 'HEAD'], text=True).strip()
        if actual != REVISION or subprocess.check_output(
                ['git', '-C', cls.source, 'status', '--porcelain'], text=True):
            raise AssertionError('Expected immutable official corecrypto revision')
        include = cls.out / 'include/corecrypto'
        include.mkdir(parents=True)
        for header in cls.source.glob('*/corecrypto/*.h'):
            link = include / header.name
            if link.exists():
                if link.resolve() != header:
                    raise AssertionError(f'Conflicting header {header}')
            else:
                link.symlink_to(header)
        cls.command = [os.environ.get('CC', 'clang'), '-std=gnu99', '-O2',
                       '-DCC_USE_ASM=0', '-DCC_INTERNAL_SDK=0', '-DNDEBUG=1',
                       '-fPIC', '-I' + str(include.parent)]
        # Formal-verification models intentionally replace standard headers;
        # production compilation must never include those model directories.
        for directory in sorted({h.parent for h in cls.source.rglob('*.h')
                                 if 'test' not in str(h.relative_to(cls.source)).lower()
                                 and 'corecrypto_verify' not in h.parts}):
            cls.command += ['-I' + str(directory)]
        builder_spec = importlib.util.spec_from_file_location('mldsa_builder', ROOT / 'scripts/build-apfs-mldsa-12377.py')
        builder = importlib.util.module_from_spec(builder_spec)
        builder_spec.loader.exec_module(builder)
        builder.generate_kat_header(cls.source, cls.out)
        cls.command += ['-I' + str(cls.out)]
        cls.sources = sorted((cls.source / 'ccmldsa/src').glob('*.c'))
        cls.sources += sorted((cls.source / 'cckeccak/src').glob('*.c'))
        cls.sources += [cls.source / 'cc/src' / name for name in (
            'cc_clear.c', 'cc_cmp_safe.c', 'cc_memory.c', 'cc_fault_canary.c',
            'cc_value_barrier.c', 'cc_try_abort.c', 'cc_abort.c',
            'cc_dit.c', 'cc_timing_safe.c')]
        cls.sources += [cls.source / 'ccxof/src/ccxof.c', cls.source / 'ccn/src/ccn_sizeof.c']
        cls.sources += [ROOT / 'scripts/apfs-mldsa-selftest.c']
        cls.plain = cls.build('plain')
        symbols = cls.symbols(cls.plain)
        if not PUBLIC <= symbols or any(not name.isidentifier() for name in symbols):
            raise AssertionError('Unexpected ML-DSA export inventory')
        namespace = cls.out / 'namespace.h'
        namespace.write_text(''.join(f'#define {name} zeta_mldsa26_{name}\n'
                                     for name in sorted(symbols - PUBLIC)))
        cls.namespaced = cls.build('namespaced', ['-include', str(namespace)])
        cls.definitions = cls.symbols(cls.namespaced)
        kat = cls.source / 'cc_fips/fipspost_post_mldsa.c'
        cls.kat_hash = hashlib.sha256(kat.read_bytes()).hexdigest()
        text = kat.read_text()
        cls.arrays = {}
        for name in ('pubkey_kat', 'sig_kat', 'msg_kat'):
            raw = re.search(r'\b' + name + r'\[[^\]]*\]\s*=\s*\{([^}]+)\}', text).group(1)
            cls.arrays[name] = bytes(int(value.strip(), 0) for value in raw.split(',') if value.strip())
        cls.results = {}

    @classmethod
    def build(cls, name, flags=None):
        library = cls.out / (name + '.so')
        result = subprocess.run([*cls.command, *(flags or []), *map(str, cls.sources),
                                 '-shared', '-Wl,-z,defs', '-o', str(library)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])
        return library

    @staticmethod
    def symbols(library):
        return {line.split()[-1] for line in subprocess.check_output(
            ['nm', '-D', '--defined-only', library], text=True).splitlines()}

    @classmethod
    def tearDownClass(cls):
        if os.environ.get('APFS_MLDSA_REPORT'):
            Path(os.environ['APFS_MLDSA_REPORT']).write_text(json.dumps({
                'source_revision': REVISION, 'kat_source_sha256': cls.kat_hash,
                'source_sha256': {str(p.relative_to(cls.source)) if p.is_relative_to(cls.source) else p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in cls.sources},
                'public_apis': sorted(PUBLIC), 'results': cls.results,
                'host_only': True, 'kernel_integrated': False}, indent=2) + '\n')
        cls.temporary.cleanup()

    def test_public_api_namespace_is_isolated(self):
        self.assertEqual({n for n in self.definitions if not n.startswith('zeta_mldsa26_')}, PUBLIC)
        self.assertIn('zeta_mldsa26_cc_clear', self.definitions)
        self.assertIn('zeta_mldsa26_cc_malloc_clear', self.definitions)

    def test_actual_known_answer_and_rejected_corruptions(self):
        key, sig, msg = (self.arrays[n] for n in ('pubkey_kat', 'sig_kat', 'msg_kat'))
        self.assertEqual((len(key), len(sig), len(msg)), (2592, 4627, 32))
        for variant, path, prefix in (('plain', self.plain, ''), ('namespaced', self.namespaced, 'zeta_mldsa26_')):
            with self.subTest(variant=variant):
                lib = ctypes.CDLL(str(path))
                lib.ccmldsa87.restype = ctypes.c_void_p
                size_fn = getattr(lib, prefix + 'ccmldsa_sizeof_pub_ctx')
                size_fn.argtypes = [ctypes.c_void_p]
                size_fn.restype = ctypes.c_size_t
                lib.ccmldsa_import_pubkey.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
                lib.ccmldsa_verify.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
                params = lib.ccmldsa87()
                size = size_fn(params)
                self.assertEqual(size, 2600)
                context = ctypes.create_string_buffer(size)
                self.assertEqual(lib.ccmldsa_import_pubkey(params, len(key), key, context), 0)
                rows = {}
                for name, signature, message, expected in (
                    ('valid', sig, msg, 0),
                    ('changed_signature', bytes([sig[0] ^ 1]) + sig[1:], msg, -146),
                    ('changed_message', sig, bytes([msg[0] ^ 1]) + msg[1:], -146),
                    ('short_signature', sig[:-1], msg, -7)):
                    result = lib.ccmldsa_verify(context, len(signature), signature, len(message), message)
                    self.assertEqual(result, expected, name)
                    rows[name] = result
                rows['short_key'] = lib.ccmldsa_import_pubkey(params, len(key) - 1, key, context)
                self.assertEqual(rows['short_key'], -7)
                self.results[variant] = rows

    def test_runtime_kat_and_false_success_verifier_detection(self):
        for variant, path, prefix in (('plain', self.plain, ''), ('namespaced', self.namespaced, 'zeta_mldsa26_')):
            lib = ctypes.CDLL(str(path))
            function = getattr(lib, prefix + 'native_apfs_mldsa_selftest')
            status = ctypes.c_uint32.in_dll(lib, prefix + 'native_apfs_mldsa_selftest_result')
            self.assertEqual(function(), 0, variant)
            self.assertEqual(status.value, 0, variant)
        wrapper = self.out / 'false-success.c'
        wrapper.write_text('''#include <stddef.h>
int __wrap_ccmldsa_verify(void *context, size_t sn, const void *sig,
                         size_t mn, const void *msg) {
    (void)context; (void)sn; (void)sig; (void)mn; (void)msg; return 0;
}
''')
        injected = self.build('false-success', [str(wrapper), '-Wl,--wrap=ccmldsa_verify'])
        lib = ctypes.CDLL(str(injected))
        self.assertEqual(lib.native_apfs_mldsa_selftest(), 5)
        self.assertEqual(ctypes.c_uint32.in_dll(lib, 'native_apfs_mldsa_selftest_result').value, 5)
        self.results['runtime_kat'] = {'plain': 0, 'namespaced': 0, 'false_success_rejected': 5}


if __name__ == '__main__':
    unittest.main(verbosity=2)
