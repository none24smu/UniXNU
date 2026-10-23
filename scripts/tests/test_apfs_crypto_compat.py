#!/usr/bin/env python3
"""Exercise the actual pinned scalar Apple digests plus the serial pair KPI.

No source is edited: the generated header overlay uses XNU's descriptor ABI.
Defaults use this repository's refer/, .cache/ and build/ directories. Explicit
APFS_CRYPTO_SOURCE, APFS_CRYPTO_DIGEST_HEADER and APFS_CRYPTO_TEST_OUT environment
overrides select a different local checkout/header/output without editing them.
This is host correctness evidence, not proof of kernel registration or boot.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get('APFS_CRYPTO_SOURCE', ROOT / 'refer/corecrypto-2023')).resolve()
KERNEL_HEADER = Path(os.environ.get('APFS_CRYPTO_DIGEST_HEADER',
    ROOT / '.cache/xnu-12377.121.6-work/EXTERNAL_HEADERS/corecrypto/ccdigest.h')).resolve()
COMPAT = Path(os.environ.get('APFS_CRYPTO_COMPAT_SOURCE', ROOT / 'scripts/apfs-crypto-compat.c')).resolve()
SELFTEST = Path(os.environ.get('APFS_CRYPTO_SELFTEST_SOURCE', ROOT / 'scripts/apfs-crypto-selftest.c')).resolve()
OUT = Path(os.environ.get('APFS_CRYPTO_TEST_OUT', ROOT / 'build/apfs-crypto-tests')).resolve()
REVISION = '11fba65b12d8830630e248dfa8344caf8b065f26'
SOURCES = [
    'cc/src/cc_clear.c', 'ccdigest/src/ccdigest.c',
    'ccdigest/src/ccdigest_init.c', 'ccdigest/src/ccdigest_update.c',
    'ccdigest/src/ccdigest_final_64be.c', 'cckeccak/src/cckeccak.c',
    'ccsha3/src/ccsha3_initial_state.c', 'ccsha3/src/ccsha3_final.c',
    *[f'ccsha3/src/ccsha3_{n}_di.c' for n in (256, 384, 512)],
    'ccsha2/src/ccsha256_K.c', 'ccsha2/src/ccsha512_K.c',
    'ccsha2/src/ccsha256_di.c',
    *[f'ccsha2/src/ccsha{n}_initial_state.c' for n in (256, 384, 512)],
    *[f'ccsha2/src/ccsha{n}_ltc_di.c' for n in (256, 384, 512)],
    'ccsha2/src/ccsha256_ltc_compress.c', 'ccsha2/src/ccsha512_ltc_compress.c',
]
ALGORITHMS = ('sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_384', 'sha3_512')
SHIM = r'''
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>
#include <stddef.h>
const struct ccdigest_info *apfs_test_di(unsigned i) {
    switch (i) {
    case 0: return &ccsha256_ltc_di;
    case 1: return &ccsha384_ltc_di;
    case 2: return &ccsha512_ltc_di;
    case 3: return ccsha3_256_di();
    case 4: return ccsha3_384_di();
    case 5: return ccsha3_512_di();
    default: return 0;
    }
}
size_t apfs_test_abi(unsigned i) {
    switch (i) {
    case 0: return sizeof(struct ccdigest_info);
    case 1: return offsetof(struct ccdigest_info, compress);
    case 2: return offsetof(struct ccdigest_info, final);
    case 3: return offsetof(struct ccdigest_info, impl);
    case 4: return offsetof(struct ccdigest_info, compress_parallel);
    default: return 0;
    }
}
void apfs_test_stream(const struct ccdigest_info *di, size_t n,
                      const unsigned char *data, void *out) {
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    for (size_t at = 0; at < n;) {
        size_t take = (at % 17) + 1;
        if (take > n - at) take = n - at;
        ccdigest_update(di, ctx, take, data + at);
        at += take;
    }
    ccdigest_final(di, ctx, out);
    ccdigest_di_clear(di, ctx);
}
'''


def compile_command():
    actual = subprocess.check_output(['git', '-C', SOURCE, 'rev-parse', 'HEAD'], text=True).strip()
    if actual != REVISION:
        raise AssertionError(f'Unexpected pinned source: {actual}')
    if subprocess.check_output(['git', '-C', SOURCE, 'status', '--porcelain'], text=True):
        raise AssertionError('Pinned crypto source is dirty')
    include = OUT / 'include/corecrypto'
    include.mkdir(parents=True, exist_ok=True)
    for header in SOURCE.glob('*/corecrypto/*.h'):
        if header.name == 'ccdigest.h':
            header = KERNEL_HEADER
        link = include / header.name
        if link.exists():
            if link.resolve() != header.resolve():
                raise AssertionError(f'Unexpected include overlay: {link}')
        else:
            link.symlink_to(header.resolve())
    shim = OUT / 'shim.c'
    shim.write_text(SHIM)
    command = [os.environ.get('CC', 'clang'), '-std=gnu99', '-O2',
               '-DCC_USE_ASM=0', '-DCC_INTERNAL_SDK=0', '-DNDEBUG=1',
               '-I' + str(include.parent)]
    for directory in sorted({h.parent for h in SOURCE.rglob('*.h')
                             if 'test' not in str(h.relative_to(SOURCE)).lower()}):
        command.append('-I' + str(directory))
    return command + [str(SOURCE / p) for p in SOURCES] + [str(COMPAT), str(SELFTEST), str(shim)]


def data_pair(n):
    return (bytes((i * 73 + 19) % 256 for i in range(n)),
            bytes((i * 11 + 241) % 256 for i in range(n)))


class CryptoCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.command = compile_command()
        cls.library_path = OUT / 'crypto.so'
        result = subprocess.run([*cls.command, '-fPIC', '-shared', '-Wl,-z,defs',
                                 '-o', str(cls.library_path)], capture_output=True, text=True)
        (OUT / 'compile.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.lib = ctypes.CDLL(str(cls.library_path))
        cls.lib.apfs_test_di.argtypes = [ctypes.c_uint]
        cls.lib.apfs_test_di.restype = ctypes.c_void_p
        cls.lib.apfs_test_abi.argtypes = [ctypes.c_uint]
        cls.lib.apfs_test_abi.restype = ctypes.c_size_t
        for name in ('ccdigest', 'apfs_test_stream'):
            getattr(cls.lib, name).argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                              ctypes.c_void_p, ctypes.c_void_p]
        cls.lib.ccdigest_parallel.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                              ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.c_void_p]
        cls.counts = {'one_shot': 0, 'stream': 0, 'parallel': 0, 'alias': 0}

    @classmethod
    def tearDownClass(cls):
        report = {
            'source_revision': REVISION, 'source_files': SOURCES,
            'file_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in [*[SOURCE / p for p in SOURCES], KERNEL_HEADER, COMPAT, SELFTEST]},
            'compile_command': cls.command, 'case_counts': cls.counts,
            'shared_library_sha256': hashlib.sha256(cls.library_path.read_bytes()).hexdigest(),
            'descriptor_abi': [cls.lib.apfs_test_abi(i) for i in range(5)],
            'host_validation_only': True, 'kernel_runtime_verified': False,
        }
        (OUT / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def test_actual_kernel_descriptor_abi(self):
        self.assertEqual([self.lib.apfs_test_abi(i) for i in range(5)], [80, 48, 56, 64, 72])

    def test_provider_namespace(self):
        # These collisions are present in the linked verified-root kernel.
        # Compiling the fallback with the same forced-include header must bind
        # it to the provider's private operations, preserving public KPI names.
        namespace = OUT / 'namespace.h'
        namespace.write_text(''.join(f'#define {name} cc14_{name}\n' for name in
                                    ('cc_clear', 'ccdigest_init', 'ccdigest_update',
                                     'ccdigest_final_64be')))
        library_path = OUT / 'crypto-namespaced.so'
        command = [*self.command, '-include', str(namespace), '-fPIC', '-shared',
                   '-Wl,-z,defs', '-o', str(library_path)]
        build = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        symbols = subprocess.check_output(['nm', '-D', '--defined-only', library_path], text=True)
        self.assertIn(' cc14_ccdigest_init\n', symbols)
        self.assertNotIn(' ccdigest_init\n', symbols)
        self.assertIn(' ccdigest_parallel\n', symbols)
        library = ctypes.CDLL(str(library_path))
        library.apfs_test_di.argtypes = [ctypes.c_uint]
        library.apfs_test_di.restype = ctypes.c_void_p
        library.ccdigest_parallel.argtypes = self.lib.ccdigest_parallel.argtypes
        for alg, name in enumerate(ALGORITHMS):
            left, right = data_pair(4096)
            data1, data2 = ctypes.create_string_buffer(left), ctypes.create_string_buffer(right)
            size = hashlib.new(name).digest_size
            out1, out2 = ctypes.create_string_buffer(size), ctypes.create_string_buffer(size)
            library.ccdigest_parallel(library.apfs_test_di(alg), len(left), data1, out1, data2, out2)
            self.assertEqual(out1.raw, hashlib.new(name, left).digest())
            self.assertEqual(out2.raw, hashlib.new(name, right).digest())
        status = ctypes.c_uint32.in_dll(library, 'native_apfs_crypto_selftest_result')
        self.assertEqual(status.value, 0xffffffff)
        self.assertEqual(library.native_apfs_crypto_kpis_selftest(), 0)
        self.assertEqual(status.value, 0)
        (OUT / 'namespace-validation.json').write_text(json.dumps({
            'compile_command': command, 'public_pair_name_retained': True,
            'private_provider_operations_used': True, 'algorithms_crosschecked': list(ALGORITHMS),
            'shared_library_sha256': hashlib.sha256(library_path.read_bytes()).hexdigest(),
        }, indent=2) + '\n')

    def test_runtime_kat_and_failure_detection(self):
        status = ctypes.c_uint32.in_dll(self.lib, 'native_apfs_crypto_selftest_result')
        self.assertEqual(status.value, 0xffffffff)
        self.assertEqual(self.lib.native_apfs_crypto_kpis_selftest(), 0)
        self.assertEqual(status.value, 0)
        self.assertEqual(self.lib.native_apfs_crypto_kpis_selftest(), 0)
        self.assertEqual(status.value, 0)

        # GNU ELF linker wrappers alter real computed digests only at the
        # boundary, leaving the production selftest and crypto files unchanged.
        corruption = OUT / 'fault-injection.c'
        corruption.write_text(r'''
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha3.h>
unsigned apfs_test_fault;
extern void __real_ccdigest(const struct ccdigest_info *, size_t, const void *, void *);
extern void __real_ccdigest_parallel(const struct ccdigest_info *, size_t,
                                   const void *, void *, const void *, void *);
extern const struct ccdigest_info *__real_ccsha3_256_di(void);
const struct ccdigest_info *__wrap_ccsha3_256_di(void) {
    return apfs_test_fault == 7 ? 0 : __real_ccsha3_256_di();
}
void __wrap_ccdigest(const struct ccdigest_info *di, size_t n, const void *data, void *out) {
    __real_ccdigest(di, n, data, out);
    unsigned target = di->output_size == 32 ? 1 : di->output_size == 48 ? 3 : 5;
    if (apfs_test_fault == target + (n != 0)) ((unsigned char *)out)[0] ^= 1;
}
void __wrap_ccdigest_parallel(const struct ccdigest_info *di, size_t n,
                             const void *a, void *out1, const void *b, void *out2) {
    __real_ccdigest_parallel(di, n, a, out1, b, out2);
    if (apfs_test_fault == 8) ((unsigned char *)out1)[0] ^= 1;
    if (apfs_test_fault == 9) ((unsigned char *)out2)[0] ^= 1;
}
''')
        library_path = OUT / 'crypto-fault-injection.so'
        command = [*self.command, str(corruption), '-fPIC', '-shared', '-Wl,-z,defs',
                   '-Wl,--wrap=ccdigest', '-Wl,--wrap=ccdigest_parallel',
                   '-Wl,--wrap=ccsha3_256_di', '-o', str(library_path)]
        build = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        library = ctypes.CDLL(str(library_path))
        result = ctypes.c_uint32.in_dll(library, 'native_apfs_crypto_selftest_result')
        fault = ctypes.c_uint.in_dll(library, 'apfs_test_fault')
        self.assertEqual(result.value, 0xffffffff)
        expected = {1: 0x102, 2: 0x103, 3: 0x112, 4: 0x113,
                    5: 0x122, 6: 0x123, 7: 0x101, 8: 0x202, 9: 0x203}
        for selected, code in expected.items():
            with self.subTest(fault=selected, code=code):
                fault.value = selected
                self.assertEqual(library.native_apfs_crypto_kpis_selftest(), code)
                self.assertEqual(result.value, code)
        fault.value = 0
        self.assertEqual(library.native_apfs_crypto_kpis_selftest(), 0)
        self.assertEqual(result.value, 0)
        (OUT / 'runtime-kat-validation.json').write_text(json.dumps({
            'unmodified_runtime_kat_passed': True,
            'namespace_runtime_kat_tested_separately': True,
            'actual_digest_corruption_detected': expected,
            'compile_command': command,
            'shared_library_sha256': hashlib.sha256(library_path.read_bytes()).hexdigest(),
        }, indent=2) + '\n')

    def test_known_answers_and_boundaries(self):
        # Empty, abc, one-million-a, plus boundaries for all SHA2/SHA3 rates.
        messages = [b'', b'abc', b'a' * 1000000]
        messages += [data_pair(n)[0] for n in
                     (1, 7, 31, 55, 56, 63, 64, 65, 71, 72, 73, 103, 104,
                      105, 127, 128, 129, 135, 136, 137, 143, 144, 145, 4096)]
        for algorithm_id, name in enumerate(ALGORITHMS):
            di = self.lib.apfs_test_di(algorithm_id)
            for data in messages:
                expected = hashlib.new(name, data).digest()
                source = ctypes.create_string_buffer(data)
                for mode in ('ccdigest', 'apfs_test_stream'):
                    with self.subTest(algorithm=name, length=len(data), mode=mode):
                        out = ctypes.create_string_buffer(len(expected))
                        getattr(self.lib, mode)(di, len(data), source, out)
                        self.assertEqual(out.raw, expected)
                        self.counts['one_shot' if mode == 'ccdigest' else 'stream'] += 1

    def test_independent_pairs_and_cross_aliases(self):
        for algorithm_id, name in enumerate(ALGORITHMS):
            di = self.lib.apfs_test_di(algorithm_id)
            digest_size = hashlib.new(name).digest_size
            for n in (0, 1, 31, 63, 64, 65, 71, 72, 73, 103, 104, 105,
                      127, 128, 129, 135, 136, 137, 143, 144, 145, 4096):
                left, right = data_pair(n)
                expected1 = hashlib.new(name, left).digest()
                expected2 = hashlib.new(name, right).digest()
                # Separate, in-place, crossed, partial-overlap, identical-input.
                for mode in range(5):
                    buffer1 = ctypes.create_string_buffer(left, max(n, digest_size) + digest_size + 8)
                    buffer2 = ctypes.create_string_buffer(right, max(n, digest_size) + digest_size + 8)
                    output1 = ctypes.create_string_buffer(digest_size)
                    output2 = ctypes.create_string_buffer(digest_size)
                    source1, source2 = ctypes.addressof(buffer1), ctypes.addressof(buffer2)
                    target1, target2 = ctypes.addressof(output1), ctypes.addressof(output2)
                    expected_right = expected2
                    if mode == 1:
                        target1, target2 = source1, source2
                    elif mode == 2:
                        target1, target2 = source2, source1
                    elif mode == 3:
                        target1, target2 = source2 + 1, source1 + 3
                    elif mode == 4:
                        source2 = source1
                        expected_right = expected1
                    with self.subTest(algorithm=name, length=n, alias=mode):
                        self.lib.ccdigest_parallel(di, n, source1, target1, source2, target2)
                        self.assertEqual(ctypes.string_at(target1, digest_size), expected1)
                        self.assertEqual(ctypes.string_at(target2, digest_size), expected_right)
                        self.counts['parallel' if mode == 0 else 'alias'] += 1

    def test_address_and_undefined_sanitizers(self):
        # A separate executable makes ASan/UBSan observe the actual C calls.
        statements = []
        for alg, name in enumerate(ALGORITHMS):
            for n in (0, 1, 31, 63, 64, 65, 71, 72, 73, 103, 104, 105,
                      127, 128, 129, 135, 136, 137, 143, 144, 145, 4096):
                left, right = data_pair(n)
                e1, e2 = hashlib.new(name, left).hexdigest(), hashlib.new(name, right).hexdigest()
                statements.append(f'check({alg}, {n}, "{e1}", "{e2}");')
        runner = OUT / 'sanitizer.c'
        runner.write_text(r'''
#include <corecrypto/ccdigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern const struct ccdigest_info *apfs_test_di(unsigned);
extern int native_apfs_crypto_kpis_selftest(void);
static unsigned nibble(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }
static void verify(const unsigned char *out, const char *hex, size_t size) {
    for (size_t i = 0; i < size; i++)
        if (out[i] != (nibble(hex[2*i]) << 4 | nibble(hex[2*i+1]))) abort();
}
static void check(unsigned alg, size_t n, const char *e1, const char *e2) {
    unsigned char a[4200], b[4200], d1[64], d2[64];
    const struct ccdigest_info *di = apfs_test_di(alg);
    for (unsigned mode = 0; mode < 4; mode++) {
        for (size_t i = 0; i < sizeof(a); i++) {
            a[i] = (i * 73 + 19) % 256; b[i] = (i * 11 + 241) % 256;
        }
        unsigned char *out1 = d1, *out2 = d2;
        if (mode == 1) { out1 = a; out2 = b; }
        if (mode == 2) { out1 = b; out2 = a; }
        if (mode == 3) { out1 = b + 1; out2 = a + 3; }
        ccdigest_parallel(di, n, a, out1, b, out2);
        verify(out1, e1, di->output_size); verify(out2, e2, di->output_size);
    }
}
int main(void) {
''' + '\n'.join(statements) + '\nif (native_apfs_crypto_kpis_selftest()) abort();\n'
                'puts("528 sanitizer pair calls and runtime KAT passed"); return 0; }\n')
        binary = OUT / 'sanitizer'
        command = [*self.command, '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                   str(runner), '-o', str(binary)]
        build = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        run = subprocess.run([str(binary)], capture_output=True, text=True)
        (OUT / 'sanitizer.log').write_text(build.stdout + build.stderr + run.stdout + run.stderr)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('528 sanitizer pair calls and runtime KAT passed', run.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
