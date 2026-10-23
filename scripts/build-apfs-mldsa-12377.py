#!/usr/bin/env python3
"""Build isolated real ML-DSA KPIs for native ARM64 XNU12377/iOS26.

This is a separate implementation archive, not a registered crypto provider.
The existing corecrypto provider and its POST remain untouched. Compiling this
archive does not establish successful kernel execution or trust evaluation.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REVISION = '9612a959abb6eac0aac3ee6a7245c46365c9d81b'
URL = 'https://github.com/apple/corecrypto.git'
PUBLIC = {'ccmldsa87', 'ccmldsa_import_pubkey', 'ccmldsa_verify'}
PREFIX = 'zeta_mldsa26_'
KAT_SHA256 = '9aa88a4464fd4a2838d25e215beb816f093220767e237a5ceaeadd35ab79bacc'


def source_files(source):
    files = sorted((source / 'ccmldsa/src').glob('*.c'))
    files += sorted((source / 'cckeccak/src').glob('*.c'))
    files += [source / 'cc/src' / name for name in (
        'cc_clear.c', 'cc_cmp_safe.c', 'cc_memory.c', 'cc_fault_canary.c',
        'cc_value_barrier.c', 'cc_try_abort.c', 'cc_abort.c',
        'cc_dit.c', 'cc_timing_safe.c')]
    files += [source / 'ccxof/src/ccxof.c', source / 'ccn/src/ccn_sizeof.c']
    if len(files) != 25 or any(not p.is_file() for p in files):
        raise SystemExit('Pinned 25-source ML-DSA implementation inventory changed')
    return files


def ensure_source(source):
    if not source.exists():
        source.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'clone', '--filter=blob:none', '--no-checkout', URL, source], check=True)
        subprocess.run(['git', '-C', source, 'fetch', '--depth=1', 'origin', REVISION], check=True)
        subprocess.run(['git', '-C', source, 'checkout', '--detach', REVISION], check=True)
    actual = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', source, 'status', '--porcelain'], text=True)
    if actual != REVISION or dirty:
        raise SystemExit('Expected immutable official corecrypto2026 source revision')


def prepare_headers(source, output):
    include = output / 'include/corecrypto'
    include.mkdir(parents=True, exist_ok=True)
    for header in source.glob('*/corecrypto/*.h'):
        link = include / header.name
        if link.exists():
            if link.resolve() != header.resolve():
                raise SystemExit(f'Conflicting header: {link}')
        else:
            link.symlink_to(header)
    # Never overlay 2023 or XNU ccdigest.h: this isolated subset owns all its
    # opaque crypto layouts and only exposes the audited ML-DSA public ABI.
    return include.parent


def generate_kat_header(source, output):
    kat = source / 'cc_fips/fipspost_post_mldsa.c'
    data = kat.read_bytes()
    if hashlib.sha256(data).hexdigest() != KAT_SHA256:
        raise SystemExit('Unaudited ML-DSA known-answer source')
    arrays = {}
    for name, renamed, expected in (
            ('pubkey_kat', 'apfs_mldsa_kat_pubkey', 2592),
            ('sig_kat', 'apfs_mldsa_kat_signature', 4627),
            ('msg_kat', 'apfs_mldsa_kat_message', 32)):
        matches = re.findall(r'\b' + name + r'\[[^\]]*\]\s*=\s*\{([^}]+)\}', data.decode())
        if len(matches) != 1:
            raise SystemExit(f'Ambiguous KAT array: {name}')
        values = bytes(int(v.strip(), 0) for v in matches[0].split(',') if v.strip())
        if len(values) != expected:
            raise SystemExit(f'Wrong KAT array length: {name}')
        arrays[renamed] = values
    header = output / 'apfs-mldsa-kat.h'
    header.write_text('/* Generated from immutable external Apple source; do not commit. */\n'
        + '\n'.join(f'static const unsigned char {name}[{len(values)}] = {{\n'
                    + ',\n'.join(','.join(f'0x{v:02x}' for v in values[i:i + 24])
                                for i in range(0, len(values), 24)) + '\n};'
                    for name, values in arrays.items()) + '\n')
    return {'source': str(kat), 'source_sha256': KAT_SHA256,
            'arrays': {n: {'bytes': len(v), 'sha256': hashlib.sha256(v).hexdigest()}
                       for n, v in arrays.items()}}


def names(path, defined):
    text = subprocess.check_output(['xcrun', 'nm', '-g', '-U' if defined else '-u', '-j', path], text=True)
    return {line.strip() for line in text.splitlines() if line.startswith('_')}


def audit_object(path):
    data = path.read_bytes()
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise SystemExit(f'Object is not ordinary ARM64 Mach-O: {path}')
    count = struct.unpack_from('<I', data, 16)[0]
    offset = 32
    deployments = []
    for _ in range(count):
        if offset + 8 > len(data):
            raise SystemExit(f'Truncated object load command: {path}')
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or offset + size > len(data):
            raise SystemExit(f'Malformed object load command: {path}')
        if command == 0x32:
            if size < 24:
                raise SystemExit(f'Malformed build-version command: {path}')
            deployments.append(struct.unpack_from('<II', data, offset + 8))
        offset += size
    if deployments != [(2, 0x1a0000)]:
        raise SystemExit(f'Wrong object platform/deployment: {path}: {deployments}')


def build(command, files, source, output, variant, jobs):
    directory = output / ('objects-' + variant)
    directory.mkdir(exist_ok=True)

    def compile_one(path):
        relative = str(path.relative_to(source)) if path.is_relative_to(source) else 'scripts/' + path.name
        stem = hashlib.sha256(relative.encode()).hexdigest()[:12] + '-' + path.stem
        destination = directory / (stem + '.o')
        result = subprocess.run([*command, '-c', path, '-o', destination],
                                capture_output=True, text=True)
        (directory / (stem + '.log')).write_text(result.stdout + result.stderr)
        return {'source': relative, 'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'object': str(destination), 'exit_code': result.returncode,
                'diagnostic': (result.stdout + result.stderr)[-3000:] if result.returncode else None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        results = list(executor.map(compile_one, files))
    failures = [row for row in results if row['exit_code']]
    (output / ('build-' + variant + '.json')).write_text(json.dumps({
        'compile_command': command, 'sources': results, 'failures': len(failures),
        'kernel_runtime_verified': False}, indent=2) + '\n')
    for row in failures[:8]:
        print(row['source'], row['diagnostic'], file=sys.stderr)
    if failures:
        raise SystemExit(f'{len(failures)} ML-DSA sources failed to compile')
    for row in results:
        audit_object(Path(row['object']))
    archive = output / ('libapfs_mldsa_' + variant + '.a')
    archive.unlink(missing_ok=True)
    subprocess.run(['xcrun', 'ar', 'rcs', archive, *[row['object'] for row in results]], check=True)
    return archive, results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(os.environ.get(
        'APFS_MLDSA_SOURCE', ROOT / 'refer/corecrypto-2026')))
    parser.add_argument('--output', type=Path, default=ROOT / 'build/apfs-mldsa-12377')
    parser.add_argument('--kernel', type=Path, help='Audit against this actual linked kernel instead of link.filelist')
    parser.add_argument('--kernel-objects', type=Path,
        default=ROOT / 'build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--prepare-only', action='store_true',
        help='Prepare immutable source/header/KAT inventory only; does not claim a native build')
    args = parser.parse_args()
    if args.jobs < 1 or args.jobs > 32:
        raise SystemExit('jobs must be between1 and32')
    source, output = args.source.resolve(), args.output.resolve()
    ensure_source(source)
    files = source_files(source)
    output.mkdir(parents=True, exist_ok=True)
    include = prepare_headers(source, output)
    kat = generate_kat_header(source, output)
    files.append(ROOT / 'scripts/apfs-mldsa-selftest.c')
    if not files[-1].is_file():
        raise SystemExit('Missing runtime ML-DSA verification selftest source')
    report = {'source_url': URL, 'source_revision': REVISION,
              'source_files': [str(p) for p in files], 'known_answer': kat,
              'public_apis': sorted(PUBLIC), 'namespace_prefix': PREFIX,
              'target': 'arm64-apple-ios26.0', 'assembly_enabled': False,
              'registered_provider': False, 'native_build_completed': False,
              'kernel_runtime_verified': False}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if args.prepare_only:
        print('Prepared25 source files plus runtime KAT; no native compilation performed')
        return
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    framework = ROOT / '.cache/xnu-12377.121.6-fakeroot/System/Library/Frameworks/Kernel.framework/Versions/A'
    if not (framework / 'PrivateHeaders').is_dir() or not (framework / 'Headers').is_dir():
        raise SystemExit('Build actual XNU12377 Kernel.framework headers before this archive')
    command = ['xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64-apple-ios26.0',
               '-isysroot', sdk, '-mkernel', '-ffreestanding', '-fno-builtin',
               '-fno-stack-check', '-std=gnu99', '-fblocks', '-O2',
               '-fno-vectorize', '-fno-slp-vectorize', '-mno-implicit-float',
               '-DKERNEL=1', '-DKERNEL_PRIVATE=1', '-DBUILDKERNEL=1',
               '-DCC_USE_ASM=0', '-DCC_INTERNAL_SDK=0', '-DNDEBUG=1',
               '-Wno-deprecated-declarations', '-Wno-incompatible-library-redeclaration',
               '-I' + str(include), '-I' + str(output),
               '-I' + str(framework / 'PrivateHeaders'), '-I' + str(framework / 'Headers')]
    for folder in sorted({h.parent for h in source.rglob('*.h')
                          if 'test' not in str(h.relative_to(source)).lower()
                          and 'corecrypto_verify' not in h.parts}):
        command += ['-I', str(folder)]
    plain, _ = build(command, files, source, output, 'plain', args.jobs)
    defined = names(plain, True)
    expected_public = {'_' + name for name in PUBLIC}
    if not expected_public <= defined or any(not name[1:].isidentifier() for name in defined):
        raise SystemExit('Unexpected ML-DSA public API/global symbol inventory')
    private = sorted(defined - expected_public)
    namespace = output / 'namespace.h'
    namespace.write_text(''.join(f'#define {name[1:]} {PREFIX}{name[1:]}\n' for name in private))
    archive, results = build([*command, '-include', str(namespace)],
                             files, source, output, 'namespaced', args.jobs)
    final_defined = names(archive, True)
    expected_defined = expected_public | {'_' + PREFIX + name[1:] for name in private}
    if final_defined != expected_defined:
        raise SystemExit('Namespaced ML-DSA definitions do not exactly match isolated inventory')
    external = names(archive, False) - final_defined
    if args.kernel:
        kernel_symbols = names(args.kernel.resolve(), True)
    else:
        sys.path.insert(0, str(ROOT / 'scripts'))
        from xnu_symbols import kernel_names
        kernel_symbols = kernel_names(ROOT, object_directory=args.kernel_objects.resolve())
    missing, duplicate = sorted(external - kernel_symbols), sorted(final_defined & kernel_symbols)
    report.update({'native_build_completed': True, 'compiled_objects': len(results),
                   'private_globals_namespaced': len(private),
                   'defined_names': sorted(final_defined), 'external_names': sorted(external),
                   'missing_kernel_names': missing, 'duplicate_kernel_names': duplicate,
                   'archive': str(archive), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                   'runtime_selftest_function': '_' + PREFIX + 'native_apfs_mldsa_selftest',
                   'runtime_selftest_status': '_' + PREFIX + 'native_apfs_mldsa_selftest_result',
                   'runtime_selftest_must_run_after_allocator_ready': True})
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'required-symbols.txt').write_text(''.join(name + '\n' for name in sorted(expected_public)))
    (output / 'link-flags.json').write_text(json.dumps(
        [*[f'-Wl,-u,{name}' for name in sorted(expected_public)], str(archive)], indent=2) + '\n')
    if missing or duplicate:
        raise SystemExit(f'ML-DSA link audit failed: missing={missing}, duplicate={duplicate}')
    print(f'Built{len(results)} audited ordinary ARM64/iOS26 objects; isolated{len(private)} globals')
    print('Actual native archive:', archive)
    print('External names:', ', '.join(sorted(external)))
    print('Runtime KAT and kernel execution remain unverified')


if __name__ == '__main__':
    main()
