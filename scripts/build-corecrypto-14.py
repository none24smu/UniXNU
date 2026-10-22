#!/usr/bin/env python3
"""Compile the pinned 2023 crypto provider internally for ABI verification.

Apple source, generated headers and objects remain ignored. This does not
register the provider, produce a certified module or demonstrate a kernel boot.
"""
import concurrent.futures
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from xnu_symbols import kernel_names
SOURCE = ROOT / 'refer/corecrypto-2023'
REVISION = '11fba65b12d8830630e248dfa8344caf8b065f26'
OUT = ROOT / 'build/corecrypto-2023'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--namespace', action='store_true', help='Isolate provider globals from XNU crypto wrappers')
parser.add_argument('--xnu-12377', action='store_true', help='Use the iOS 26 build headers, ABI adapter and separate output')
args = parser.parse_args()
if args.xnu_12377:
    OUT = ROOT / 'build/corecrypto-12377'
deployment = '26.0' if args.xnu_12377 else '17.0'
kernel_objects = ROOT / 'build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837' if args.xnu_12377 else None


def current_kernel_names():
    return kernel_names(ROOT, object_directory=kernel_objects)


def names(path, mode):
    text = subprocess.check_output(['xcrun', 'nm', '-g', mode, '-j', path], text=True)
    return {line.strip() for line in text.splitlines() if line.startswith('_')}


if subprocess.check_output(['git', '-C', SOURCE, 'rev-parse', 'HEAD'], text=True).strip() != REVISION:
    raise SystemExit('Unexpected corecrypto source revision')
if subprocess.check_output(['git', '-C', SOURCE, 'status', '--porcelain'], text=True):
    raise SystemExit('The crypto reference must stay immutable')
OUT.mkdir(parents=True, exist_ok=True)
if args.xnu_12377:
    xnu = ROOT / '.cache/xnu-12377.121.6-work'
    def normalized(text):
        return re.sub(r'\s+', '', re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S))
    for name in ('ccmode', 'cchmac'):
        if normalized((SOURCE / name / 'corecrypto' / (name + '.h')).read_text()) != normalized(
                (xnu / 'EXTERNAL_HEADERS/corecrypto' / (name + '.h')).read_text()):
            raise SystemExit(f'Unaudited {name} ABI change')
    def table(text, name):
        return normalized(text.split('struct ' + name + ' {', 1)[1].split('};', 1)[0])
    if table((SOURCE / 'cckprng/corecrypto/cckprng.h').read_text(), 'cckprng_funcs') != table(
            (xnu / 'EXTERNAL_HEADERS/corecrypto/cckprng.h').read_text(), 'cckprng_funcs'):
        raise SystemExit('Unaudited PRNG callback ABI change')
    if table((SOURCE / 'ccrng/corecrypto/ccrng.h').read_text(), 'ccrng_state') != table(
            (xnu / 'EXTERNAL_HEADERS/corecrypto/ccrng.h').read_text(), 'ccrng_state'):
        raise SystemExit('Unaudited RNG callback ABI change')
    fields_text = (xnu / 'libkern/libkern/crypto/register_crypto.h').read_text().split(
        'typedef struct crypto_functions {', 1)[1].split('} *crypto_functions_t;', 1)[0]
    fields = set(re.findall(r'\b(\w+)\s*;', fields_text))
    provider = (SOURCE / 'corecrypto_kext/corecrypto_kext.c').read_text()
    adapter = (ROOT / 'scripts/corecrypto-12377-kpi.h').read_text()
    assigned = set(re.findall(r'\bkpis\.(\w+)\s*=', provider)) | set(re.findall(r'\bfuncs->(\w+)\s*=', adapter))
    if fields != assigned:
        raise SystemExit(f'Incomplete crypto callback coverage: {sorted(fields ^ assigned)}')
    (OUT / 'abi-report.json').write_text(json.dumps({
        'callback_fields_assigned': sorted(fields), 'rng_and_prng_callbacks_match': True,
        'mode_and_hmac_headers_match': True, 'digest_descriptor_uses_kernel_header': True,
        'provider_private_contexts_are_opaque_to_xnu': True,
        'runtime_compatibility_verified': False}, indent=2) + '\n')
subprocess.run(['plutil', '-convert', 'json', '-o', OUT / 'project.json',
                SOURCE / 'corecrypto.xcodeproj/project.pbxproj'], check=True)
project = json.loads((OUT / 'project.json').read_text())
objects = project['objects']
parents = {child: key for key, value in objects.items() for child in value.get('children', [])}


def resolve(key):
    entry = objects[key]
    path = entry.get('path', '')
    if entry.get('sourceTree') == 'SOURCE_ROOT' or key not in parents:
        return SOURCE / path
    if entry.get('sourceTree') != '<group>':
        raise ValueError(f'Unsupported source tree: {entry}')
    return resolve(parents[key]) / path


target = next(value for value in objects.values() if value.get('isa') == 'PBXNativeTarget'
              and value.get('name') == 'corecrypto_kext')
phase = next(objects[key] for key in target['buildPhases'] if objects[key]['isa'] == 'PBXSourcesBuildPhase')
sources = [resolve(objects[key]['fileRef']) for key in phase['files']
           if objects[objects[key]['fileRef']].get('path', '').endswith('.c')]
for source in sources:
    if not source.is_file() or not source.resolve().is_relative_to(SOURCE.resolve()):
        raise SystemExit(f'Missing or unexpected source path: {source}')
include = OUT / 'include/corecrypto'
include.mkdir(parents=True, exist_ok=True)
for header in SOURCE.glob('*/corecrypto/*.h'):
    if args.xnu_12377 and header.name == 'ccdigest.h':
        header = ROOT / '.cache/xnu-12377.121.6-work/EXTERNAL_HEADERS/corecrypto/ccdigest.h'
    link = include / header.name
    if link.exists() and link.resolve() != header.resolve():
        raise SystemExit(f'Conflicting header: {header.name}')
    if not link.exists():
        link.symlink_to(header)
sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
framework_root = '.cache/xnu-12377.121.6-fakeroot' if args.xnu_12377 else '.cache/fakeroot'
framework = ROOT / framework_root / 'System/Library/Frameworks/Kernel.framework/Versions/A'
# The separate include directory preserves the provider's private contexts;
# ccdigest.h above uses the kernel's appended compress_parallel descriptor field.
command = ['xcrun', '--sdk', 'iphoneos', 'clang', '-target', f'arm64-apple-ios{deployment}', '-isysroot', sdk,
           '-mkernel', '-ffreestanding', '-fno-builtin', '-fno-stack-check', '-std=gnu99', '-fblocks', '-O2',
           '-fno-vectorize', '-fno-slp-vectorize', '-mno-implicit-float',
           '-DKERNEL=1', '-DKERNEL_PRIVATE=1', '-DBUILDKERNEL=1', '-DCC_USE_ASM=0', '-DNDEBUG=1',
           '-DCC_DISABLE_RSAKEYGEN=1', '-Wno-deprecated-declarations', '-Wno-incompatible-library-redeclaration',
           '-I' + str(include.parent), '-I' + str(framework / 'PrivateHeaders'), '-I' + str(framework / 'Headers')]
if args.xnu_12377:
    # The generic non-Apple kernel has no Apple userspace commpage. Scalar C
    # implementations must not probe its CPU-capability mapping for DIT/SHA.
    command.append('-DCC_INTERNAL_SDK=0')
for folder in sorted({h.parent for h in SOURCE.rglob('*.h') if 'test' not in str(h.relative_to(SOURCE)).lower()}):
    command.extend(['-I', str(folder)])
variant = '-namespaced' if args.namespace else ''
if args.namespace:
    plain = OUT / 'libcorecrypto_kernel_noasm.a'
    if not plain.is_file():
        raise SystemExit('Build the plain provider once before creating its namespace')
    collisions = sorted(names(plain, '-U') & current_kernel_names())
    if any(not name[1:].isidentifier() for name in collisions):
        raise SystemExit('A colliding symbol cannot be namespaced with a C identifier')
    header = OUT / 'namespace.h'
    header.write_text(''.join(f'#define {name[1:]} cc14_{name[1:]}\n' for name in collisions))
    command.extend(['-include', str(header)])
(OUT / f'compile-command{variant}.json').write_text(json.dumps(command, indent=2) + '\n')
object_dir = OUT / f'objects{variant}'
object_dir.mkdir(exist_ok=True)


def compile_one(source):
    relative = str(source.relative_to(SOURCE))
    name = hashlib.sha256(relative.encode()).hexdigest()[:12] + '-' + source.stem
    destination = object_dir / (name + '.o')
    compile_source = source
    if args.xnu_12377 and relative == 'corecrypto_kext/corecrypto_kext.c':
        text = source.read_text()
        registration = '    register_crypto_functions(&kpis);'
        definition = 'kern_return_t corecrypto_kext_start(kmod_info_t *ki, void *d)\n{'
        if text.count(registration) != 1 or text.count(definition) != 1:
            raise SystemExit('Unexpected provider registration source')
        text = text.replace(definition, '#include "' + str(ROOT / 'scripts/corecrypto-12377-kpi.h') + '"\n\n' + definition)
        text = text.replace(registration, '    cc12377_complete_kpis(&kpis);\n' + registration)
        compile_source = object_dir / 'corecrypto_kext-12377.c'
        compile_source.write_text(text)
    result = subprocess.run([*command, '-c', compile_source, '-o', destination], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    (object_dir / (name + '.log')).write_text(result.stdout)
    return {'source': relative, 'object': destination.name, 'exit_code': result.returncode,
            'diagnostic': result.stdout[-2500:] if result.returncode else None}


with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(compile_one, sources))
failed = [result for result in results if result['exit_code']]
report = {'source_url': 'https://github.com/ONLYA/corecrypto-2023', 'source_revision': REVISION,
          'provenance': 'Third-party source snapshot; not authenticated against an Apple archive',
          'module_version': '14.0', 'target': f'arm64-apple-ios{deployment}', 'assembly_enabled': False,
          'compiled_sources': len(results), 'failures': len(failed), 'objects': results,
          'kernel_provider_registered': False, 'crypto_selftests_passed': False}
(OUT / f'build-report{variant}.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'{len(results)} kernel C sources; {len(failed)} failures', flush=True)
for result in failed[:8]:
    print(result['source'], result['diagnostic'], flush=True)
if failed:
    sys.exit(1)
for result in results:
    data = (object_dir / result['object']).read_bytes()
    magic, cpu, subtype, kind, count, size = struct.unpack_from('<6I', data)
    if (magic, cpu, subtype, kind) != (0xfeedfacf, 0x100000c, 0, 1):
        raise SystemExit(f'Wrong object architecture: {result["object"]}')
    offset = 32
    object_deployment = None
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', data, offset)
        if cmd == 0x32:
            object_deployment = struct.unpack_from('<II', data, offset + 8)
        offset += length
    if object_deployment != (2, 0x1a0000 if args.xnu_12377 else 0x110000):
        raise SystemExit(f'Wrong deployment: {result["object"]}: {object_deployment}')
archive = OUT / f'libcorecrypto_kernel_noasm{variant}.a'
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', archive, *[object_dir / result['object'] for result in results]], check=True)
defined = names(archive, '-U')
undefined = names(archive, '-u') - defined
kernel_exports = current_kernel_names()
survey = {'unresolved_external_names': sorted(undefined), 'missing_kernel_names': sorted(undefined - kernel_exports),
          'duplicate_kernel_names': sorted(defined & kernel_exports), 'provider_registered': False,
          'abi_compatibility_proven': False}
(OUT / f'link-survey{variant}.json').write_text(json.dumps(survey, indent=2) + '\n')
report['object_architecture_and_deployment_audited'] = len(results)
report['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
report['namespace_isolated'] = args.namespace
(OUT / f'build-report{variant}.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'Internal unregistered provider archive: {archive.name}')
print(f'External names absent from kernel: {survey["missing_kernel_names"]}')
print(f'Globals shared with kernel: {len(survey["duplicate_kernel_names"])}; initialization and intact selftests are still required')
