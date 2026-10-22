#!/usr/bin/env python3
"""Build the generic platform and CPU drivers with the current XNU 12377 ABI."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('component', choices=['ArmDTPlatform', 'ArmCpu'])
args = parser.parse_args()
obj = ROOT / 'build/xnu-12377.121.6/ios-obj/DEVELOPMENT_ARM64_BCM2837'
record = json.loads((obj / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').read_text().strip().rstrip(','))
out = ROOT / 'build/platform-12377' / args.component
out.mkdir(parents=True, exist_ok=True)
source = ROOT / 'drivers' / args.component / (args.component + '.cpp')
destination = out / (args.component + '.o')
command = []
arguments = record['arguments']
index = 0
while index < len(arguments):
    value = arguments[index]
    if value == record['file']:
        command.append(str(source))
    elif value == '-o':
        command += ['-o', str(destination)]
        index += 1
    elif value in ('-MF', '-MJ', '-MT', '-MQ'):
        index += 1
    elif value == '-Xclang' and arguments[index + 1].startswith('-W'):
        index += 1
    elif value not in ('-MD', '-MMD', '-MP') and not value.startswith('-W'):
        command.append(value)
    index += 1
command += ['-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-c99-designator',
            '-Wno-reorder-init-list', '-Wno-deprecated-enum-enum-conversion',
            '-Wno-unnecessary-virtual-specifier']
(out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
result = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
(out / 'compile.log').write_text(result.stdout + result.stderr)
if result.returncode:
    raise SystemExit(result.stdout + result.stderr)
data = destination.read_bytes()
if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
    raise SystemExit('Expected a plain ARM64 Mach-O object')
cursor = 32
deployment = None
for _ in range(struct.unpack_from('<I', data, 16)[0]):
    kind, size = struct.unpack_from('<II', data, cursor)
    if kind == 0x32:
        deployment = struct.unpack_from('<II', data, cursor + 8)
    cursor += size
if deployment != (2, 26 << 16):
    raise SystemExit(f'Expected iOS 26 deployment, found {deployment}')
archive = out / ('lib' + args.component + '.a')
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', archive, destination], check=True)
print(f'{args.component}: compiled against XNU 12377, ARM64/iOS 26 object verified')
