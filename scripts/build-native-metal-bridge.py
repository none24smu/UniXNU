#!/usr/bin/env python3
"""Build the native Metal bridge (drivers/NativeMetal/bridge/NativeMetalBridge.rs): the pinned metal2vulkan runtime behind a C ABI, as a static library.

--target ios (default) cross-builds for arm64-apple-ios17.0, --target host for the macOS host simulation. The runtime's own example library
(runtime_examples.ll) and its function-constant fixture are assembled to AIR with llvm-as and embedded for the self-tests. Only generated build files hold local paths; nothing here
is committed. Output: build/native-metal-bridge/<target>/libnative_metal_bridge.a"""
import argparse
import json
import os
import platform
import re
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / 'scripts/data/gpu-metal-vulkan-inputs.json').read_text())['translator']['commit']
SOURCE = ROOT / '.cache/gpu-reference/metal2vulkan'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--target', choices=['ios', 'host'], default='ios')
args = parser.parse_args()
if subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
    raise SystemExit('Translator revision differs from the qualified source pin')
from recorded_patches import apply_series
PATCHES = [ROOT / 'drivers/NativeMetal/bridge/patches' / name for name in ['0001-optional-constant-output-members.patch', '0002-resource-wait-storage-dependencies.patch', '0003-cache-device-entry-point-priming.patch', '0004-fold-constant-global-field-loads.patch', '0005-keep-module-decodes-and-profile-fingerprints.patch', '0006-skip-draws-without-a-pipeline.patch', '0007-accept-two-plane-rgb-surfaces.patch', '0008-alias-padded-rows-of-written-textures.patch', '0009-keep-final-pass.patch', '0010-fewer-allocations-per-draw.patch', '0011-keep-draw-commands.patch', '0012-keep-draw-lists.patch', '0013-skip-unchanged-rebinds.patch', '0014-map-tracker-keys.patch', '0015-two-plane-shadow-as-memory-lies.patch', '0016-tile-stores-within-rows.patch', '0017-smaller-pool-blocks.patch']]
apply_series(SOURCE, PATCHES)
out = ROOT / 'build/native-metal-bridge'
out.mkdir(parents=True, exist_ok=True)
llvm_as = next((p for p in ['/opt/homebrew/opt/llvm/bin/llvm-as', shutil.which('llvm-as') or ''] if p and Path(p).exists()), None)
if not llvm_as:
    raise SystemExit('llvm-as (LLVM 21 or newer) is required to assemble the fixture')
air = out / 'runtime_examples.air'
subprocess.run([llvm_as, '-o', air, SOURCE / 'crates/metal2vulkan-validation/fixtures/public/examples/runtime_examples.ll'], check=True)
fc_air = out / 'function_constant.air'
subprocess.run([llvm_as, '-o', fc_air, SOURCE / 'crates/metal2vulkan-validation/fixtures/public/kernel_function_constant_gate_fold.ll'], check=True)
manifest = out / 'Cargo.toml'
manifest.write_text('\n'.join([
    '[package]', 'name = "native-metal-bridge"', 'version = "0.1.0"', 'edition = "2024"', 'rust-version = "1.98"', '[workspace]',
    '[lib]', 'crate-type = ["staticlib"]', 'path = ' + json.dumps(str(ROOT / 'drivers/NativeMetal/bridge/NativeMetalBridge.rs')),
    '[dependencies]',
    'metal2vulkan = { path = ' + json.dumps(str(SOURCE / 'crates/metal2vulkan')) + ', features = ["ash"] }',
    'metal2vulkan-runtime = { path = ' + json.dumps(str(SOURCE / 'crates/metal2vulkan-runtime')) + ' }',
    'libc = "0.2"',
    # The runtime hashes every shader-cache key and entry; without asm, sha2 0.10 on aarch64 is the portable software rounds, not the
    # ARMv8 SHA-256 instructions every target CPU has (cpufeatures answers sha2 true on Apple platforms).
    'sha2 = { version = "0.10", features = ["asm"] }',
    '[profile.release]', 'panic = "unwind"', 'debug = 1', '',
]))
triple = 'aarch64-apple-ios' if args.target == 'ios' else {
    'arm64': 'aarch64-apple-darwin', 'x86_64': 'x86_64-apple-darwin',
}[platform.machine()]
env = dict(os.environ, NMB_FIXTURE_AIR=str(air), NMB_FC_AIR=str(fc_air), IPHONEOS_DEPLOYMENT_TARGET='17.0', MACOSX_DEPLOYMENT_TARGET='14.0')
target_dir = ROOT / 'build/m2v-target'
log = out / ('build-%s.log' % args.target)
with log.open('w') as stream:
    result = subprocess.run(['cargo', '+1.98.0', 'build', '--release', '--manifest-path', manifest, '--target', triple,
                             '--target-dir', target_dir], env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
if result.returncode:
    raise SystemExit(log.read_text()[-6000:])
library = target_dir / triple / 'release/libnative_metal_bridge.a'
final = out / args.target / 'libnative_metal_bridge.a'
final.parent.mkdir(exist_ok=True)
shutil.copyfile(library, final)
print('PASS: native Metal bridge static library for %s (%d bytes); translator %s' % (args.target, final.stat().st_size, PIN[:12]))
