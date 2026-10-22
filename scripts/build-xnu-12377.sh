#!/usr/bin/env bash
set -euo pipefail
# Name the command that stops the build.
trap 'echo "build-xnu-12377.sh: line $LINENO: $BASH_COMMAND failed" >&2' ERR
# DEVELOPMENT BCM2837 kernel from xnu-12377 (iOS 26) and the patches/xnu-12377 series.
# The xnu-10063 kernel (build-xnu-4k-baseline.sh) and its trees are not touched: everything here lives under
# .cache/xnu-$XNU_VERSION-* and build/xnu-$XNU_VERSION. Source versions come from feeds.toml through the unixnu
# driver; the defaults are the macOS/iOS 26.5 release set.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
XNU_TAG=${UNIXNU_XNU_TAG:-xnu-12377.121.6}
XNU_COMMIT=${UNIXNU_XNU_COMMIT:-ac9718fb1af618d5ce8678d0dc6e8a58f252216f}
XNU_DARWIN=${UNIXNU_XNU_DARWIN:-25.5.0}
XNU_VERSION=${UNIXNU_XNU_VERSION:-12377.121.6}
LIBPLATFORM_TAG=${UNIXNU_LIBPLATFORM_TAG:-libplatform-375.120.2}
LIBDISPATCH_TAG=${UNIXNU_LIBDISPATCH_TAG:-libdispatch-1542.100.32}
AVAILABILITY_TAG=${UNIXNU_AVAILABILITYVERSIONS_TAG:-AvailabilityVersions-157.2}
# Kernel Debug Kit of the same release (macOS 26.5.2 25F84 = iOS 26.5.2 23F84), for the headers xnu-12377 takes from it.
KDK_URL=${UNIXNU_KDK_URL:-https://github.com/dortania/KdkSupportPkg/releases/download/25F84/Kernel_Debug_Kit_26.5.2_build_25F84.dmg}
KDK_SHA256=${UNIXNU_KDK_SHA256:-faef4393becf65c88a2791770904909babf1826d23d2ea478bf878a6417851ab}
IOS_MIN=${XNU_IOS_DEPLOYMENT_TARGET:-26.0}
JOBS=${JOBS:-4}

WORK=.cache/xnu-$XNU_VERSION-work
FAKEROOT=$ROOT/.cache/xnu-$XNU_VERSION-fakeroot
KDKROOT=$ROOT/.cache/xnu-$XNU_VERSION-kdk
OUT=$ROOT/build/xnu-$XNU_VERSION
PATCHES=$ROOT/patches/xnu-12377

clone() {  # clone DIR REPOSITORY TAG
  if [ ! -d "$1/.git" ]; then
    git clone --depth 1 --branch "$3" "https://github.com/apple-oss-distributions/$2.git" "$1"
  fi
}

clone refer/xnu xnu "$XNU_TAG"
if [ "$(git -C refer/xnu rev-parse HEAD)" != "$XNU_COMMIT" ]; then
  echo "error: refer/xnu is not $XNU_TAG ($XNU_COMMIT); run unixnu fetch with the xnu-12377 feeds" >&2
  exit 1
fi
if [ ! -d "$WORK/.git" ]; then
  git clone --shared refer/xnu "$WORK"
fi
if [ "$(git -C "$WORK" rev-parse HEAD)" != "$XNU_COMMIT" ]; then
  echo "error: $WORK is not at $XNU_COMMIT; remove it to start again" >&2
  exit 1
fi
# Apply the series in name order; a patch that is already in the tree is skipped.
for PATCH in "$PATCHES"/*.patch; do
  if ! git -C "$WORK" apply --reverse --check "$PATCH" >/dev/null 2>&1; then
    git -C "$WORK" apply --check "$PATCH"
    git -C "$WORK" apply "$PATCH"
  fi
done

if [ ! -x "$FAKEROOT/usr/local/libexec/availability.pl" ]; then
  clone refer/AvailabilityVersions AvailabilityVersions "$AVAILABILITY_TAG"
  mkdir -p "$FAKEROOT"
  make -C refer/AvailabilityVersions install -j"$JOBS" \
    OBJROOT="$OUT/availability" SYMROOT="$OUT/availability" \
    DSTROOT="$FAKEROOT" CMAKE="$(command -v cmake)" NINJA="$(command -v ninja)"
fi
export XNU_AVAILABILITY_PL=$FAKEROOT/usr/local/libexec/availability.pl

python3 scripts/kdk-headers.py --url "$KDK_URL" --sha256 "$KDK_SHA256" --cache .cache/kdk "$KDKROOT"

clone refer/libplatform libplatform "$LIBPLATFORM_TAG"
mkdir -p "$FAKEROOT/usr/local/include/kernel"
ditto refer/libplatform/include "$FAKEROOT/usr/local/include"
ditto refer/libplatform/private "$FAKEROOT/usr/local/include"
ditto refer/libplatform/private/platform "$FAKEROOT/System/Library/Frameworks/Kernel.framework/Versions/A/PrivateHeaders/platform"

clone refer/libdispatch libdispatch "$LIBDISPATCH_TAG"
python3 - "$FAKEROOT/usr/local/include/os" <<'PY'
from pathlib import Path
import subprocess, sys
output = Path(sys.argv[1])
output.mkdir(parents=True, exist_ok=True)
for header in Path('refer/libdispatch/os').glob('*.h'):
    result = subprocess.run(['unifdef', '-DKERNEL=1', '-DOS_FIREHOSE_SPI=1',
                             '-DOS_VOUCHER_ACTIVITY_SPI_TYPES=1',
                             '-UOS_VOUCHER_ACTIVITY_SPI', str(header)], capture_output=True)
    if result.returncode not in (0, 1):
        raise SystemExit(result.stderr.decode())
    target = output / header.name
    if not target.exists() or target.read_bytes() != result.stdout:
        target.write_bytes(result.stdout)
PY

if [ ! -f "$FAKEROOT/.xnu-$XNU_VERSION-headers" ]; then
  make -C "$WORK" installhdrs SDKROOT=macosx ARCH_CONFIGS=ARM64 \
    MACHINE_CONFIGS=BCM2837 KERNEL_CONFIGS=DEVELOPMENT \
    RC_DARWIN_KERNEL_VERSION="$XNU_DARWIN" RC_ProjectSourceVersion="$XNU_VERSION" \
    MAKEJOBS=-j"$JOBS" OBJROOT="$OUT/hdrs-obj" SYMROOT="$OUT/hdrs-sym" DSTROOT="$FAKEROOT"
  touch "$FAKEROOT/.xnu-$XNU_VERSION-headers"
fi

# libfirehose_kernel.a for the kernel link (LD_KERNEL_ARCHIVES), arm64 like the kernel.
if [ ! -f "$FAKEROOT/usr/local/lib/kernel/libfirehose_kernel.a" ]; then
  if [ ! -d ".cache/libdispatch-$LIBDISPATCH_TAG-work/.git" ]; then
    git clone --shared refer/libdispatch ".cache/libdispatch-$LIBDISPATCH_TAG-work"
  fi
  python3 - ".cache/libdispatch-$LIBDISPATCH_TAG-work/xcodeconfig/libfirehose_kernel.xcconfig" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace('$(SDKROOT)/System/Library/Frameworks/Kernel.framework',
              '$(FAKEROOT_DIR)/System/Library/Frameworks/Kernel.framework')
s = s.replace('$(SDKROOT)/usr/local/include', '$(FAKEROOT_DIR)/usr/local/include')
lines = s.splitlines()
for index, line in enumerate(lines):
    if line.startswith('HEADER_SEARCH_PATHS =') and '$(SDKROOT)/usr/include' not in line:
        lines[index] += (' $(SDKROOT)/usr/include $(FAKEROOT_DIR)/usr/local/include'
                         ' $(XNU_SOURCE)/EXTERNAL_HEADERS')
s = '\n'.join(lines) + '\n'
if p.read_text() != s:
    p.write_text(s)
PY
  xcodebuild install -project ".cache/libdispatch-$LIBDISPATCH_TAG-work/libdispatch.xcodeproj" \
    -target libfirehose_kernel -configuration Release -sdk iphoneos -jobs "$JOBS" \
    ARCHS=arm64 VALID_ARCHS=arm64 ONLY_ACTIVE_ARCH=NO IPHONEOS_DEPLOYMENT_TARGET="$IOS_MIN" \
    CODE_SIGNING_ALLOWED=NO GCC_TREAT_WARNINGS_AS_ERRORS=NO \
    OBJROOT="$OUT/firehose/obj" SYMROOT="$OUT/firehose/sym" \
    DSTROOT="$FAKEROOT" FAKEROOT_DIR="$FAKEROOT" XNU_SOURCE="$ROOT/$WORK"
  if [ -f "$FAKEROOT/usr/local/lib/kernel/liblibfirehose_kernel.a" ]; then
    cp "$FAKEROOT/usr/local/lib/kernel/liblibfirehose_kernel.a" "$FAKEROOT/usr/local/lib/kernel/libfirehose_kernel.a"
  fi
  xcrun lipo -info "$FAKEROOT/usr/local/lib/kernel/libfirehose_kernel.a"
fi

EXTRA_CFLAGS=${XNU_EXTRA_CFLAGS:--Wno-reserved-identifier -Wno-pre-c11-compat -Wno-missing-designated-field-initializers -Wno-suggest-override -Wno-unnecessary-virtual-specifier -Wno-suggest-destructor-override -Wno-ms-bitfield-padding}
EXTRA_MAKE_ARGS=()
OBJ=$OUT/ios-obj/DEVELOPMENT_ARM64_BCM2837

# flag VARIABLE: the 0/1 value of a CONFIG_XNU_ option (0 when unset).
flag() {
  local value=${!1:-0}
  if [ "$value" != 0 ] && [ "$value" != 1 ]; then
    echo "$1 must be 0 or 1" >&2
    exit 1
  fi
  echo "$value"
}
# rebuild_on_change NAME VALUE OBJECT...: make does not track per-object flags, so drop the objects when VALUE changes.
rebuild_on_change() {
  local stamp=$OBJ/.$1 value=$2
  shift 2
  mkdir -p "$OBJ"
  if [ "$(cat "$stamp" 2>/dev/null || echo 0)" != "$value" ]; then
    for object in "$@"; do
      rm -f "$OBJ/$object"
    done
    printf '%s\n' "$value" > "$stamp"
  fi
}

# BCM2837 start.s routes the core timers through the Raspberry Pi local interrupt controller (physical 0x40000040)
# before the MMU is on; other boards need it off. In the xnu-10063 build this also required ArmCpu, the GIC timer
# provider, which is not ported to xnu-12377 yet: until it is, the kernel has no timer interrupt either way.
NATIVE_ARCH_TIMER=$(flag XNU_NATIVE_ARCH_TIMER)
EXTRA_MAKE_ARGS+=("start.o_SFLAGS_ADD=-DXNU_NATIVE_ARCH_TIMER=$NATIVE_ARCH_TIMER")
rebuild_on_change native-arch-timer-mode "$NATIVE_ARCH_TIMER" osfmk/DEVELOPMENT/start.o
# PAN on ARMv8.1+ cores; the files that read the PAN register by name need ARMv8.1 code generation.
NATIVE_PAN=$(flag XNU_NATIVE_PAN)
EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_NATIVE_PAN=$NATIVE_PAN"
for object in copyio.o pcb.o platform_tests.o; do
  if [ "$NATIVE_PAN" = 1 ]; then
    EXTRA_MAKE_ARGS+=("${object}_CFLAGS_ADD=-march=armv8.1-a")
  fi
done
# Panic log in the device tree's pram region instead of the Raspberry Pi address PLATFORM_PANIC_LOG_PADDR.
DT_PANIC_REGION=$(flag XNU_DT_PANIC_REGION)
EXTRA_MAKE_ARGS+=("pe_init.o_CFLAGS_ADD=-DXNU_DT_PANIC_REGION=$DT_PANIC_REGION")
rebuild_on_change dt-panic-region-mode "$DT_PANIC_REGION" pexpert/DEVELOPMENT/pe_init.o
# trust_cache_init() at boot, which BCM2837 skips.
TRUST_CACHE_MODE=$(flag XNU_TRUST_CACHE_RUNTIME)
EXTRA_MAKE_ARGS+=("startup.o_CFLAGS_ADD=-DXNU_NATIVE_TRUST_CACHE=$TRUST_CACHE_MODE")
rebuild_on_change trust-cache-mode "$TRUST_CACHE_MODE" osfmk/DEVELOPMENT/startup.o

export KERNEL_SDKROOT=$FAKEROOT
make -C "$WORK" "${XNU_BUILD_TARGET:-build}" SDKROOT="${XNU_SDKROOT:-iphoneos}" KDKROOT="$KDKROOT" \
  ARCH_CONFIGS=ARM64 MACHINE_CONFIGS=BCM2837 KERNEL_CONFIGS=DEVELOPMENT \
  ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG=arm64 LARGE_MEMORY_DEFINE=-UARM_LARGE_MEMORY \
  ARM64_LINK_ADDR=0xfffffff007004000 ARM64_PLKSEG_ADDR=0xfffffff004004000 \
  DEPLOYMENT_TARGET_FLAGS="-miphoneos-version-min=$IOS_MIN -DXNU_TARGET_OS_IOS" \
  DEPLOYMENT_LINKER_FLAGS="-Wl,-ios_version_min,$IOS_MIN" \
  RC_DARWIN_KERNEL_VERSION="$XNU_DARWIN" RC_ProjectSourceVersion="$XNU_VERSION" \
  BUILD_LTO=0 BOUND_CHECKS=0 BUILD_WERROR="${XNU_BUILD_WERROR:-0}" MAKEJOBS=-j"$JOBS" \
  CFLAGS_EXTRA="$EXTRA_CFLAGS" "${EXTRA_MAKE_ARGS[@]}" \
  OBJROOT="$OUT/ios-obj" SYMROOT="$OUT/ios-sym" DSTROOT="$OUT/ios-dst"
find "$OUT/ios-sym" "$OUT/ios-obj/DEVELOPMENT_ARM64_BCM2837" -maxdepth 1 \( -name 'kernel.*' -o -name 'mach.*' \) -type f -exec ls -l {} +
