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

# C++ ABI changes invalidate every kernel object, not selected methods only.
# Keep generated SDK headers and provider compile records on the same profile.
KDK_IOKIT_ABI=${XNU_KDK_IOKIT_ABI:-0}
if [ "$KDK_IOKIT_ABI" != 0 ] && [ "$KDK_IOKIT_ABI" != 1 ]; then
  echo 'XNU_KDK_IOKIT_ABI must be 0 or 1' >&2
  exit 1
fi
APFS_CSR=${XNU_APFS_CSR:-0}
if [ "$APFS_CSR" != 0 ] && [ "$APFS_CSR" != 1 ]; then
  echo 'XNU_APFS_CSR must be 0 or 1' >&2
  exit 1
fi
mkdir -p "$OUT"
ABI_PROFILE="iokit-abi-v2:$KDK_IOKIT_ABI:csr=$APFS_CSR"
if [ "$(cat "$OUT/.iokit-abi-profile" 2>/dev/null || true)" != "$ABI_PROFILE" ]; then
  rm -rf "$OUT/ios-obj" "$OUT/ios-sym" "$OUT/ios-dst" "$OUT/hdrs-obj" "$OUT/hdrs-sym"
  rm -f "$FAKEROOT/.xnu-$XNU_VERSION-headers"
  printf '%s\n' "$ABI_PROFILE" > "$OUT/.iokit-abi-profile"
fi
MASTER_CONFIG_DIR=$ROOT/$WORK/config
if [ "$APFS_CSR" = 1 ]; then
  MASTER_CONFIG_DIR=$OUT/apfs-csr-config
  python3 scripts/prepare-apfs-csr-config.py "$WORK/config" "$MASTER_CONFIG_DIR"
fi
if [ "${XNU_NATIVE_UFS_SM8350:-0}" = 1 ]; then
  python3 scripts/prepare-storage-headers.py
fi

if [ ! -f "$FAKEROOT/.xnu-$XNU_VERSION-headers" ]; then
  make -C "$WORK" installhdrs SDKROOT=macosx ARCH_CONFIGS=ARM64 \
    MACHINE_CONFIGS=BCM2837 KERNEL_CONFIGS=DEVELOPMENT MASTERCONFDIR="$MASTER_CONFIG_DIR" \
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
EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_KDK_IOKIT_ABI=$KDK_IOKIT_ABI"
EXTRA_MAKE_ARGS=()
OBJ=$OUT/ios-obj/DEVELOPMENT_ARM64_BCM2837
SOURCE_CRYPTO=${XNU_SOURCE_CORECRYPTO14:-0}
if [ "$SOURCE_CRYPTO" != 0 ] && [ "$SOURCE_CRYPTO" != 1 ]; then
  echo 'XNU_SOURCE_CORECRYPTO14 must be 0 or 1' >&2
  exit 1
fi

# flag VARIABLE: the 0/1 value of a CONFIG_XNU_ option (0 when unset).
flag() {
  local value=${!1:-0}
  if [ "$value" != 0 ] && [ "$value" != 1 ]; then
    echo "$1 must be 0 or 1" >&2
    exit 1
  fi
  echo "$value"
}
APFS_CRYPTO_KPIS=$(flag XNU_APFS_CRYPTO_KPIS)
if [ "$APFS_CRYPTO_KPIS" = 1 ] && [ "$SOURCE_CRYPTO" != 1 ]; then
  echo 'XNU_APFS_CRYPTO_KPIS requires XNU_SOURCE_CORECRYPTO14=1' >&2
  exit 1
fi
APFS_MLDSA=$(flag XNU_APFS_MLDSA)
if [ "$APFS_MLDSA" = 1 ] && [ "$APFS_CRYPTO_KPIS" != 1 ]; then
  echo 'XNU_APFS_MLDSA requires XNU_APFS_CRYPTO_KPIS=1' >&2
  exit 1
fi
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
# before the MMU is on; other boards need it off and use ArmCpu's GICv3 provider.
NATIVE_ARCH_TIMER=$(flag XNU_NATIVE_ARCH_TIMER)
EXTRA_MAKE_ARGS+=("start.o_SFLAGS_ADD=-DXNU_NATIVE_ARCH_TIMER=$NATIVE_ARCH_TIMER")
rebuild_on_change native-arch-timer-mode "$NATIVE_ARCH_TIMER" osfmk/DEVELOPMENT/start.o
# An EL1 port may have access to the virtual timer while physical-timer control traps.
VIRTUAL_TIMER_ONLY=$(flag XNU_VIRTUAL_TIMER_ONLY)
EXTRA_MAKE_ARGS+=("machine_routines.o_CFLAGS_ADD=-DXNU_VIRTUAL_TIMER_ONLY=$VIRTUAL_TIMER_ONLY")
rebuild_on_change virtual-timer-only-mode "$VIRTUAL_TIMER_ONLY" osfmk/DEVELOPMENT/machine_routines.o
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
# Publish the dyld_flags boot-arg in the comm page before launchd, as customer dyld reads only the comm page.
DYLD_FLAGS_BOOTARG=$(flag XNU_DYLD_FLAGS_BOOTARG)
EXTRA_MAKE_ARGS+=("commpage.o_CFLAGS_ADD=-DXNU_DYLD_FLAGS_BOOTARG=$DYLD_FLAGS_BOOTARG")
rebuild_on_change dyld-flags-bootarg-mode "$DYLD_FLAGS_BOOTARG" osfmk/DEVELOPMENT/commpage.o
# Print every exec, spawn, exit and user hardware exception on the console, for a userland that has no log
# daemon or crash reporter yet.
PROC_TRACE_CONSOLE=$(flag XNU_PROC_TRACE_CONSOLE)
# The Data seed (UniXNU NativeRamBlock) and its kernel mount at /private/var before launchd
# (native_owner_data_prepare of offline-owner-systemos-mount, patches/xnu-12377/native-owner-data-mount.patch).
NATIVE_RAM_BLOCK=$(flag XNU_NATIVE_RAM_BLOCK)
OWNER_DATA_MOUNT=$(flag XNU_OWNER_DATA_MOUNT)
if [ "$NATIVE_RAM_BLOCK" = 1 ] && [ "$(flag XNU_NATIVE_UFS_SM8350)" != 1 ]; then
  echo 'NativeRamBlock builds with the native storage family and its store window (XNU_NATIVE_UFS_SM8350)' >&2
  exit 1
fi
if [ "$OWNER_DATA_MOUNT" = 1 ] && [ "$NATIVE_RAM_BLOCK" != 1 ]; then
  echo 'XNU_OWNER_DATA_MOUNT mounts the NativeRamBlock seed (XNU_NATIVE_RAM_BLOCK)' >&2
  exit 1
fi
EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_NATIVE_RAM_BLOCK=$NATIVE_RAM_BLOCK"
rebuild_on_change native-ram-block-mode "$NATIVE_RAM_BLOCK" iokit/DEVELOPMENT/KernelConfigTables.cpo
OWNER_DATA_HEADER=$OUT/owner-data-volume.h
mkdir -p "$OUT"
python3 - "$OWNER_DATA_HEADER" "$OWNER_DATA_MOUNT" "${XNU_OWNER_DATA_VOLUME_UUID:-}" <<'PY_DATA_UUID'
import re
import sys
from pathlib import Path
path, mode, value = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
text = ''
if mode == '1':
    if not re.fullmatch(r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', value):
        raise SystemExit('Set XNU_OWNER_DATA_VOLUME_UUID to the Data seed volume UUID (upper-case)')
    text = '#define XNU_OWNER_DATA_VOLUME_UUID "' + value + '"\n'
if not path.exists() or path.read_text() != text:
    path.write_text(text)
PY_DATA_UUID
rebuild_on_change owner-data-mount-mode "$OWNER_DATA_MOUNT:$NATIVE_RAM_BLOCK:${XNU_OWNER_DATA_VOLUME_UUID:-}" bsd/DEVELOPMENT/kern_exec.o
EXTRA_MAKE_ARGS+=("kern_exec.o_CFLAGS_ADD=-DXNU_PROC_TRACE_CONSOLE=$PROC_TRACE_CONSOLE -DXNU_OWNER_DATA_MOUNT=$OWNER_DATA_MOUNT -DXNU_NATIVE_RAM_BLOCK=$NATIVE_RAM_BLOCK -include $OWNER_DATA_HEADER")
EXTRA_MAKE_ARGS+=("kern_exit.o_CFLAGS_ADD=-DXNU_PROC_TRACE_CONSOLE=$PROC_TRACE_CONSOLE")
EXTRA_MAKE_ARGS+=("exception.o_CFLAGS_ADD=-DXNU_PROC_TRACE_CONSOLE=$PROC_TRACE_CONSOLE")
rebuild_on_change proc-trace-console-mode "$PROC_TRACE_CONSOLE" bsd/DEVELOPMENT/kern_exec.o bsd/DEVELOPMENT/kern_exit.o \
  osfmk/DEVELOPMENT/exception.o
# vfs.generic.apfs.edt_fstab from the device tree's /filesystems/fstab: getfsent() reads only this on an APFS root,
# and the KDK APFS kext does not provide it.
EDT_FSTAB=$(flag XNU_EDT_FSTAB)
EXTRA_MAKE_ARGS+=("vfs_subr.o_CFLAGS_ADD=-DXNU_EDT_FSTAB=$EDT_FSTAB")
EXTRA_MAKE_ARGS+=("kern_newsysctl.o_CFLAGS_ADD=-DXNU_EDT_FSTAB=$EDT_FSTAB")
rebuild_on_change edt-fstab-mode "$EDT_FSTAB" bsd/DEVELOPMENT/vfs_subr.o bsd/DEVELOPMENT/kern_newsysctl.o
# The boot progress layer (UniXNU zzz-boot-progress, library from the device package as kits/<kit>): diagnostic page,
# checkpoints and the user fault probe. The hooks compile in once the library exists, after the first pass.
BOOT_PROGRESS=$(flag XNU_BOOT_PROGRESS)
BOOT_PROGRESS_OBJECTS="osfmk/DEVELOPMENT/arm_init.o osfmk/DEVELOPMENT/startup.o osfmk/DEVELOPMENT/video_console.o
  osfmk/DEVELOPMENT/serial_console.o osfmk/DEVELOPMENT/sleh.o bsd/DEVELOPMENT/bsd_init.o bsd/DEVELOPMENT/kern_exec.o
  bsd/DEVELOPMENT/kern_exit.o pexpert/DEVELOPMENT/pe_kprintf.o"
EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_BOOT_PROGRESS=$BOOT_PROGRESS"
# shellcheck disable=SC2086
rebuild_on_change boot-progress-mode "$BOOT_PROGRESS" $BOOT_PROGRESS_OBJECTS
if [ "$SOURCE_CRYPTO" = 1 ]; then
  EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_SOURCE_CORECRYPTO14=1"
fi
rebuild_on_change source-crypto-mode "$SOURCE_CRYPTO" osfmk/DEVELOPMENT/prng_random.o pexpert/DEVELOPMENT/pe_init.o
ARM_DT_PLATFORM=$(flag XNU_ARM_DT_PLATFORM)
ARMCPU=$(flag XNU_ARMCPU)
if [ "$ARMCPU" = 1 ] && { [ "$ARM_DT_PLATFORM" != 1 ] || [ "$NATIVE_ARCH_TIMER" != 1 ]; }; then
  echo 'ArmCpu requires ArmDTPlatform and native architectural timer routing' >&2
  exit 1
fi
EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_ARM_DT_PLATFORM=$ARM_DT_PLATFORM -DXNU_ARMCPU=$ARMCPU"
rebuild_on_change platform-personalities "$ARM_DT_PLATFORM:$ARMCPU" iokit/DEVELOPMENT/KernelConfigTables.cpo
NATIVE_DWC3_CONSOLE=$(flag XNU_NATIVE_DWC3_CONSOLE)
SOURCE_PTHREAD=$(flag XNU_SOURCE_PTHREAD)
NATIVE_UFS_SM8350=$(flag XNU_NATIVE_UFS_SM8350)
UFS_OWNER_ROOT=$(flag XNU_NATIVE_UFS_OWNER_ROOT)
UFS_VERIFIED_ROOT=$(flag XNU_NATIVE_UFS_VERIFIED_ROOT)
if [ "$UFS_OWNER_ROOT" = 1 ] && { [ "$NATIVE_UFS_SM8350" != 1 ] || [ "$UFS_VERIFIED_ROOT" != 1 ] || [ "$SOURCE_CRYPTO" != 1 ]; }; then
  echo 'Owner root binding requires SM8350 UFS, signed block verification and source crypto' >&2
  exit 1
fi
EXTRA_MAKE_ARGS+=("bsd_init.o_CFLAGS_ADD=-DXNU_NATIVE_UFS_OWNER_ROOT=$UFS_OWNER_ROOT")
rebuild_on_change ufs-owner-root-mode "$UFS_OWNER_ROOT" bsd/DEVELOPMENT/bsd_init.o
EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_NATIVE_UFS_SM8350=$NATIVE_UFS_SM8350"
EXTRA_CFLAGS="$EXTRA_CFLAGS -DXNU_NATIVE_DWC3_CONSOLE=$NATIVE_DWC3_CONSOLE"
rebuild_on_change native-dwc3-console "$NATIVE_DWC3_CONSOLE" pexpert/DEVELOPMENT/pe_serial.o osfmk/DEVELOPMENT/rtclock.o

export KERNEL_SDKROOT=$FAKEROOT
# The search paths xnu adds for SDK and KDK content this build does not have (iBoot and AppleFeatures headers,
# platform headers and libraries). Empty, they add nothing; missing, every compile warns -Wmissing-include-dirs.
mkdir -p "$FAKEROOT/usr/local/include/iBoot" \
  "$FAKEROOT/System/Library/Frameworks/Kernel.framework/Versions/A/PrivateHeaders/AppleFeatures" \
  "$KDKROOT/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/platform" \
  "$FAKEROOT/usr/local/lib/kernel/platform" "$KDKROOT/usr/local/lib/kernel/platform"
# XNU_MAKE_KEEP_GOING=1 (make -k) compiles every object that can be compiled and reports all errors of one run.
MAKE_KEEP_GOING=()
if [ "$(flag XNU_MAKE_KEEP_GOING)" = 1 ]; then
  MAKE_KEEP_GOING=(-k)
fi
build_kernel() {
make ${MAKE_KEEP_GOING[@]+"${MAKE_KEEP_GOING[@]}"} -C "$WORK" "${XNU_BUILD_TARGET:-build}" SDKROOT="${XNU_SDKROOT:-iphoneos}" KDKROOT="$KDKROOT" \
  ARCH_CONFIGS=ARM64 MACHINE_CONFIGS=BCM2837 KERNEL_CONFIGS=DEVELOPMENT \
  MASTERCONFDIR="$MASTER_CONFIG_DIR" \
  ARCH_STRING_FOR_CURRENT_MACHINE_CONFIG=arm64 LARGE_MEMORY_DEFINE=-UARM_LARGE_MEMORY \
  ARM64_LINK_ADDR=0xfffffff007004000 ARM64_PLKSEG_ADDR=0xfffffff004004000 \
  DEPLOYMENT_TARGET_FLAGS="-miphoneos-version-min=$IOS_MIN -DXNU_TARGET_OS_IOS" \
  DEPLOYMENT_LINKER_FLAGS="-Wl,-ios_version_min,$IOS_MIN" \
  RC_DARWIN_KERNEL_VERSION="$XNU_DARWIN" RC_ProjectSourceVersion="$XNU_VERSION" \
  BUILD_LTO=0 BOUND_CHECKS=0 BUILD_WERROR="${XNU_BUILD_WERROR:-0}" MAKEJOBS=-j"$JOBS" \
  CFLAGS_EXTRA="$EXTRA_CFLAGS" "${EXTRA_MAKE_ARGS[@]}" "$@" \
  OBJROOT="$OUT/ios-obj" SYMROOT="$OUT/ios-sym" DSTROOT="$OUT/ios-dst"
}
if [ "$SOURCE_CRYPTO" = 1 ] || [ "$ARM_DT_PLATFORM" = 1 ] || [ "$ARMCPU" = 1 ] || [ "$NATIVE_DWC3_CONSOLE" = 1 ] || [ "$SOURCE_PTHREAD" = 1 ] || [ "$NATIVE_UFS_SM8350" = 1 ] || [ "$BOOT_PROGRESS" = 1 ]; then
  # First produce the unlinked objects/filelist for collision discovery.
  # Bootstrap references are enabled only after the provider archive exists.
  rm -f "$OBJ/osfmk/DEVELOPMENT/prng_random.o" "$OBJ/pexpert/DEVELOPMENT/pe_init.o"
  rm -f "$OBJ/pexpert/DEVELOPMENT/pe_serial.o" "$OBJ/osfmk/DEVELOPMENT/rtclock.o"
  build_kernel CFLAGS_EXTRA="$EXTRA_CFLAGS -UXNU_SOURCE_CORECRYPTO14 -UXNU_ARM_DT_PLATFORM -UXNU_ARMCPU -UXNU_NATIVE_DWC3_CONSOLE -UXNU_BOOT_PROGRESS" \
    "bsd_init.o_CFLAGS_ADD=-DXNU_NATIVE_UFS_OWNER_ROOT=0" \
    "kern_exec.o_CFLAGS_ADD=-DXNU_PROC_TRACE_CONSOLE=$PROC_TRACE_CONSOLE -DXNU_OWNER_DATA_MOUNT=0 -DXNU_NATIVE_RAM_BLOCK=$NATIVE_RAM_BLOCK -include $OWNER_DATA_HEADER"
  ARCHIVE_FLAGS="-L$FAKEROOT/usr/local/lib/kernel -lfirehose_kernel"
  ARCHIVE_DEPENDENCIES=""
  if [ "$SOURCE_CRYPTO" = 1 ]; then
    if [ "$APFS_MLDSA" = 1 ]; then
      python3 scripts/build-apfs-mldsa-12377.py
    fi
    python3 scripts/build-corecrypto-14.py --xnu-12377
    python3 scripts/build-corecrypto-14.py --xnu-12377 --namespace
    CRYPTO_ARCHIVE=$ROOT/build/corecrypto-12377/libcorecrypto_kernel_noasm-namespaced.a
    ARCHIVE_FLAGS="$ARCHIVE_FLAGS $CRYPTO_ARCHIVE"
    ARCHIVE_DEPENDENCIES="$CRYPTO_ARCHIVE"
    if [ "$APFS_CRYPTO_KPIS" = 1 ]; then
      # These are runtime imports of the future APFS provider; archive
      # membership alone does not retain otherwise unreferenced selectors.
      ARCHIVE_FLAGS="$ARCHIVE_FLAGS -Wl,-u,_ccdigest_parallel,-u,_ccsha3_256_di,-u,_ccsha3_384_di,-u,_ccsha3_512_di"
      ARCHIVE_FLAGS="$ARCHIVE_FLAGS -Wl,-u,_ccec_import_pub,-u,_ccrsa_import_pub,-u,_ccrsa_verify_pkcs1v15_allowshortsigs"
    fi
    if [ "$APFS_MLDSA" = 1 ]; then
      MLDSA_ARCHIVE=$ROOT/build/apfs-mldsa-12377/libapfs_mldsa_namespaced.a
      ARCHIVE_FLAGS="$ARCHIVE_FLAGS -Wl,-u,_ccmldsa87,-u,_ccmldsa_import_pubkey,-u,_ccmldsa_verify $MLDSA_ARCHIVE"
      ARCHIVE_DEPENDENCIES="$ARCHIVE_DEPENDENCIES $MLDSA_ARCHIVE"
    fi
  fi
  for component in ArmDTPlatform ArmCpu NativeDwc3Console; do
    if { [ "$component" = ArmDTPlatform ] && [ "$ARM_DT_PLATFORM" = 1 ]; } || \
       { [ "$component" = ArmCpu ] && [ "$ARMCPU" = 1 ]; } || \
       { [ "$component" = NativeDwc3Console ] && [ "$NATIVE_DWC3_CONSOLE" = 1 ]; }; then
      python3 scripts/build-platform-12377.py "$component"
      archive=$ROOT/build/platform-12377/$component/lib$component.a
      ARCHIVE_FLAGS="$ARCHIVE_FLAGS -Wl,-force_load,$archive"
      ARCHIVE_DEPENDENCIES="$ARCHIVE_DEPENDENCIES $archive"
    fi
  done
  if [ "$SOURCE_PTHREAD" = 1 ]; then
    clone refer/libpthread-539 libpthread libpthread-539.100.4
    python3 scripts/build-pthread-12377.py
    archive=$ROOT/build/libpthread-12377/libpthread_kernel.a
    ARCHIVE_FLAGS="$ARCHIVE_FLAGS -Wl,-force_load,$archive"
    ARCHIVE_DEPENDENCIES="$ARCHIVE_DEPENDENCIES $archive"
  fi
  if [ "$BOOT_PROGRESS" = 1 ]; then
    if [ ! -f scripts/build-boot-progress.py ]; then
      echo 'XNU_BOOT_PROGRESS needs scripts/build-boot-progress.py from the device repository' >&2
      exit 1
    fi
    python3 scripts/build-boot-progress.py
    archive=$ROOT/build/boot-progress/libBootProgress.a
    ARCHIVE_FLAGS="$ARCHIVE_FLAGS -Wl,-force_load,$archive"
    ARCHIVE_DEPENDENCIES="$ARCHIVE_DEPENDENCIES $archive"
    # The first pass compiled the hooks out.
    for object in $BOOT_PROGRESS_OBJECTS; do
      rm -f "$OBJ/$object"
    done
  fi
  if [ "$NATIVE_UFS_SM8350" = 1 ]; then
    python3 scripts/build-storage-12377.py
    archive=$ROOT/build/storage-12377/libStorageUfs.a
    ARCHIVE_FLAGS="$ARCHIVE_FLAGS -Wl,-force_load,$archive"
    ARCHIVE_DEPENDENCIES="$ARCHIVE_DEPENDENCIES $archive"
  fi
  rm -f "$OBJ/osfmk/DEVELOPMENT/prng_random.o" "$OBJ/pexpert/DEVELOPMENT/pe_init.o"
  rm -f "$OBJ/iokit/DEVELOPMENT/KernelConfigTables.cpo"
  rm -f "$OBJ/pexpert/DEVELOPMENT/pe_serial.o" "$OBJ/osfmk/DEVELOPMENT/rtclock.o"
  if [ "$UFS_OWNER_ROOT" = 1 ]; then
    # The first pass must not reference an archive that has not been built.
    # Recompile the callsite only after the actual owner binding exists.
    rm -f "$OBJ/bsd/DEVELOPMENT/bsd_init.o"
  fi
  if [ "$OWNER_DATA_MOUNT" = 1 ]; then
    # The Data mount calls NativeRamBlock, which links from the storage archive.
    rm -f "$OBJ/bsd/DEVELOPMENT/kern_exec.o"
  fi
  build_kernel "LD_KERNEL_ARCHIVES=$ARCHIVE_FLAGS" "XNU_EXTERNAL_KERNEL_ARCHIVES=$ARCHIVE_DEPENDENCIES"
  if [ "$APFS_CRYPTO_KPIS" = 1 ]; then
    python3 - "$OBJ/mach.development.bcm2837.unstripped.noctf" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys

kernel = Path(sys.argv[1])
defined = set(subprocess.check_output(['xcrun', 'nm', '-g', '-U', '-j', kernel], text=True).splitlines())
required = {'_ccdigest_parallel', '_ccsha3_256_di', '_ccsha3_384_di',
            '_ccsha3_512_di', '_native_apfs_crypto_kpis_selftest',
            '_native_apfs_crypto_selftest_result', '_ccec_import_pub',
            '_ccrsa_import_pub', '_ccrsa_verify_pkcs1v15_allowshortsigs'}
if os.environ.get('XNU_APFS_MLDSA') == '1':
    required |= {'_ccmldsa87', '_ccmldsa_import_pubkey', '_ccmldsa_verify',
                 '_zeta_mldsa26_native_apfs_mldsa_selftest',
                 '_zeta_mldsa26_native_apfs_mldsa_selftest_result'}
if os.environ.get('XNU_APFS_CSR') == '1':
    required.add('_csr_check')
if os.environ.get('XNU_NATIVE_UFS_OWNER_ROOT') == '1':
    required |= {'_native_ufs_owner_root_authorized', '_native_ufs_owner_root_accepted'}
missing = sorted(required - defined)
kernel.with_suffix('.apfs-crypto.json').write_text(json.dumps({
    'required_definitions': sorted(required), 'missing': missing,
    'runtime_selftest_passed': False}, indent=2) + '\n')
if missing:
    raise SystemExit(f'Final kernel omitted APFS crypto definitions: {missing}')
PY
  fi
  if [ "$SOURCE_CRYPTO" = 1 ]; then
    python3 scripts/seal-source-crypto-kernel.py --static-if-defaults "$OBJ/mach.development.bcm2837.unstripped.noctf"
  fi
else
  build_kernel
fi
# The iPhoneOS kernel is mach.development.bcm2837[.unstripped[.noctf]] in the object directory; ios-sym may not exist.
for directory in "$OUT/ios-sym" "$OBJ"; do
  if [ -d "$directory" ]; then
    find "$directory" -maxdepth 1 \( -name 'kernel.*' -o -name 'mach.*' \) -type f -exec ls -l {} +
  fi
done
