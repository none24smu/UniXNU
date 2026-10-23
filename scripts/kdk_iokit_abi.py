"""Explicit, opt-in public IOStorage compatibility profile for KDK APFS audits.

This does not change TARGET_OS_OSX, relocate a kext, or establish compatibility.
References stay immutable; only exported build copies select the public legacy
implementations associated with the extra virtual slots.
"""
import os


GUARDS = {
    'IOStorage.h': 6, 'IOStorage.cpp': 4,
    'IOBlockStorageDevice.h': 4, 'IOBlockStorageDevice.cpp': 3,
    'IOBlockStorageDriver.h': 6, 'IOBlockStorageDriver.cpp': 8,
    'IOMedia.cpp': 5, 'IOPartitionScheme.cpp': 2,
}


def enabled():
    value = os.environ.get('XNU_KDK_IOKIT_ABI', '0')
    if value not in ('0', '1'):
        raise ValueError('XNU_KDK_IOKIT_ABI must be 0 or 1')
    return value == '1'


def storage_copy(name, text, compatibility):
    if not compatibility or name not in GUARDS:
        return text
    old = '#if TARGET_OS_OSX\n'
    if text.count(old) != GUARDS[name] or 'XNU_KDK_IOKIT_ABI' in text:
        raise ValueError(f'{name}: public storage compatibility guards changed')
    return text.replace(old, '#if TARGET_OS_OSX || XNU_KDK_IOKIT_ABI\n')
