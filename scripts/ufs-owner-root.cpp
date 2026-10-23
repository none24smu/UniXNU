// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bind a mounted readonly root to an actual owner-verified UFS window.
// No Apple authentication result or registry identity is manufactured here.
#include <IOKit/IOBSD.h>
#include <IOKit/IOService.h>
#include <IOKit/storage/IOMedia.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>
#include <sys/types.h>
#include <sys/param.h>

extern "C" int native_ufs_block_authenticates(IOService *, const char *, uint8_t *);
extern volatile uint32_t native_ufs_integrity_failures;

extern "C" {
volatile int native_ufs_owner_root_accepted = 0;
volatile uint32_t native_ufs_owner_root_matches = 0;
volatile uint32_t native_ufs_owner_root_depth = 0;
char native_ufs_owner_root_uuid[37] = {};
uint8_t native_ufs_owner_root_manifest[48] = {};
}

extern "C" int
native_ufs_owner_root_authorized(dev_t mounted, dev_t selected, int readonly)
{
    native_ufs_owner_root_accepted = 0;
    native_ufs_owner_root_matches = native_ufs_owner_root_depth = 0;
    bzero(native_ufs_owner_root_uuid, sizeof(native_ufs_owner_root_uuid));
    bzero(native_ufs_owner_root_manifest, sizeof(native_ufs_owner_root_manifest));
    if (!readonly || mounted == NODEV || mounted != selected || native_ufs_integrity_failures) return 0;

    OSDictionary *matching = IOService::serviceMatching("IOMedia");
    OSDictionary *properties = OSDictionary::withCapacity(2);
    OSNumber *mjr = OSNumber::withNumber(static_cast<unsigned>(major(mounted)), 32);
    OSNumber *mnr = OSNumber::withNumber(static_cast<unsigned>(minor(mounted)), 32);
    if (!matching || !properties || !mjr || !mnr) {
        OSSafeReleaseNULL(mnr); OSSafeReleaseNULL(mjr);
        OSSafeReleaseNULL(properties); OSSafeReleaseNULL(matching);
        return 0;
    }
    bool ready = properties->setObject(kIOBSDMajorKey, mjr) && properties->setObject(kIOBSDMinorKey, mnr) &&
        matching->setObject("IOPropertyMatch", properties);
    mnr->release(); mjr->release(); properties->release();
    OSIterator *iterator = ready ? IOService::getMatchingServices(matching) : nullptr;
    matching->release();
    if (!iterator) return 0;

    bool authorized = false;
    unsigned matches = 0, depth = 0;
    char uuid[37] = {};
    uint8_t digest[48] = {};
    while (OSObject *object = iterator->getNextObject()) {
        // More than one object for the selected dev_t is ambiguous, even if
        // one happens to authenticate. Inspect the entire result set.
        if (++matches != 1) { authorized = false; break; }
        IOMedia *media = OSDynamicCast(IOMedia, object);
        if (!media || media->isWritable()) continue;
        OSString *identity = OSDynamicCast(OSString, media->getProperty("UUID"));
        if (!identity || identity->getLength() != 36) continue;
        strlcpy(uuid, identity->getCStringNoCopy(), sizeof(uuid));
        for (IOService *provider = media; provider && depth < 64; provider = provider->getProvider()) {
            ++depth;
            // Strongly linked to NativeUfs. It accepts only an online UFS
            // window whose real RSA-verified policy names this exact UUID.
            // Every read still verifies its block against that signed table.
            int verdict = native_ufs_block_authenticates(provider, uuid, digest);
            if (verdict >= 0) { authorized = verdict == 1; break; }
        }
    }
    iterator->release();
    native_ufs_owner_root_matches = matches;
    native_ufs_owner_root_depth = depth;
    if (!authorized || matches != 1 || native_ufs_integrity_failures) return 0;
    strlcpy(native_ufs_owner_root_uuid, uuid, sizeof(native_ufs_owner_root_uuid));
    memcpy(native_ufs_owner_root_manifest, digest, sizeof(digest));
    native_ufs_owner_root_accepted = 1;
    return 1;
}
