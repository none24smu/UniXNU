/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <sys/param.h>
#include <sys/proc.h>
#include <kern/startup.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>
#include <mach/kmod.h>
#include <sys/pthread_shims.h>

extern kern_return_t pthread_start(kmod_info_t *, void *);
extern pthread_functions_t pthread_functions;
extern pthread_callbacks_t pthread539_pthread_kern;
SECURITY_READ_ONLY_LATE(kern_return_t) source_pthread_status = KERN_FAILURE;

static void
source_pthread_bootstrap(void)
{
    static kmod_info_t info = {
        .info_version = KMOD_INFO_VERSION,
        .name = "source-libpthread",
        .version = "539.100.4",
    };
    source_pthread_status = pthread_start(&info, NULL);
    if (source_pthread_status != KERN_SUCCESS || !pthread_functions ||
        !pthread_functions->pthread_init || !pthread_functions->pth_proc_hashinit ||
        !pthread539_pthread_kern || pthread539_pthread_kern->version != 1) {
        panic("source libpthread failed versioned callback registration: %d", source_pthread_status);
    }
}
STARTUP(EARLY_BOOT, STARTUP_RANK_SECOND, source_pthread_bootstrap);
