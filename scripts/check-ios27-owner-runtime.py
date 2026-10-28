#!/usr/bin/env python3
"""Exercise the real owner-runtime composition and explicit watchdog policy gate.

Host peers test selection, error propagation and call order. This does not
replace compilation with XNU headers or native mount/launchd validation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
source = a.source / 'bsd/kern/kern_exec.c'
text = source.read_text()
start = text.index('\tuint32_t owner_runtime = 0;')
end = text.index('\n#endif\ndone:', start)
namespace = text[start:end]
start = text.index('#if defined(XNU_BOOT_PROGRESS) && XNU_BOOT_PROGRESS\n', end)
end = text.index('\n#endif\n#if CONFIG_MEMORYSTATUS', start)
policy = text[start:end]
assert 'ios27-owner-runtime' in namespace and 'sheng-disable-watchdogd' in policy
assert not a.output.exists()
a.output.mkdir(parents=True)
code = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef EAUTH
#define EAUTH 80
#endif
typedef void *vnode_t;
#define NULLVP ((vnode_t)0)
static unsigned enabled, watchdog, missing, forbidden, lookups, put_count, mounts;
static unsigned bad_mount, bad_stage, policy_calls, policy_error, panics;
static int PE_parse_boot_argn(const char *name, void *out, unsigned size) {
 assert(size == sizeof(uint32_t));
 if (!strcmp(name,"ios27-owner-runtime")) {*(uint32_t *)out=enabled;return enabled!=0;}
 assert(!strcmp(name,"sheng-disable-watchdogd"));*(uint32_t *)out=watchdog;return watchdog!=0;
}
static void *vfs_context_current(void) {return (void *)0x100;}
static int vnode_lookup(const char *name,int flags,vnode_t *out,void *context) {
 assert(!flags && context==(void *)0x100);++lookups;
 if (!strcmp(name,"/private/var/Library/libobjc-trampolines.dylib")) {
  if(missing)return ENOENT;*out=(void *)0x200;return 0;
 }
 assert(!strcmp(name,"/System/Cryptexes/OS/usr/lib/dyld") || !strcmp(name,"/private/var/Library/dyld"));
 if (forbidden) {*out=(void *)0x200;return 0;}return ENOENT;
}
static void vnode_put(vnode_t v) {assert(v==(void *)0x200);++put_count;}
static void native_gpu_addon_mount(void *p,uint64_t scratch,uint64_t offset,const char *from,unsigned long from_size,
 const char *to,unsigned long to_size,const char *visible,const char *own,volatile int *stage,volatile int *status) {
 assert(p==(void *)0x300 && scratch==0x100000 && offset==0x400);
 assert(from_size==strlen(from)+1 && to_size==strlen(to)+1);
 assert(!strcmp(to,"/usr/lib") && !strcmp(visible,"/usr/lib/dyld") && !strcmp(own,"/usr/lib/libobjc-trampolines.dylib"));
 assert(!strcmp(from,mounts?"/private/var/Library":"/System/Cryptexes/OS/usr/lib"));
 ++mounts;*stage=(bad_stage==mounts)?4:5;*status=(bad_mount==mounts)?EIO:0;
}
int sheng_boot_watchdog_policy(void *p,uint64_t scratch) {
 assert(p==(void *)0x300 && scratch==0x100000);++policy_calls;return (int)policy_error;
}
static void boot_progress_stage(const char *s) {(void)s;}
static void panic(const char *s,int e) {(void)s;assert(e==EIO);++panics;}
static int test_namespace(void) {int error=0;void *p=(void *)0x300;uint64_t scratch=0x100000;
NAMESPACE
 return error;
}
static void test_policy(void) {void *p=(void *)0x300;uint64_t scratch_addr=0x100000;
POLICY
}
static void reset(void) {enabled=watchdog=missing=forbidden=lookups=put_count=mounts=bad_mount=bad_stage=policy_calls=policy_error=panics=0;}
int main(void) {
 reset();assert(!test_namespace());assert(!lookups && !mounts);
 reset();enabled=2;assert(!test_namespace());assert(!lookups && !mounts);
 reset();enabled=1;assert(!test_namespace());assert(lookups==3 && put_count==1 && mounts==2);
 reset();enabled=missing=1;assert(test_namespace()==ENOENT);assert(lookups==1 && !put_count && !mounts);
 reset();enabled=forbidden=1;assert(test_namespace()==EAUTH);assert(lookups==2 && put_count==2 && !mounts);
 for(unsigned n=1;n<=2;n++) {
  reset();enabled=1;bad_mount=n;assert(test_namespace()==EIO && mounts==n);
  reset();enabled=1;bad_stage=n;assert(test_namespace()==EIO && mounts==n);
 }
 reset();test_policy();assert(policy_calls==(XNU_IOS27_CRYPTEXES?0:1));
 reset();watchdog=2;test_policy();assert(policy_calls==(XNU_IOS27_CRYPTEXES?0:1));
 reset();watchdog=1;test_policy();assert(policy_calls==1 && !panics);
 reset();watchdog=1;policy_error=EIO;test_policy();assert(policy_calls==1 && panics==1);
 return 0;
}
'''.replace('NAMESPACE', namespace).replace('POLICY', policy)
test = a.output / 'test.c'
test.write_text(code)
results = []
for profile in (0, 1):
    binary = a.output / f'profile{profile}'
    command = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
               '-DXNU_BOOT_PROGRESS=1', f'-DXNU_IOS27_CRYPTEXES={profile}', str(test), '-o', str(binary)]
    built = subprocess.run(command, capture_output=True)
    (a.output / f'build{profile}.log').write_bytes(built.stdout + built.stderr)
    built.check_returncode()
    run = subprocess.run([str(binary)], capture_output=True)
    (a.output / f'run{profile}.log').write_bytes(run.stdout + run.stderr)
    run.check_returncode()
    results.append(dict(profile=profile, passed=True, command=command))
result = dict(result='pass', results=results, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
              real_source_fragments=True, asan_ubsan=True, kernel_headers_compiled=False,
              native_execution=False, scope='Explicit opt-in, both mount failures and missing/forbidden inputs; watchdog policy opt-in and errors')
(a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
