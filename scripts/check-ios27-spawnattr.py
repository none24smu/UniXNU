#!/usr/bin/env python3
"""Test the production iOS27 spawnattr translator against legacy layout.

Host failure injection checks bytes and bounds, not native syscall behavior.
The corresponding IPSW setter instructions are an independent evidence gate.
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
begin = text.index('static int\nnative_ios27_spawnattr_copyin(')
end = text.index('\n#endif', begin)
helper = text[begin:end]
header = (a.source / 'bsd/sys/spawn_internal.h').read_text()
begin = header.index('typedef struct _posix_spawnattr {')
end = header.index('} *_posix_spawnattr_t;', begin) + len('} *_posix_spawnattr_t;')
layout = header[begin:end]
assert not a.output.exists()
a.output.mkdir(parents=True)
code = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#ifndef ARM_FIXTURE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#else
static int failed;
#define assert(x) do {if(!(x))failed=__LINE__;}while(0)
void *memcpy(void *d,const void *s,size_t n){unsigned char *to=d;const unsigned char *from=s;for(size_t i=0;i<n;i++)to[i]=from[i];return d;}
void *memset(void *d,int c,size_t n){unsigned char *to=d;for(size_t i=0;i<n;i++)to[i]=(unsigned char)c;return d;}
int memcmp(const void *a,const void *b,size_t n){const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return x[i]-y[i];return 0;}
#endif
#define EINVAL 22
#define EFAULT 14
#define ENOTSUP 45
#define bzero(d,n) memset(d,0,n)
#define NBINPREFS 4
typedef uint64_t user_addr_t,user_size_t;
typedef uint32_t sigset_t;
typedef int32_t pid_t,cpu_type_t,cpu_subtype_t,task_role_t;
typedef void *_posix_spawn_port_actions_t,*_posix_spawn_mac_policy_extensions_t;
LAYOUT
static const unsigned char *allowed;
static size_t available;
static int reads;
static int copyin(user_addr_t address,void *to,size_t n) {
 ++reads;uintptr_t low=(uintptr_t)allowed,at=(uintptr_t)address;
 if(at<low || at-low>available || n>available-(at-low))return EFAULT;
 memcpy(to,(const void *)at,n);return 0;
}
HELPER
static void u32(unsigned char *b,size_t o,uint32_t n){memcpy(b+o,&n,4);}
#ifdef ARM_FIXTURE
extern int stock_crash(void *,unsigned,unsigned);
extern int stock_kq(void *,unsigned,unsigned);
extern int stock_security(void *,unsigned);
extern int stock_conclave(void *,unsigned);
extern int stock_fd(void *,unsigned,unsigned);
extern int stock_port(void *,unsigned,unsigned);
#endif
static int test(void) {
 unsigned char wire[256],before[256];
 struct _posix_spawnattr out,prior;
 memset(wire,0,sizeof(wire));wire[0xa8]=3;
 u32(wire,0xac,0x1201);u32(wire,0xb4,7);u32(wire,0xb8,1);
 u32(wire,0xbc,512);u32(wire,0xc0,1024);u32(wire,0xc4,2048);
 u32(wire,0x84,10000);u32(wire,0x88,20000);u32(wire,0x8c,400);u32(wire,0x90,800);
#ifdef ARM_FIXTURE
 void *attr=wire;
 assert(!stock_crash(&attr,7,1));assert(!stock_kq(&attr,512,1024));
 assert(!stock_security(&attr,0x1201));assert(!stock_conclave(&attr,2048));
 assert(!stock_fd(&attr,400,800));assert(!stock_port(&attr,10000,20000));
#endif
 memcpy(before,wire,sizeof(wire));allowed=wire;available=sizeof(wire);reads=0;
 memset(&out,0x55,sizeof(out));
 assert(!native_ios27_spawnattr_copyin((uintptr_t)wire,256,true,&out));
 assert(reads==1 && !memcmp(before,wire,sizeof(wire)));
 assert(!memcmp(wire,&out,0xa9));assert(out.psa_sec_flags==0x1201);
 assert(out.psa_crash_count==7 && out.psa_throttle_timeout==1);
 assert(out.psa_kqworkloop_soft_limit==512 && out.psa_kqworkloop_hard_limit==1024);
 assert(out.psa_conclave_mem_limit==2048 && out.psa_ports==(void *)0x5555555555555555ULL);
 assert(out.psa_port_soft_limit==10000 && out.psa_port_hard_limit==20000);
 assert(out.psa_filedesc_soft_limit==400 && out.psa_filedesc_hard_limit==800);
 /* Reproduce the original bug: old prefix reads crash/throttle as limits. */
 memset(&prior,0,sizeof(prior));memcpy(&prior,wire,0xc0);
 assert(prior.psa_kqworkloop_soft_limit==7 && prior.psa_kqworkloop_hard_limit==1);
 /* New requests outside supported policy fail before changing output. */
 prior=out;wire[0xb0]=1;
 assert(native_ios27_spawnattr_copyin((uintptr_t)wire,256,true,&out)==ENOTSUP);
 assert(!memcmp(&out,&prior,sizeof(out)));wire[0xb0]=0;
 u32(wire,0xac,0x10000);
 assert(native_ios27_spawnattr_copyin((uintptr_t)wire,256,true,&out)==ENOTSUP);
 assert(!memcmp(&out,&prior,sizeof(out)));u32(wire,0xac,0x1201);
 available=199;
 assert(native_ios27_spawnattr_copyin((uintptr_t)wire,256,true,&out)==EFAULT);
 assert(!memcmp(&out,&prior,sizeof(out)));available=sizeof(wire);
 assert(native_ios27_spawnattr_copyin((uintptr_t)wire,255,true,&out)==EINVAL);
 assert(native_ios27_spawnattr_copyin((uintptr_t)wire,257,true,&out)==EINVAL);
 /* Legacy and 32-bit paths retain the exact prior prefix copy. */
 memset(&out,0x55,sizeof(out));
 assert(!native_ios27_spawnattr_copyin((uintptr_t)wire,248,true,&out));
 assert(!memcmp(&out,wire,0xc0));
 assert(!native_ios27_spawnattr_copyin((uintptr_t)wire,220,false,&out));
 assert(!memcmp(&out,wire,0xc0));
#ifdef ARM_FIXTURE
 return failed;
#else
 return 0;
#endif
}
#ifndef ARM_FIXTURE
int main(void){return test();}
#else
void _start(void){register long status __asm__("x0")=test();register long call __asm__("x8")=93;__asm__ volatile("svc #0"::"r"(status),"r"(call):"memory");__builtin_unreachable();}
#endif
'''.replace('LAYOUT', layout).replace('HELPER', helper)
test = a.output / 'test.c'
test.write_text(code)
command = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
           '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(test), '-o', str(a.output / 'host')]
r = subprocess.run(command, capture_output=True)
(a.output / 'build.log').write_bytes(r.stdout + r.stderr)
r.check_returncode()
r = subprocess.run([str(a.output / 'host')], capture_output=True)
(a.output / 'run.log').write_bytes(r.stdout + r.stderr)
r.check_returncode()
result = dict(result='pass', real_source_helper=True, real_legacy_layout=True, asan_ubsan=True,
              source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), command=command,
              old_bug_reproduced=True, unsupported_policy_rejected=True, original_input_unchanged=True,
              real_sdk_compilation=False, native_syscall_execution=False)
(a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
