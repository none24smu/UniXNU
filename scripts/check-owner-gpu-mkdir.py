#!/usr/bin/env python3
"""Host failure/selection checks of the real typed owner GPU directory helper.

VFS peers verify path/mode/segment/error handling; real kernel-header compilation
and native APFS installation are separate gates.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();source=a.source/'bsd/vfs/vfs_syscalls.c';text=source.read_text()
start=text.index('int native_owner_mkdir_gpu_path(');end=text.index('\n/*\n * mkdir_extended:',start)
body=text[start:end]
assert 'UIO_SYSSPACE' in body and 'mkdir1at' in body
assert not a.output.exists();a.output.mkdir(parents=True)
template='\n#include <assert.h>\n#include <stdint.h>\n#include <string.h>\n#include <errno.h>\n#define AT_FDCWD -2\n#define UIO_SYSSPACE 2\n#ifdef CAST_USER_ADDR_T\n#undef CAST_USER_ADDR_T\n#endif\n#define CAST_USER_ADDR_T(p) ((uintptr_t)(p))\nstruct vnode_attr {int va_mode;};\n#define VATTR_INIT(v) memset(v,0,sizeof(*(v)))\n#define VATTR_SET(v,n,x) ((v)->n=(x))\nstatic int calls,error;\nstatic const char *expected;\nstatic void *vfs_context_current(void){return (void *)0x100;}\nstatic int mkdir1at(void *ctx,uintptr_t path,struct vnode_attr *a,int fd,int seg){\n assert(ctx==(void*)0x100 && !strcmp((const char*)path,expected));\n assert(a->va_mode==0755 && fd==AT_FDCWD && seg==UIO_SYSSPACE);calls++;return error;\n}\nBODY\nint main(void){\n const char *bad[]={0,"", "/private/var", "/private/var/ngpux", "/private/var/ngpu/../Library", "/private/var/ngpu/./addons", "/private/var/ngpu/../../etc"};\n for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++)assert(native_owner_mkdir_gpu_path(bad[i])==EINVAL && !calls);\n const char *good[]={"/private/var/ngpu", "/private/var/ngpu/addons", "/private/var/ngpu/addons/NativeAdrenoMetal.bundle"};\n int errors[]={0,EEXIST,EIO,ENOSPC,EROFS};\n for(unsigned i=0;i<3;i++)for(unsigned e=0;e<5;e++){expected=good[i];error=errors[e];int before=calls;assert(native_owner_mkdir_gpu_path(good[i])==error && calls==before+1);}\n return 0;\n}\n'
(a.output/'test.c').write_text(template.replace('BODY',body))
subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',str(a.output/'test.c'),'-o',str(a.output/'test')],check=True)
subprocess.run([str(a.output/'test')],check=True)
r=dict(result='pass',source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),rejected_paths=7,valid_paths=3,propagated_errors=5,asan_ubsan=True,kernel_headers_compiled=False,native_execution=False)
(a.output/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
