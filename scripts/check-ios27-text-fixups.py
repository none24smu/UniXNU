#!/usr/bin/env python3
"""ASan/UBSan tests of the actual patched validator, with source profile0/1.

Extracts production C and its real VM validation hook into explicit host peers.
No kernel build, working-source patch, root image or phone access occurs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',required=True,type=Path)
p.add_argument('--descriptors',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
p.add_argument('--page-size',type=int,choices=(4096,16384),default=4096);args=p.parse_args()
args.output.mkdir(parents=True,exist_ok=False)
patch=ROOT/'patches/xnu-12377/native-text-fixup.patch'
names=['bsd/kern/ubc_subr.c','osfmk/vm/vm_fault.c','osfmk/vm/vm_protos.h','bsd/kern/mach_loader.c']
with tempfile.TemporaryDirectory() as temporary:
    tree=Path(temporary)
    for name in names:
        raw=subprocess.check_output(['git','-C',str(args.source),'show','HEAD:'+name]);target=tree/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    subprocess.run(['git','apply','--unsafe-paths','--directory='+str(tree).lstrip('/'),str(patch)],cwd='/',check=True)
    ubc=(tree/names[0]).read_text();vm=(tree/names[1]).read_text()
    start=ubc.index('/*\n * Fixups of signed file text');end=ubc.index('\nboolean_t\ncs_validate_range',start)
    production=ubc[start:end]
    begin=vm.index('\t/* Boot-argument fixups of signed text land after validation')
    hook=vm[begin:vm.index('\n#endif',begin)]
    (args.output/'production-validator.c').write_text(production)
    (args.output/'production-vm-hook.c').write_text(hook)
    loader=(tree/names[3]).read_text()
    begin=loader.index('#if __arm64__\n\t/* addr is a private kalloc/vn_rdwr copy')
    loader_hook=loader[begin:loader.index('\n#endif',begin)+len('\n#endif')]
    assert loader.index('addr = kalloc_data(alloc_size, Z_WAITOK);') < loader.index('error = vn_rdwr(UIO_READ, vp, addr, (int)alloc_size') < begin < loader.index(' *  Scan through the commands') < loader.index('valid = cs_validate_range(vp,')
    (args.output/'production-loader-hook.c').write_text(loader_hook)

header=r'''#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAGE_SIZE 4096u
#define PAGE_MASK 4095u
#define PAGE_SHIFT 12u
#define __arm64__ 1
#define NULLVP NULL
#define kSuccess 0
#define VMP_CS_ALL_TRUE 1
#define VMP_CS_ALL_FALSE 0
#define TUNABLE_STR(v,n,k,d) char v[n]=d
#define STARTUP(a,b,c)
#define relaxed __ATOMIC_RELAXED
#define os_atomic_inc(p,o) __atomic_add_fetch((p),1,(o))
#define os_atomic_add(p,n,o) __atomic_add_fetch((p),(n),(o))
typedef uint64_t memory_object_offset_t;
typedef uintptr_t pmap_paddr_t;
typedef void *DTEntry;
struct vnode {const char *v_name;};
static const char *legacy_table,*large_table;
static unsigned legacy_size,large_size,syncs;
static int SecureDTLookupEntry(void*a,const char*b,DTEntry*out){(void)a;(void)b;*out=(void*)1;return 0;}
static int SecureDTGetProperty(DTEntry a,const char*n,const void**v,unsigned*s){
 (void)a;if(!strcmp(n,"text-fixups")&&legacy_table){*v=legacy_table;*s=legacy_size;return 0;}
 if(!strcmp(n,"text-fixups-ios27")&&large_table){*v=large_table;*s=large_size;return 0;}return 1;}
static size_t host_strlcpy(char*d,const char*s,size_t z){size_t n=strlen(s);if(z){size_t k=n<z-1?n:z-1;memcpy(d,s,k);d[k]=0;}return n;}
#define strlcpy host_strlcpy
struct TestPage {uint8_t bytes[PAGE_SIZE];};
static struct TestPage testpage __attribute__((aligned(PAGE_SIZE)));
static uintptr_t phystokv(uintptr_t p){return p;}
#define VM_PAGE_GET_PHYS_PAGE(p) ((uintptr_t)(p)->bytes>>PAGE_SHIFT)
static void cache_sync_page(uintptr_t p){(void)p;syncs++;}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#x);exit(2);}}while(0)
'''
wrapper='\nstatic void validated_page(struct vnode*vnode,uint64_t mo_offset,struct TestPage*page,int validated,int tainted){\n'+hook+'\n}\n'
tests=r'''
static void reset(const char*old,unsigned os,const char*next,unsigned ns){
 legacy_table=old;legacy_size=os;large_table=next;large_size=ns;
 cs_text_fixup_count=cs_text_fixup_parsed=cs_text_fixup_applied=0;
 memset(cs_text_fixups,0,sizeof(cs_text_fixups));
 cs_text_fixup_arg0[0]=cs_text_fixup_arg1[0]=cs_text_fixup_arg2[0]=cs_text_fixup_arg3[0]=0;
 cs_text_fixup_arg4[0]=cs_text_fixup_arg5[0]=cs_text_fixup_arg6[0]=cs_text_fixup_arg7[0]=0;
 #if XNU_IOS27_TEXT_FIXUPS
 cs_ios27_text_file_count=cs_ios27_text_fixup_parsed=cs_ios27_text_fixup_applied=0;
 cs_ios27_text_fixup_rejected=cs_ios27_text_fixup_mismatched_pages=0;
 cs_ios27_text_fixup_page_lookups=cs_ios27_text_fixup_lookup_steps=0;
 #endif
 syncs=0;memset(&testpage,0,sizeof(testpage));cs_text_fixup_init();
}
static char*read_file(const char*path,size_t*size){FILE*f=fopen(path,"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>=0);rewind(f);char*b=malloc((size_t)n+1);CHECK(b);CHECK(fread(b,1,(size_t)n,f)==(size_t)n);fclose(f);b[n]=0;*size=(size_t)n;return b;}
int main(int argc,char**argv){
 (void)argv;CHECK(argc==3);const char*old="legacy,0,01020304,05060708";struct vnode legacy={"legacy"};
 reset(old,(unsigned)strlen(old)+1,NULL,0);CHECK(cs_text_fixup_parsed==1);
 memcpy(testpage.bytes,"\1\2\3\4",4);validated_page(&legacy,0,&testpage,0,0);CHECK(!syncs&&!memcmp(testpage.bytes,"\1\2\3\4",4));
 validated_page(&legacy,0,&testpage,1,1);CHECK(!syncs);validated_page(&legacy,0,&testpage,1,0);CHECK(syncs==1&&!memcmp(testpage.bytes,"\5\6\7\10",4));
 #if !XNU_IOS27_TEXT_FIXUPS
 const char*next="child,0,01020304,05060708";reset(NULL,0,next,(unsigned)strlen(next)+1);CHECK(!cs_text_fixup_parsed&&sizeof(cs_text_fixups)/sizeof(cs_text_fixups[0])==32);
 struct vnode child={"child"};memcpy(testpage.bytes,"\1\2\3\4",4);validated_page(&child,0,&testpage,1,0);CHECK(!syncs&&!memcmp(testpage.bytes,"\1\2\3\4",4));
 puts("PASS profile0 ordinary32 behavior and large-property ignored");return 0;
 #else
 const char good[]="child,0,01020304,05060708\0child,4,090a0b0c,0d0e0f10";
 reset(NULL,0,good,sizeof(good));CHECK(cs_ios27_text_fixup_parsed==2);struct vnode child={"child"};
 memcpy(testpage.bytes,"\1\2\3\4\11\12\13\14",8);validated_page(&child,0,&testpage,0,0);CHECK(!cs_ios27_text_fixup_page_lookups&&!syncs);
 validated_page(&child,0,&testpage,1,1);CHECK(!cs_ios27_text_fixup_page_lookups&&!syncs);validated_page(&child,0,&testpage,1,0);
 CHECK(cs_ios27_text_fixup_applied==2&&syncs==1&&!memcmp(testpage.bytes,"\5\6\7\10\15\16\17\20",8));
 reset(NULL,0,good,sizeof(good));memcpy(testpage.bytes,"\1\2\3\4\11\12\13\0",8);uint8_t prior[PAGE_SIZE];memcpy(prior,testpage.bytes,PAGE_SIZE);
 validated_page(&child,0,&testpage,1,0);CHECK(!syncs&&!cs_ios27_text_fixup_applied&&cs_ios27_text_fixup_mismatched_pages==1&&!memcmp(prior,testpage.bytes,PAGE_SIZE));
 const char*bad[]={"z,0,00,01\0a,0,00,01","child,0,00,01\0child,0,00,01","child,0,00010203,04050607\0child,2,0001,0203","child,,00,01","child,0,0,01","child,0,00,0102","child,ffffffffffffffff,00,01","child,10000000000000000,00,01","child,ffe,00010203,04050607","bad/name,0,00,01","child,0,00,01,",""};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
  unsigned n=(unsigned)strlen(bad[i])+1;if(i<3)n=(unsigned)strlen(bad[i])+1+(unsigned)strlen(bad[i]+strlen(bad[i])+1)+1;
  reset(NULL,0,bad[i],n);CHECK(!cs_ios27_text_fixup_parsed&&cs_ios27_text_fixup_rejected==1);
 }
 reset(NULL,0,good,sizeof(good)-1);CHECK(cs_ios27_text_fixup_rejected==1&&!cs_ios27_text_fixup_parsed);
 reset(NULL,0,"x",CS_IOS27_TEXT_FIXUP_MAX*160u+1);CHECK(cs_ios27_text_fixup_rejected==1);
 reset(old,(unsigned)strlen(old)+1,good,sizeof(good));CHECK(cs_text_fixup_parsed==1&&cs_ios27_text_fixup_parsed==2);
 memcpy(testpage.bytes,"\1\2\3\4",4);validated_page(&legacy,0,&testpage,1,0);CHECK(syncs==1&&!memcmp(testpage.bytes,"\5\6\7\10",4));
 memcpy(testpage.bytes,"\1\2\3\4\11\12\13\14",8);validated_page(&child,0,&testpage,1,0);CHECK(syncs==2&&cs_ios27_text_fixup_applied==2);
 const char*overlap="legacy,0,01020304,05060708";reset(old,(unsigned)strlen(old)+1,overlap,(unsigned)strlen(overlap)+1);
 CHECK(cs_text_fixup_parsed==1&&!cs_ios27_text_fixup_parsed&&cs_ios27_text_fixup_rejected==1);
 char*large=malloc(4*1024*1024);CHECK(large);size_t used=0;
 for(unsigned i=0;i<CS_IOS27_TEXT_FIXUP_MAX+1;i++){int n=snprintf(large+used,4*1024*1024-used,"huge,%x,01020304,05060708",i*4);CHECK(n>0);used+=(size_t)n+1;if(i+1==CS_IOS27_TEXT_FIXUP_MAX){
  reset(NULL,0,large,(unsigned)used);CHECK(cs_ios27_text_fixup_parsed==CS_IOS27_TEXT_FIXUP_MAX);
  struct vnode cache={"dyld_shared_cache_arm64e_x1.01"};validated_page(&cache,0,&testpage,1,0);CHECK(!syncs&&cs_ios27_text_fixup_lookup_steps<=8);
  for(unsigned j=0;j<PAGE_SIZE;j+=4)memcpy(testpage.bytes+j,"\1\2\3\4",4);
  struct vnode huge={"huge"};uint64_t steps=cs_ios27_text_fixup_lookup_steps;validated_page(&huge,(i*4)&~(uint64_t)PAGE_MASK,&testpage,1,0);
  CHECK(cs_ios27_text_fixup_applied==1024&&syncs==1&&cs_ios27_text_fixup_lookup_steps-steps<=18);
 }}
 reset(NULL,0,large,(unsigned)used);CHECK(!cs_ios27_text_fixup_parsed&&cs_ios27_text_fixup_rejected==1);free(large);
 char many[CS_IOS27_TEXT_FILE_MAX*32+32];used=0;for(unsigned i=0;i<CS_IOS27_TEXT_FILE_MAX+1;i++){int n=snprintf(many+used,sizeof(many)-used,"name%03u,0,00,01",i);CHECK(n>0);used+=(size_t)n+1;if(i+1==CS_IOS27_TEXT_FILE_MAX){reset(NULL,0,many,(unsigned)used);CHECK(cs_ios27_text_fixup_parsed==CS_IOS27_TEXT_FILE_MAX&&cs_ios27_text_file_count==CS_IOS27_TEXT_FILE_MAX);}}
 reset(NULL,0,many,(unsigned)used);CHECK(!cs_ios27_text_fixup_parsed&&cs_ios27_text_fixup_rejected==1);
 size_t table_size;char*table=read_file(argv[1],&table_size);reset(NULL,0,table,(unsigned)table_size);CHECK(cs_ios27_text_fixup_parsed==28208);
 unsigned pages=0;uint8_t expected[PAGE_SIZE];
 for(uint32_t i=0;i<cs_ios27_text_fixup_parsed;){
  struct cs_text_fixup*f=&cs_ios27_text_fixups[i];uint64_t page=f->offset&~(uint64_t)PAGE_MASK;char path[1024];CHECK(snprintf(path,sizeof(path),"%s/%s",argv[2],f->name)>0);
  FILE*input=fopen(path,"rb");CHECK(input&&!fseek(input,(long)page,SEEK_SET));memset(testpage.bytes,0,PAGE_SIZE);CHECK(fread(testpage.bytes,1,PAGE_SIZE,input)>0);fclose(input);memcpy(expected,testpage.bytes,PAGE_SIZE);
  uint32_t first=i;while(i<cs_ios27_text_fixup_parsed&&!strcmp(f->name,cs_ios27_text_fixups[i].name)&&(cs_ios27_text_fixups[i].offset&~(uint64_t)PAGE_MASK)==page){
   struct cs_text_fixup*x=&cs_ios27_text_fixups[i];CHECK(!memcmp(expected+(x->offset-page),x->original,x->length));memcpy(expected+(x->offset-page),x->replacement,x->length);i++;
  }
  struct vnode node={f->name};unsigned before=cs_ios27_text_fixup_applied;validated_page(&node,page,&testpage,1,0);CHECK(cs_ios27_text_fixup_applied-before==i-first&&!memcmp(expected,testpage.bytes,PAGE_SIZE));pages++;
 }
 CHECK(cs_ios27_text_fixup_applied==28208&&syncs==pages);printf("PASS profile1 actual28208descriptors on%upages, signature/taint gates, table/page atomicity,65536cap and indexed misses\n",pages);free(table);return 0;
 #endif
}
'''
manifest=json.loads((args.descriptors/'manifest.json').read_text())
header=header.replace('#define PAGE_SIZE 4096u',f'#define PAGE_SIZE {args.page_size}u').replace('#define PAGE_MASK 4095u',f'#define PAGE_MASK {args.page_size-1}u')
tests=tests.replace('28208',str(manifest['descriptor_count'])).replace('cs_ios27_text_fixup_applied==1024','cs_ios27_text_fixup_applied==PAGE_SIZE/4')
tests=tests.replace('child,ffe,00010203,04050607',f'child,{args.page_size-2:x},00010203,04050607')
source=header+production+wrapper+tests;(args.output/'test.c').write_text(source)
flat=args.output/'originals';flat.mkdir()
for file in manifest['files']:
    original=Path(file['original']['path']);assert hashlib.sha256(original.read_bytes()).hexdigest()==file['original']['sha256'];shutil.copy2(original,flat/file['basename'])
results=[]
for profile in (0,1):
    exe=args.output/f'profile{profile}';command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-format','-Wno-unused-function','-fsanitize=address,undefined','-fno-omit-frame-pointer',f'-DXNU_IOS27_TEXT_FIXUPS={profile}',str(args.output/'test.c'),'-o',str(exe)]
    built=subprocess.run(command,capture_output=True,text=True);(args.output/f'build{profile}.log').write_text(built.stdout+built.stderr);built.check_returncode()
    result=subprocess.run([str(exe),str(args.descriptors/'text-fixups-ios27.bin'),str(flat)],capture_output=True,text=True);(args.output/f'run{profile}.log').write_text(result.stdout+result.stderr);result.check_returncode();assert f'PASS profile{profile}' in result.stdout
    results.append({'profile':profile,'compiler_command':command,'passed':True,'log_sha256':hashlib.sha256((args.output/f'run{profile}.log').read_bytes()).hexdigest()})
report={'schema':'zeta-ios27-production-text-fixups-host-v1','results':results,'patch_sha256':hashlib.sha256(patch.read_bytes()).hexdigest(),'production_c_sha256':hashlib.sha256(production.encode()).hexdigest(),'real_vm_hook_extracted':True,'real_private_loader_hook_extracted':True,'page_size':args.page_size,'max_records':65536,'max_files':256,'actual_descriptor_count':manifest['descriptor_count'],'original_files_checked':len(manifest['files']),'asan_ubsan':True,'kernel_compilation':False,'phone_commands':False,'limits':['Exact production validator and real post-validation conditional over explicit host vnode/ADT/page/cache peers','Native VM lock/lifecycle and actual kernel object compilation remain separate gates']}
(args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
