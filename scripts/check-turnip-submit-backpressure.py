#!/usr/bin/env python3
"""Exercise the exact recorded submit function with deterministic transport/time peers."""
from pathlib import Path
import argparse,re,subprocess,shutil
p=argparse.ArgumentParser();p.add_argument('--adreno',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
patch=(root/'patches/mesa/turnip-darwin-kmd.patch').read_text();marker='diff --git a/src/freedreno/vulkan/tu_knl_darwin.cc';block=patch[patch.index(marker):];block=block[:block.index('\ndiff --git ',1)];original=''.join(x[1:]+'\n' for x in block.splitlines() if x.startswith('+') and not x.startswith('+++'))
source=out/'source';path=source/'src/freedreno/vulkan/tu_knl_darwin.cc';path.parent.mkdir(parents=True,exist_ok=True);path.write_text(original)
subprocess.run(['git','init','-q',str(source)],check=True)
subprocess.run(['git','apply',str(root/'patches/mesa/turnip-submit-backpressure.patch')],cwd=source,check=True)
assert 'for (;;)' in path.read_text() and 'attempt < 64' not in path.read_text(), 'Patch was not applied to the isolated test source'
def function(text):
 start=text.index('static VkResult\ndarwin_submit_chunk(');return text[start:text.index('\n}\n',start)+3]
prefix=r'''
#include <stdint.h>
#include <stddef.h>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include "NativeAdrenoABI.h"
using VkResult=int;using kern_return_t=int;
constexpr int VK_SUCCESS=0,VK_TIMEOUT=2,VK_ERROR_DEVICE_LOST=-4,KERN_SUCCESS=0,kIOReturnBusy=-9;
struct tu_device {int vk;};struct tu_queue {tu_device *device;};
static struct {pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;unsigned inflight_count;uint32_t inflight[8];} dw;
static uint64_t clock_ns,seen_deadline;static int busy,forced_error,wait_result;static unsigned calls,sleeps,waits;
static uint64_t os_time_get_nano(){return clock_ns;}
static void test_sleep(unsigned us){if(us!=100)std::abort();++sleeps;clock_ns+=uint64_t(us)*1000;}
#define usleep test_sleep
static VkResult vk_device_set_lost(int *,const char *,...){return VK_ERROR_DEVICE_LOST;}
static VkResult dw_wait_fence_locked_free(tu_device *,uint32_t fence,uint64_t deadline){
 if(fence!=11)std::abort();++waits;seen_deadline=deadline;if(wait_result==VK_TIMEOUT)clock_ns=deadline;return wait_result;
}
static kern_return_t dw_call(unsigned method,const void *in,size_t in_bytes,void *out,size_t out_bytes){
 const auto *r=static_cast<const NativeAdrenoAbiSubmit *>(in);
 if(method!=NativeAdrenoMethodSubmit || in_bytes!=sizeof(*r) || out_bytes!=sizeof(NativeAdrenoAbiSubmitReply) || r->buffer_count!=1 || r->queue!=0 || r->buffers[0].handle!=5)std::abort();
 ++calls;if(forced_error)return forced_error;if(busy){if(busy>0)--busy;return kIOReturnBusy;}static_cast<NativeAdrenoAbiSubmitReply *>(out)->fence=77;return KERN_SUCCESS;
}
'''
suffix=r'''
#define REQUIRE(x,message) do {if(!(x)){std::fprintf(stderr,"FAIL: %s\n",message);return 1;}}while(0)
static void reset(bool local){clock_ns=9000000000ull;seen_deadline=0;busy=forced_error=wait_result=0;calls=sleeps=waits=0;dw.inflight_count=local?1:0;dw.inflight[0]=11;}
int main(){
 tu_device device{};tu_queue queue{&device};NativeAdrenoAbiSubmitBuffer entry{5,4096,4};uint32_t fence=0;
 // Shared slots stay occupied although this process's old fence is complete.
 reset(true);busy=200;auto result=darwin_submit_chunk(&queue,&entry,1,&fence);
 REQUIRE(result==VK_SUCCESS && fence==77 && calls==201,"pressure survives more than 64 busy replies");
 REQUIRE(sleeps==200 && waits==200 && clock_ns==9020000000ull && seen_deadline==14000000000ull,"completed old fence still yields against one fixed deadline");
 reset(false);busy=200;result=darwin_submit_chunk(&queue,&entry,1,&fence);
 REQUIRE(result==VK_SUCCESS && calls==201 && waits==0 && sleeps==200,"other client pressure with no local fence yields and recovers");
 reset(true);busy=-1;result=darwin_submit_chunk(&queue,&entry,1,&fence);
 REQUIRE(result==VK_ERROR_DEVICE_LOST && clock_ns==14000000000ull && calls==50001,"permanent busy is bounded to five seconds");
 reset(true);busy=1;wait_result=VK_TIMEOUT;result=darwin_submit_chunk(&queue,&entry,1,&fence);
 REQUIRE(result==VK_ERROR_DEVICE_LOST && waits==1 && calls==1 && sleeps==0,"real fence timeout remains fatal");
 reset(true);forced_error=-14;result=darwin_submit_chunk(&queue,&entry,1,&fence);
 REQUIRE(result==VK_ERROR_DEVICE_LOST && calls==1 && !sleeps && !waits,"non-busy transport failure is not retried");
 reset(false);result=darwin_submit_chunk(&queue,&entry,1,&fence);
 REQUIRE(result==VK_SUCCESS && fence==77 && calls==1 && !sleeps,"uncontended submit has no added delay");
 std::puts("PASS: actual submit function handles shared-slot pressure beyond 64 attempts, yields with a completed local fence, keeps a fixed deadline and preserves genuine failures; no GPU execution");
}
'''
for label,text in [('fixed',path.read_text()),('old',original)]:
 cpp=out/(label+'.cpp');cpp.write_text(prefix+function(text)+suffix);exe=out/label
 subprocess.run(['clang++','-std=c++17','-O1','-Wall','-Wextra','-Werror','-Wno-missing-field-initializers','-fsanitize=address,undefined','-pthread','-I',str(a.adreno.resolve() if a.adreno else root/'drivers/NativeAdreno'),str(cpp),'-o',str(exe)],check=True)
 r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=20);(out/(label+'.log')).write_text(r.stdout+r.stderr)
 if label=='fixed':
  if r.returncode:raise SystemExit(r.stdout+r.stderr)
  print(r.stdout,end='')
 elif r.returncode!=1 or 'pressure survives more than 64 busy replies' not in r.stderr:raise SystemExit('Old-code control failed unexpectedly: '+r.stdout+r.stderr)
 else:print('PASS: old 64-attempt policy fails the exact transient-pressure assertion')
