#!/usr/bin/env python3
"""Run actual CPU dispatch/quiesce method bodies with privileged I/O stand-ins.
No real GIC/timer/power execution is established by this host check.
"""
from pathlib import Path
import subprocess,json,hashlib
root=Path(__file__).resolve().parents[1];out=root/'build/cpu-desktop/armcpu-diagnostics';out.mkdir(parents=True,exist_ok=True)
s=(root/'drivers/ArmCpu/ArmCpu.cpp').read_text()
def method(name):
 start=s.index('void ArmCpu::'+name+' (');brace=s.index('{',start);depth=1;i=brace+1
 while depth:
  if s[i]=='{':depth+=1
  if s[i]=='}':depth-=1
  i+=1
 return s[start:i]
body='\n'.join(method(n) for n in ['interrupt','enableCPUTimeBase','quiesceCPU','haltCPU'])
original=body
replacements={
 '__asm__ volatile ("mrs %0, icc_iar1_el1" : "=r" (id));':'id=ack();',
 '__asm__ volatile ("msr icc_eoir1_el1, %0; isb" :: "r" (id) : "memory");':'eoi(id);',
 '__asm__ volatile ("msr cntv_ctl_el0, %0; isb" :: "r" (value) : "memory");':'timerWrite(value);',
 '__asm__ volatile ("msr icc_igrpen1_el1, %0; dsb sy; isb" :: "r" (value) : "memory");':'gicWrite(value);',
 '__asm__ volatile ("msr daifset, #15" ::: "memory");':'mask();',
 'for (;;) { __asm__ volatile ("wfi"); }':'park();',
}
for before,after in replacements.items():
 assert before in body,before
 body=body.replace(before,after)
assert '__asm__' not in body
prefix=r'''
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <vector>
#include <stdio.h>
struct Failure{const char *format;};
[[noreturn]] static void panic(const char *f,...){throw Failure{f};}
static std::vector<uint64_t> pending,events;static size_t cursor;
volatile uint32_t armcpu_irq_phase,armcpu_irq_id,armcpu_quiesce_calls,armcpu_halt_calls;
volatile uint64_t armcpu_timer_interrupts,armcpu_ipi_interrupts;
volatile uint32_t armcpu_core_timer[8],armcpu_core_sgi[8],armcpu_spi_unhandled_id;
volatile uint64_t armcpu_spi_unhandled;
static bool gSpiIpi=false;
static const uint32_t kIpiSpiBase=1008;
static uintptr_t gDist;
struct ArmCpuSpi {uint32_t id;void (*handler)(void *);void *context;volatile uint64_t count;};
static ArmCpuSpi gSpi[16];static volatile uint32_t gSpiUsed;
static std::vector<uint64_t> mmio;
static void write32(uintptr_t base,unsigned offset,uint32_t value){assert(base==gDist);mmio={offset,value};}
static void spiHandler(void *context){assert(context==&gDist);events.push_back(777);}
static bool failClock;
static uint64_t ack(){assert(cursor<pending.size());return pending[cursor++];}
static void eoi(uint64_t id){events.push_back(100+id);}
static void rtclock_intr(unsigned n){assert(n==0);events.push_back(1);if(failClock)panic("clock blocked");}
static void ipi(){events.push_back(2);}
static void timerWrite(uint64_t v){events.push_back(200+v);}
static void gicWrite(uint64_t v){events.push_back(300+v);}
static void mask(){events.push_back(400);}
static void park(){panic("park");}
static const int kIOCPUStateStopped=7;
class ArmCpu{public:bool diagnosePower=true;uint32_t logicalId=0;void (*ipi_handler)()=ipi;
void interrupt();void enableCPUTimeBase(bool);void quiesceCPU();void haltCPU();
void setCPUState(int s){events.push_back(500+s);}};
'''
main=r'''
int main(){
 ArmCpu cpu;
 pending={27,0,1023};cpu.interrupt();assert(events==std::vector<uint64_t>({1,127,2,100}));assert(armcpu_irq_phase==0);
 events.clear();cursor=0;pending.assign(128,27);pending.push_back(1023);cpu.interrupt();assert(events.size()==256&&armcpu_irq_phase==0);
 events.clear();cursor=0;pending.assign(130,27);bool failed=false;
 try{cpu.interrupt();}catch(Failure){failed=true;}assert(failed&&events.size()==256&&cursor==129);
 events.clear();cursor=0;pending={99};failed=false;try{cpu.interrupt();}catch(Failure){failed=true;}assert(failed&&events.empty());
 events.clear();cursor=0;pending={48,1023};gDist=1;gSpi[0]={48,spiHandler,&gDist,0};gSpiUsed=1;
 cpu.interrupt();assert(events==std::vector<uint64_t>({777,148})&&gSpi[0].count==1&&mmio.empty());
 events.clear();cursor=0;pending={99,1023};cpu.interrupt();
 assert(events==std::vector<uint64_t>({199})&&mmio==std::vector<uint64_t>({0x18c,8})&&armcpu_spi_unhandled==1&&armcpu_spi_unhandled_id==99);
 events.clear();cursor=0;pending={1008,1023};gSpiIpi=true;cpu.interrupt();
 assert(events==std::vector<uint64_t>({2,1108}));gSpiIpi=false;
 events.clear();cursor=0;pending={27};failClock=true;failed=false;try{cpu.interrupt();}catch(Failure){failed=true;}assert(failed&&events==std::vector<uint64_t>({1})&&armcpu_irq_phase==2);failClock=false;
 events.clear();failed=false;try{cpu.quiesceCPU();}catch(Failure){failed=true;}assert(failed&&events.empty());
 failed=false;try{cpu.haltCPU();}catch(Failure){failed=true;}assert(failed&&events.empty()&&armcpu_halt_calls==1);
 cpu.diagnosePower=false;cpu.quiesceCPU();assert(events==std::vector<uint64_t>({202,300}));
 puts("PASS: actual CPU method bodies, timer/IPI/EOI order, bounded flood, unexpected IRQ, callback failure, quiesce guards and legacy disable order; hardware I/O substituted");
}
'''
(out/'test.cpp').write_text(prefix+body+main)
subprocess.run(['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined',str(out/'test.cpp'),'-o',str(out/'test')],check=True,timeout=60)
r=subprocess.run([str(out/'test')],check=True,capture_output=True,text=True,timeout=30)
(out/'report.json').write_text(json.dumps({'method_bodies_sha256':hashlib.sha256(original.encode()).hexdigest(),'passed':True,'privileged_io_substituted':True,'hardware_observed':False},indent=2)+'\n');print(r.stdout,end='')
