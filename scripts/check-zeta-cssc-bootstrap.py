#!/usr/bin/env python3
"""Compile the actual patched SLEH function for bootstrap/final modes and check callback references."""
import argparse
from pathlib import Path
import subprocess
import shutil
import json
import hashlib

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--xnu-source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
source = out / 'source/osfmk/arm64/sleh.c'
source.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(a.xnu_source / 'osfmk/arm64/sleh.c', source)
patch = ROOT / 'patches/xnu-12377/native-zeta-user-cssc.patch'
subprocess.run(['patch', '--batch', '-p1', '-d', str(out / 'source'), '-i', str(patch)], check=True)
text = source.read_text()
start = text.index('#if defined(XNU_ZETA_USER_CSSC)')
end = text.index('\n#if __has_feature(ptrauth_calls)', start)
body = text[start:end]
prefix = r'''
#include <stdint.h>
#include <stddef.h>
typedef struct { uint64_t pc; uint32_t cpsr; } arm_saved_state_t;
typedef int exception_type_t, mach_msg_type_number_t, boolean_t;
typedef int64_t mach_exception_data_type_t;
enum { EXC_BAD_INSTRUCTION=1,EXC_ARM_UNDEFINED=2,EXC_BREAKPOINT=3,EXC_ARM_BREAKPOINT=4,FALSE=0 };
static inline uint64_t get_saved_state_pc(arm_saved_state_t *s) { return s->pc; }
static inline uint32_t get_saved_state_cpsr(arm_saved_state_t *s) { return s->cpsr; }
#define PSR64_IS_USER64(x) (((x)&31)==0)
#define PSR64_IS_KERNEL(x) (((x)&15)!=0)
#define IS_ARM_GDB_TRAP(x) ((x)==0xe7ffdefeU)
extern int test_copyin(uint64_t,char*,size_t);
#define COPYIN(a,b,c) test_copyin(a,b,c)
extern boolean_t ml_set_interrupts_enabled(boolean_t);
struct mock_thread { struct {arm_saved_state_t *kpcb;} machine; };
extern struct mock_thread *current_thread(void);
extern void DebuggerCall(exception_type_t,arm_saved_state_t*);
extern void panic(const char*,...);
extern void exception_triage(exception_type_t,mach_exception_data_type_t*,mach_msg_type_number_t);
'''
(out / 'sleh-function.c').write_text(prefix + body + '\nvoid test_entry(arm_saved_state_t *s) { handle_uncategorized(s); }\n')
results = []
for mode in (0, 1):
    obj = out / f'sleh-mode{mode}.o'
    subprocess.run(['clang', '-target', 'arm64-apple-ios26.0', '-march=armv8-a',
                    '-ffreestanding', '-O0', '-Wall', '-Wextra', '-Werror',
                    '-DCONFIG_DTRACE=0', f'-DXNU_ZETA_USER_CSSC={mode}',
                    '-c', str(out / 'sleh-function.c'), '-o', str(obj)], check=True)
    symbols = subprocess.check_output(['llvm-nm', '-u', str(obj)], text=True)
    present = '_zeta_user_instruction_compat' in symbols
    assert present == bool(mode), (mode, symbols)
    results.append({'mode': mode, 'callback_reference_present': present,
                    'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest()})
script = (ROOT / 'scripts/build-xnu-12377.sh').read_text()
first_pass = script[script.index('  build_kernel CFLAGS_EXTRA='):script.index('  ARCHIVE_FLAGS=', script.index('  build_kernel CFLAGS_EXTRA='))]
assert '-UXNU_ZETA_USER_CSSC' in first_pass
assert 'rebuild_on_change zeta-user-cssc-mode' in script
(out / 'result.json').write_text(json.dumps({'passed': True, 'modes': results,
    'scope': 'actual patched function with ABI stubs; complete native kernel link still required',
    'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest()}, indent=2)+'\n')
print('PASS: bootstrap has no compatibility reference; enabled final object requires the adapter')
