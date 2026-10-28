#!/usr/bin/env python3
"""Check the actual public Lockdown Mode query against its observed 8-byte ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
patch = Path(__file__).resolve().parents[1] / 'patches/xnu-12377/native-ios27-lockdown-public.patch'
with tempfile.TemporaryDirectory() as tmp:
    tree = Path(tmp)
    name = 'bsd/kern/lockdown_mode.c'
    target = tree / name
    target.parent.mkdir(parents=True)
    target.write_bytes(subprocess.check_output(['git', '-C', str(a.source), 'show', 'HEAD:' + name]))
    subprocess.run(['git', 'apply', '--unsafe-paths', '--directory=' + str(tree).lstrip('/'), str(patch)], cwd='/', check=True)
    text = target.read_text()
    body = text[text.index('static int\nsysctl_lockdown_mode_state_public'):text.index('\nSYSCTL_PROC(')]
    declaration = text[text.index('SYSCTL_PROC('):text.index('\n\n__startup_func')]
    assert 'CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_KERN' in declaration
    assert 'CTLFLAG_WR' not in declaration and 'lockdown_mode_state_public' in declaration
    assert 'SYSCTL_INT(_security_mac, OID_AUTO, lockdown_mode_state,' in text

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
struct sysctl_req { uint64_t value; size_t size; int error; };
static int state, calls;
static int get_lockdown_mode_state(void) { calls++; return state; }
#define SYSCTL_HANDLER_ARGS (struct sysctl_req *req)
static int host_out(struct sysctl_req *req, const void *p, size_t n) {
    req->size = n;
    if (req->error) return req->error;
    assert(n == sizeof(req->value)); memcpy(&req->value, p, n); return 0;
}
#define SYSCTL_OUT(req, p, n) host_out(req, p, n)
'''
tests = r'''
int main(void) {
    struct sysctl_req req = {0};
    state = 0; assert(!sysctl_lockdown_mode_state_public(&req));
    assert(req.size == 8 && req.value == 0 && state == 0);
    state = 1; assert(!sysctl_lockdown_mode_state_public(&req));
    assert(req.size == 8 && req.value == 1 && state == 1);
    state = 7; assert(!sysctl_lockdown_mode_state_public(&req));
    assert(req.value == 7 && state == 7); /* No forced zero or boolean policy. */
    req.error = 12; assert(sysctl_lockdown_mode_state_public(&req) == 12);
    assert(state == 7 && calls == 4); return 0;
}
'''
(a.output / 'production-handler.c').write_text(body + '\n')
(a.output / 'test.c').write_text(prefix + body + tests)
exe = a.output / 'check'
subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', str(a.output / 'test.c'), '-o', str(exe)], check=True)
subprocess.run([str(exe)], check=True)
result = dict(result='pass', handler_sha256=hashlib.sha256(body.encode()).hexdigest(), patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(), output_width=8, actual_state_forwarded=True, read_only_declaration=True, ordinary_private_query_preserved=True, native_execution=False)
(a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
