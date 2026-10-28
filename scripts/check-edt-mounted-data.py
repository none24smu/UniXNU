#!/usr/bin/env python3
"""Exercise the production EDT mounted-Data selector over explicit host VFS peers."""
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
patch = Path(__file__).resolve().parents[1] / 'patches/xnu-12377/native-edt-fstab.patch'
with tempfile.TemporaryDirectory() as tmp:
    tree = Path(tmp)
    for name in ('bsd/kern/kern_newsysctl.c', 'bsd/vfs/vfs_subr.c'):
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(['git', '-C', str(a.source), 'show', 'HEAD:' + name]))
    subprocess.run(['git', 'apply', '--unsafe-paths', '--directory=' + str(tree).lstrip('/'), str(patch)], cwd='/', check=True)
    text = (tree / 'bsd/vfs/vfs_subr.c').read_text()
    layout = text[text.index('struct edt_fstab {'):text.index('/* dyld reads ten entries at most.')]
    start = text.index('static bool\nedt_fstab_mounted_data(')
    body = text[start:text.index('\nstatic int\nsysctl_edt_fstab', start)]

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define NULLVP NULL
#define VROOT 1
struct vfsstatfs { char f_fstypename[16], f_mntonname[128], f_mntfromname[128]; };
struct mount { struct vfsstatfs stat; };
struct vnode { struct mount *mp; int v_flag; };
typedef struct vnode *vnode_t;
static struct mount root_mount, data_mount;
static struct vnode root_node, data_node;
static vnode_t rootvnode, lookup_node;
static unsigned gets, puts_count;
static int lookup_error;
static void *vfs_context_kernel(void) { return (void *)1; }
static int vnode_lookup(const char *p, int flags, vnode_t *vp, void *ctx) {
    assert(!strcmp(p, "/private/var") && !flags && ctx == (void *)1);
    if (lookup_error) return lookup_error;
    *vp = lookup_node; gets++; return 0;
}
static struct mount *vnode_mount(vnode_t vp) { return vp->mp; }
static struct vfsstatfs *vfs_statfs(struct mount *mp) { return &mp->stat; }
static void vnode_put(vnode_t vp) { assert(vp == lookup_node); puts_count++; }
static size_t host_strlcpy(char *dst, const char *src, size_t n) {
    size_t size = strlen(src); assert(n); size_t copied = size < n-1 ? size : n-1;
    memcpy(dst, src, copied); dst[copied] = 0; return size;
}
#define strlcpy host_strlcpy
'''
tests = r'''
static struct edt_fstab entry(void) {
    struct edt_fstab fs = {0}; strcpy(fs.fs_file, "/private/var"); fs.fs_role = 64; return fs;
}
static void reject(void) {
    struct edt_fstab fs = entry(); assert(!edt_fstab_mounted_data(&fs));
    assert(!fs.fs_spec[0] && !fs.fs_vfstype[0] && gets == puts_count);
}
int main(void) {
    root_node.mp = &root_mount; rootvnode = &root_node;
    data_node.mp = &data_mount; data_node.v_flag = VROOT; lookup_node = &data_node;
    strcpy(data_mount.stat.f_fstypename, "apfs");
    strcpy(data_mount.stat.f_mntonname, "/private/var");
    strcpy(data_mount.stat.f_mntfromname, "/dev/disk1s1");
    struct edt_fstab fs = entry(); assert(edt_fstab_mounted_data(&fs));
    assert(!strcmp(fs.fs_spec, "/dev/disk1s1") && !strcmp(fs.fs_vfstype, "apfs"));
    assert(gets == puts_count);
    rootvnode = NULLVP; reject(); rootvnode = &root_node;
    lookup_error = 2; reject(); lookup_error = 0;
    data_node.mp = &root_mount; reject(); data_node.mp = &data_mount;
    data_node.mp = NULL; reject(); data_node.mp = &data_mount;
    data_node.v_flag = 0; reject(); data_node.v_flag = VROOT;
    strcpy(data_mount.stat.f_fstypename, "tmpfs"); reject();
    strcpy(data_mount.stat.f_fstypename, "apfs");
    strcpy(data_mount.stat.f_mntonname, "/private/var/alias"); reject();
    strcpy(data_mount.stat.f_mntonname, "/private/var");
    strcpy(data_mount.stat.f_mntfromname, "ramdisk"); reject();
    strcpy(data_mount.stat.f_mntfromname, "/dev/"); reject();
    strcpy(data_mount.stat.f_mntfromname, "/dev/123456789012345678901234567890123456789"); reject();
    strcpy(data_mount.stat.f_mntfromname, "/dev/disk1s1");
    fs = entry(); strcpy(fs.fs_file, "/private/var/alias");
    unsigned before = gets; assert(!edt_fstab_mounted_data(&fs) && gets == before);
    fs = entry(); assert(edt_fstab_mounted_data(&fs) && gets == puts_count);
    puts("PASS mounted persistent APFS Data, reject root directory/alias/tmpfs/missing/truncated device; balanced vnode iocounts");
}
'''
source = prefix + layout + body + tests
(a.output / 'test.c').write_text(source)
command = ['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', str(a.output / 'test.c'), '-o', str(a.output / 'test')]
subprocess.run(command, check=True)
result = subprocess.run([str(a.output / 'test')], capture_output=True, text=True, check=True)
(a.output / 'run.log').write_text(result.stdout + result.stderr)
report = dict(result='pass', patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),
              production_helper_sha256=hashlib.sha256(body.encode()).hexdigest(),
              patch_applies_to_original_source=True, asan_ubsan=True,
              actual_kernel_sdk_compilation=False, native_mount_execution=False,
              scope='Exact production mounted-Data selector over explicit host VFS/vnode peers')
(a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(result.stdout, end='')
