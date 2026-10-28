#!/usr/bin/env python3
"""Test the production restorer against a native cached executable and its original signature.

Only private host buffers are changed. The captured executable, original file,
signature, kernel and device remain untouched.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
for name in ('fixture', 'descriptors', 'original', 'cached', 'board-scripts', 'output'):
    p.add_argument('--' + name, required=True, type=Path)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
patch = Path(__file__).resolve().parents[1] / 'patches/xnu-12377/native-text-fixup.patch'
fixture = json.loads((a.fixture / 'result.json').read_text())
assert fixture['patch_sha256'] == hashlib.sha256(patch.read_bytes()).hexdigest()
assert fixture['page_size'] == 16384 and all(x['passed'] for x in fixture['results'])
source = '#define main existing_validator_main\n#include ' + json.dumps(str((a.fixture / 'test.c').resolve())) + '\n#undef main\n'
source += r'''
static void output(const char *path, const void *data, size_t size) {
 FILE *f=fopen(path,"wb");CHECK(f&&fwrite(data,1,size,f)==size);fclose(f);
}
int main(int argc,char **argv) {
 CHECK(argc==6);size_t ts,os,cs;
 char *table=read_file(argv[1],&ts),*original=read_file(argv[2],&os),*cached=read_file(argv[3],&cs);
 CHECK(os==cs&&os>=PAGE_SIZE);reset(NULL,0,table,(unsigned)ts);
 struct vnode mount={"mount"},wrong={"another"};
 char *copy=malloc(os),*saved=malloc(os);CHECK(copy&&saved);memcpy(saved,cached,os);
 memcpy(copy,cached,os);uint32_t initial=cs_text_fixup_restore_range(&mount,0,copy,PAGE_SIZE);
 CHECK(initial>0&&!memcmp(copy,original,PAGE_SIZE)&&!memcmp(cached,saved,os));
 CHECK(!cs_text_fixup_restore_range(&mount,0,copy,PAGE_SIZE));
 for(unsigned iteration=0;iteration<3;iteration++) {
  memcpy(copy,cached,os);CHECK(cs_text_fixup_restore_range(&mount,0,copy,os)>0);
  CHECK(!memcmp(copy,original,os)&&!memcmp(cached,saved,os));
 }
 output(argv[4],copy,os);
 memcpy(copy,cached,os);CHECK(!cs_text_fixup_restore_range(&wrong,0,copy,os)&&!memcmp(copy,cached,os));
 CHECK(!cs_text_fixup_restore_range(NULL,0,copy,os));
 CHECK(!cs_text_fixup_restore_range(&mount,0,NULL,os));
 CHECK(!cs_text_fixup_restore_range(&mount,UINT64_MAX,copy,os));
 CHECK(!cs_text_fixup_restore_range(&mount,0,copy,0));
 uint32_t at=0;while(at<cs_ios27_text_fixup_parsed&&strcmp(cs_ios27_text_fixups[at].name,"mount"))at++;
 CHECK(at<cs_ios27_text_fixup_parsed);struct cs_text_fixup *entry=&cs_ios27_text_fixups[at];
 CHECK(entry->length>1&&entry->offset+entry->length<os);
 memcpy(copy,cached,os);copy[entry->offset]^=0x80;memcpy(saved,copy,os);
 CHECK(!cs_text_fixup_restore_range(&mount,0,copy,os)&&!memcmp(copy,saved,os));
 char fragment[16];memcpy(fragment,entry->replacement+1,entry->length-1);char prior[16];memcpy(prior,fragment,entry->length-1);
 CHECK(!cs_text_fixup_restore_range(&mount,entry->offset+1,fragment,entry->length-1)&&!memcmp(fragment,prior,entry->length-1));
 /* A non-target mutation survives reconstruction and must fail the real signature. */
 memcpy(copy,cached,os);copy[0x40]^=1;CHECK(cs_text_fixup_restore_range(&mount,0,copy,os)>0);
 CHECK(copy[0x40]==(char)(original[0x40]^1));output(argv[5],copy,os);
 /* The separate ordinary legacy mechanism gets the same private-copy behavior. */
 const char *legacy="legacy,0,01020304,05060708";struct vnode lv={"legacy"};
 reset(legacy,(unsigned)strlen(legacy)+1,NULL,0);uint8_t value[4]={5,6,7,8};
 CHECK(cs_text_fixup_restore_range(&lv,0,value,4)==1&&!memcmp(value,"\1\2\3\4",4));
 puts("PASS captured repeat-exec private-copy restoration; original signature inputs, unchanged cached executable, unknown/partial/non-target rejection and legacy compatibility");
 free(table);free(original);free(cached);free(copy);free(saved);return 0;
}
'''
(a.output / 'test.c').write_text(source)
command = ['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-format', '-Wno-unused-function', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-DXNU_IOS27_TEXT_FIXUPS=1', str(a.output / 'test.c'), '-o', str(a.output / 'test')]
subprocess.run(command, check=True)
canonical = a.output / 'canonical.bin'
mutated = a.output / 'non-target-mutated.bin'
run = subprocess.run([str(a.output / 'test'), str(a.descriptors / 'text-fixups-ios27.bin'), str(a.original), str(a.cached), str(canonical), str(mutated)], capture_output=True, text=True)
(a.output / 'run.log').write_text(run.stdout + run.stderr)
run.check_returncode()
sys.path.insert(0, str(a.board_scripts.resolve()))
spec = importlib.util.spec_from_file_location('original_signature_reader', a.board_scripts / 'rewrite-zeta-userland.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
original = a.original.read_bytes()
directory = m.code_directory(original, m.parse(original, allow_x1_analysis=True))
m.verify_code_pages(original, directory)
m.verify_code_pages(canonical.read_bytes(), directory)
rejections = {}
for name, data in [('captured_cached_file', a.cached.read_bytes()), ('non_target_mutation', mutated.read_bytes())]:
    try:
        m.verify_code_pages(data, directory)
    except ValueError as error:
        rejections[name] = str(error)
    else:
        raise AssertionError('Original signature unexpectedly accepted ' + name)
assert canonical.read_bytes() == original
report = dict(result='pass', production_patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),
              original_sha256=hashlib.sha256(original).hexdigest(), cached_sha256=hashlib.sha256(a.cached.read_bytes()).hexdigest(),
              original_signature_pages_verified=directory['code_slots'], original_signature_unchanged=True,
              canonical_private_copy_exactly_equals_original=True, cached_source_unchanged=True,
              repeat_loads=3, signature_rejections=rejections, asan_ubsan=True,
              actual_kernel_sdk_compilation=False, native_fix_execution=False,
              scope='Extracted production restorer over actual native cached-file bytes and original CodeDirectory; kernel loader hook and native repeat exec are separate gates')
(a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
