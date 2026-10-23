"""Exercise actual root-binding code against adversarial registry graphs."""
import ctypes
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
STUBS = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#define major(d) ((unsigned)((d) >> 24))
#define minor(d) ((unsigned)((d) & 0xffffff))
#define NODEV ((dev_t)-1)
#define kIOBSDMajorKey "major"
#define kIOBSDMinorKey "minor"
#define OSDynamicCast(T,p) dynamic_cast<T *>(p)
#define OSSafeReleaseNULL(p) do {if(p){(p)->release();p=nullptr;}}while(0)
struct OSObject { virtual ~OSObject(){} virtual void release(){} };
static bool fail_allocate, fail_property, fail_iterator;
static unsigned backend_calls;
struct OSNumber: OSObject {unsigned value; explicit OSNumber(unsigned v):value(v){}
static OSNumber *withNumber(unsigned v,unsigned){return fail_allocate?nullptr:new OSNumber(v);} };
struct OSDictionary: OSObject {std::map<std::string,OSObject*> props;
static OSDictionary *withCapacity(unsigned){return fail_allocate?nullptr:new OSDictionary;}
bool setObject(const char *k,OSObject *v){if(fail_property)return false;props[k]=v;return true;} };
struct OSString: OSObject {std::string text; explicit OSString(const char *s):text(s){}
unsigned getLength()const{return text.size();}const char *getCStringNoCopy()const{return text.c_str();} };
struct OSIterator;
struct IOService: OSObject {IOService *parent=nullptr;OSObject *uuid=nullptr;int trust=-1;bool late_failure=false;
static OSDictionary *serviceMatching(const char *s){return !strcmp(s,"IOMedia")?OSDictionary::withCapacity(1):nullptr;}
static OSIterator *getMatchingServices(OSDictionary *);
IOService *getProvider(){return parent;}OSObject *getProperty(const char *k){return !strcmp(k,"UUID")?uuid:nullptr;} };
struct IOMedia: IOService {bool writable=false;bool isWritable(){return writable;} };
struct OSIterator: OSObject {std::vector<OSObject*> objects;size_t index=0;
OSObject *getNextObject(){return index<objects.size()?objects[index++]:nullptr;} };
static std::vector<OSObject*> registry;
OSIterator *IOService::getMatchingServices(OSDictionary *d){
if(fail_iterator)return nullptr;
auto *p=dynamic_cast<OSDictionary*>(d->props["IOPropertyMatch"]);
if(!p)return nullptr;
auto *a=dynamic_cast<OSNumber*>(p->props[kIOBSDMajorKey]);auto *b=dynamic_cast<OSNumber*>(p->props[kIOBSDMinorKey]);
if(!a||!b||a->value!=1||b->value!=7)return nullptr;
auto *i=new OSIterator;i->objects=registry;return i;}
volatile uint32_t native_ufs_integrity_failures=0;
static const char *valid_uuid="B6C635B2-67F6-4034-B5D5-539E4D03D1EC";
extern "C" int native_ufs_block_authenticates(IOService *p,const char *uuid,uint8_t *digest){
++backend_calls;if(p->trust<0)return -1;
if(p->late_failure)native_ufs_integrity_failures=1;
if(p->trust!=1||strcmp(uuid,valid_uuid))return 0;
memset(digest,0x5a,48);return 1;}
'''
WRAPPER = r'''
extern "C" int run_case(int scenario){
// Objects remain alive across the actual query. Host stubs intentionally
// replace framework allocation/reference accounting, not binding decisions.
fail_allocate=fail_property=fail_iterator=false;backend_calls=0;registry.clear();native_ufs_integrity_failures=0;
static OSString identity(valid_uuid),wrong("B6C635B2-67F6-4034-B5D5-539E4D03D1ED"),short_id("bad");
static OSNumber not_string(42);
IOMedia media,other;IOService backing,ordinary;media.uuid=&identity;media.parent=&backing;backing.trust=1;
registry.push_back(&media);dev_t mounted=0x1000007,selected=mounted;int readonly=1;
std::vector<std::unique_ptr<IOService>> chain;
switch(scenario){
case 1:selected++;break;case 2:readonly=0;break;case 3:registry.clear();break;
case 4:registry.push_back(&media);break;case 5:media.writable=true;break;
case 6:media.uuid=nullptr;break;case 7:media.uuid=&wrong;break;
case 8:media.parent=&ordinary;break;case 9:backing.trust=0;break;
case 10:native_ufs_integrity_failures=1;break;case 11:backing.late_failure=true;break;
case 12:case 21:{unsigned links=scenario==21?62:63;IOService *previous=&media;
for(unsigned i=0;i<links;i++){chain.emplace_back(new IOService);previous->parent=chain.back().get();previous=chain.back().get();}previous->parent=&backing;break;}
case 13:media.parent=&ordinary;ordinary.parent=&media;break;
case 14:fail_allocate=true;break;case 15:fail_property=true;break;case 16:fail_iterator=true;break;
case 17:mounted=selected=NODEV;break;case 18:media.uuid=&short_id;break;
case 19:media.uuid=nullptr;other.uuid=&identity;other.parent=&backing;registry.push_back(&other);break;
case 20:ordinary.uuid=&identity;ordinary.parent=&backing;registry[0]=&ordinary;break;
case 22:media.uuid=&not_string;break;
}
return native_ufs_owner_root_authorized(mounted,selected,readonly);}
extern "C" unsigned calls(){return backend_calls;}
extern "C" int evidence_clear(){for(unsigned i=0;i<48;i++)if(native_ufs_owner_root_manifest[i])return 0;
return !native_ufs_owner_root_accepted&&!native_ufs_owner_root_uuid[0];}
'''


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='ufs-owner-root-')
        directory = Path(cls.temporary.name)
        actual = (ROOT / 'scripts/ufs-owner-root.cpp').read_text()
        actual = re.sub(r'^#include[^\n]*\n', '', actual, flags=re.M)
        source = directory / 'binding.cpp'
        source.write_text(STUBS + actual + WRAPPER)
        library = directory / 'binding.so'
        result = subprocess.run(['c++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', str(source), '-o', str(library)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.run_case.argtypes = [ctypes.c_int]
        cls.lib.run_case.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_only_unique_readonly_uuid_bound_owner_backing_is_accepted(self):
        self.assertEqual(self.lib.run_case(0), 1)
        self.assertEqual(self.lib.run_case(21), 1)  # UFS ancestor exactly at depth64.

    def test_all_adversarial_registry_and_mount_cases_are_rejected(self):
        for case in list(range(1, 21)) + [22]:
            with self.subTest(case=case):
                self.assertEqual(self.lib.run_case(0), 1)
                self.assertEqual(self.lib.run_case(case), 0)
                self.assertEqual(self.lib.evidence_clear(), 1)

    def test_wrong_device_writable_mount_and_prior_integrity_failure_never_query_owner(self):
        for case in (1, 2, 10, 17):
            self.assertEqual(self.lib.run_case(case), 0)
            self.assertEqual(self.lib.calls(), 0)


XNU_SOURCE = Path(os.environ.get('OWNER_ROOT_XNU_SOURCE', ROOT / 'refer/xnu'))


@unittest.skipUnless((XNU_SOURCE / 'bsd/kern/bsd_init.c').is_file(), 'supply exact XNU source')
class ActualBSDCallsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='ufs-owner-callsite-')
        out = Path(cls.temporary.name)
        target = out / 'bsd/kern/bsd_init.c'
        target.parent.mkdir(parents=True)
        shutil.copyfile(XNU_SOURCE / 'bsd/kern/bsd_init.c', target)
        subprocess.run(['git', 'apply', '--unsafe-paths', '--directory', str(out), str(ROOT / 'patches/xnu-12377/native-ufs-owner-root.patch')], cwd=out, check=True, capture_output=True)
        text = target.read_text()
        start = text.index('int autherr = VNOP_IOCTL(rootvnode, FSIOC_KERNEL_ROOTAUTH')
        body = text[start:text.index('\n\t\t}\n\t}\n', start)]
        stubs = r'''
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#define DEVELOPMENT 1
#define DEBUG 0
#define NODEV ((dev_t)-1)
#define MNT_RDONLY 1
#define FSIOC_KERNEL_ROOTAUTH 0
#define major(d) ((unsigned)((d)>>24))
#define minor(d) ((unsigned)((d)&0xffffff))
#define VNOP_IOCTL(...) apple_result
typedef void *mount_t;typedef void *vnode_t;
vnode_t rootvnode=(void*)1;static dev_t rootdev,mounted;
static int apple_result,owner_result,ro,has_device,panicked,queries,puts;
mount_t vnode_mount(vnode_t v){return v;}
vnode_t vfs_devvp(mount_t m){return has_device?m:NULL;}
dev_t vnode_specrdev(vnode_t v){(void)v;return mounted;}
unsigned vfs_flags(mount_t m){(void)m;return ro?MNT_RDONLY:0;}
void vnode_put(vnode_t v){(void)v;puts++;}
void panic(const char *s){(void)s;panicked=1;}
int test_printf(const char *s,...){(void)s;return 0;}
#define printf test_printf
int native_ufs_owner_root_authorized(dev_t m,dev_t s,int readonly){queries++;return owner_result&&readonly&&m==s;}
int auth_run(int apple,int owner,int readonly,int device,int same){
apple_result=apple;owner_result=owner;ro=readonly;has_device=device;
mounted=0x1000007;rootdev=mounted+(same?0:1);panicked=queries=puts=0;
'''
        cls.libraries = []
        for enabled in (0, 1):
            source = out / ('callsite%d.c' % enabled)
            source.write_text(stubs + body + '\nreturn !panicked;}\nint query_count(void){return queries;}\nint put_count(void){return puts;}\n')
            library = out / ('callsite%d.so' % enabled)
            result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', '-DXNU_NATIVE_UFS_OWNER_ROOT=%d' % enabled, str(source), '-o', str(library)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            native = ctypes.CDLL(str(library))
            native.auth_run.argtypes = [ctypes.c_int] * 5
            cls.libraries.append(native)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_disabled_profile_preserves_original_apple_check(self):
        native = self.libraries[0]
        self.assertEqual(native.auth_run(0, 0, 1, 1, 1), 1)
        self.assertEqual(native.auth_run(81, 1, 1, 1, 1), 0)
        self.assertEqual(native.query_count(), 0)

    def test_enabled_profile_requires_real_binding_and_balances_vnode_reference(self):
        native = self.libraries[1]
        self.assertEqual(native.auth_run(0, 0, 1, 1, 1), 1)
        self.assertEqual(native.query_count(), 0)
        self.assertEqual(native.auth_run(81, 1, 1, 1, 1), 1)
        self.assertEqual(native.query_count(), 1)
        self.assertEqual(native.put_count(), 1)
        for owner, readonly, device, same in ((0, 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0)):
            self.assertEqual(native.auth_run(81, owner, readonly, device, same), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
