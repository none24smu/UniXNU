"""Exercise actual patched-header preprocessing and pinned public storage copies."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('profile', ROOT / 'scripts/kdk_iokit_abi.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
HEADER = Path(os.environ.get('XNU_ABI_HEADER_SOURCE', ROOT / 'refer/xnu/libkern/libkern/c++/OSMetaClass.h'))
STORAGE = Path(os.environ.get('XNU_ABI_STORAGE_SOURCE', ROOT / 'refer/IOStorageFamily'))


class PublicProfileTests(unittest.TestCase):
    @unittest.skipUnless(STORAGE.is_dir(), 'supply pinned public IOStorageFamily source')
    def test_public_bodies_preserved_and_ios_profile_unchanged(self):
        for name, count in P.GUARDS.items():
            with self.subTest(name=name):
                original = (STORAGE / name).read_text()
                self.assertEqual(P.storage_copy(name, original, False), original)
                adapted = P.storage_copy(name, original, True)
                self.assertEqual(adapted.count('#if TARGET_OS_OSX || XNU_KDK_IOKIT_ABI\n'), count)
                self.assertEqual(adapted.replace('#if TARGET_OS_OSX || XNU_KDK_IOKIT_ABI\n',
                                                '#if TARGET_OS_OSX\n'), original)
                self.assertNotIn('#define TARGET_OS_OSX', adapted)

    def test_changed_reference_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'guards changed'):
            P.storage_copy('IOStorage.h', '#if TARGET_OS_OSX\n#endif\n', True)

    def test_profile_does_not_retarget_other_storage_code(self):
        text = '#if TARGET_OS_OSX\nimplementation\n#endif\n'
        self.assertEqual(P.storage_copy('IOMediaBSDClient.cpp', text, True), text)


@unittest.skipUnless(HEADER.is_file() and shutil.which('clang'), 'supply pinned XNU header and clang')
class ActualHeaderTests(unittest.TestCase):
    def test_all_public_and_private_profiles_keep_container_alignment(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            header = root / 'libkern/libkern/c++/OSMetaClass.h'
            header.parent.mkdir(parents=True)
            shutil.copyfile(HEADER, header)
            patch = ROOT / 'patches/xnu-12377/native-kdk-iokit-abi.patch'
            command = ['git', 'apply', '--unsafe-paths', '--directory', str(root)]
            subprocess.run(command + [str(patch)], cwd=root, check=True, capture_output=True)
            subprocess.run(command + ['--reverse', '--check', str(patch)], cwd=root,
                           check=True, capture_output=True)
            text = header.read_text()
            start = text.index('// An explicit whole-kernel IOKit ABI experiment.')
            end = text.index('#if defined(__LP64__)', start)
            block = text[start:end]
            (root / 'TargetConditionals.h').write_text(
                '#define TARGET_OS_IPHONE 1\n#define TARGET_OS_SIMULATOR 0\n#define TARGET_OS_OSX 0\n')
            for compatibility in (0, 1):
                for private in (False, True):
                    with self.subTest(compatibility=compatibility, private=private):
                        source = block + f'''
#if APPLE_KEXT_VTABLE_PADDING != {compatibility}
#error wrong reserved slot profile
#endif
#if APPLE_KEXT_ALIGN_CONTAINERS != 1
#error container alignment changed
#endif
#if XNU_TARGET_OS_OSX != 0 || XNU_TARGET_OS_IOS != 1
#error changed kernel target
#endif
'''
                        args = ['clang', '-E', '-x', 'c++', '-I', str(root), '-D__arm64__=1',
                                '-DXNU_TARGET_OS_IOS=1', '-DXNU_TARGET_OS_OSX=0',
                                f'-DXNU_KDK_IOKIT_ABI={compatibility}']
                        if private:
                            args += ['-DXNU_KERNEL_PRIVATE=1']
                        subprocess.run(args + ['-'], input=source, text=True, capture_output=True,
                                       check=True)
            result = subprocess.run(['clang', '-E', '-x', 'c++', '-DXNU_KDK_IOKIT_ABI=1', '-'],
                                    input=block, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires ARM64', result.stderr)


if __name__ == '__main__':
    unittest.main()
