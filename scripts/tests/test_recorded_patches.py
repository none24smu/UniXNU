import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('recorded_patches', Path(__file__).parents[1] / 'recorded_patches.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecordedPatchesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'source'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / 'value').write_text('base\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        self.patches = []
        for i, value in enumerate(['first\n', 'second\n']):
            (self.repo / 'value').write_text(value)
            if i == 1:
                (self.repo / 'added').write_text('recorded new file\n')
            self.git('add', '.')
            patch = self.root / f'{i}.patch'
            patch.write_bytes(self.git('diff', '--cached', 'HEAD'))
            self.patches.append(patch)
            self.git('commit', '-qm', value.strip())
        self.git('reset', '--hard', 'HEAD~2')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.PIPE)

    def test_overlapping_series_added_file_and_repeated_verification(self):
        original_index = self.git('write-tree')
        module.apply_series(self.repo, self.patches)
        module.apply_series(self.repo, self.patches)
        self.assertEqual((self.repo / 'value').read_text(), 'second\n')
        self.assertEqual((self.repo / 'added').read_text(), 'recorded new file\n')
        self.assertEqual(self.git('write-tree'), original_index)

    def test_valid_interrupted_prefix(self):
        self.git('apply', str(self.patches[0]))
        module.apply_series(self.repo, self.patches)
        self.assertEqual((self.repo / 'value').read_text(), 'second\n')

    def test_refuses_modified_recorded_new_file(self):
        module.apply_series(self.repo, self.patches)
        (self.repo / 'added').write_text('unrecorded change\n')
        with self.assertRaisesRegex(ValueError, 'recorded patch prefix'):
            module.apply_series(self.repo, self.patches)

    def test_refuses_unrelated_untracked_source(self):
        (self.repo / 'unexpected.rs').write_text('unrecorded\n')
        with self.assertRaisesRegex(ValueError, 'outside'):
            module.apply_series(self.repo, self.patches)


if __name__ == '__main__':
    unittest.main()
