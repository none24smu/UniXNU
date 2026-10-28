"""Execute the actual per-object flag/cache-invalidation shell fragment."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class TextFixupBuildFlags(unittest.TestCase):
    def test_actual_ubc_record_default_toggle_and_invalid_flag(self):
        text=(ROOT/'scripts/build-xnu-12377.sh').read_text()
        def function(name):
            begin=text.index(name+'() {');end=re.search(r'^}',text[begin:],re.M).end()+begin
            return text[begin:end]
        first=text.index('IOS27_TEXT_FIXUPS=$(flag XNU_IOS27_TEXT_FIXUPS)')
        last=text.index('\n',text.index('rebuild_on_change ios27-text-fixups-mode',first))
        fragment=text[first:last]
        self.assertEqual(fragment.count('ubc_subr.o_CFLAGS_ADD='),1)
        self.assertNotIn('EXTRA_CFLAGS=',fragment)
        with tempfile.TemporaryDirectory() as directory:
            obj=Path(directory)/'objects';unit=obj/'bsd/DEVELOPMENT/ubc_subr.o';other=obj/'bsd/DEVELOPMENT/other.o';unit.parent.mkdir(parents=True)
            script='set -euo pipefail\nOBJ=$1\nEXTRA_MAKE_ARGS=()\nEXTRA_CFLAGS=unchanged\n'+function('flag')+'\n'+function('rebuild_on_change')+'\nif [ "$2" = unset ]; then unset XNU_IOS27_TEXT_FIXUPS; else export XNU_IOS27_TEXT_FIXUPS=$2; fi\n'+fragment+'\nprintf "%s\\n" "${EXTRA_MAKE_ARGS[@]}" "$EXTRA_CFLAGS"\n'
            for mode,remove in [('unset',False),('1',True),('1',False),('0',True)]:
                unit.write_bytes(b'validator');other.write_bytes(b'other')
                result=subprocess.run(['bash','-c',script,'check',str(obj),mode],capture_output=True,text=True,check=True)
                self.assertEqual(result.stdout.splitlines(),['ubc_subr.o_CFLAGS_ADD=-DXNU_IOS27_TEXT_FIXUPS='+('0' if mode=='unset' else mode),'unchanged'])
                self.assertEqual(unit.exists(),not remove);self.assertEqual(other.read_bytes(),b'other')
            unit.write_bytes(b'validator')
            result=subprocess.run(['bash','-c',script,'check',str(obj),'2'],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('must be 0 or 1',result.stderr);self.assertEqual(unit.read_bytes(),b'validator')


if __name__=='__main__':unittest.main()
