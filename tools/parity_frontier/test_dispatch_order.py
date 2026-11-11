"""Fixture validation for the exact remote-dispatch anchors and new ordering."""
import tempfile
import pathlib
import subprocess
import sys
import unittest
import fix_dispatch_order as fix

class DispatchOrderTests(unittest.TestCase):
    def setUp(self):
        self.original = 'class PrimitiveDispatcher {\n' + fix.OLD_TOPK + '\n' + fix.OLD_MOE + '\n};\n'
    def test_two_cases_replaced(self):
        new, status = fix.patch(self.original)
        self.assertEqual(status, 'PATCH_READY')
        self.assertEqual(new.count('TOPK_BIND_FAIL'), 1)
        self.assertEqual(new.count('MOE_BIND_FAIL'), 1)
        self.assertLess(new.index('float* output = getOutput(op);'), new.index('const size_t outputN'))
        self.assertNotIn('TopKFwd(getInput(op,0),getOutput(op)', new)
    def test_idempotence(self):
        new, _ = fix.patch(self.original)
        after, status = fix.patch(new)
        self.assertEqual(new, after)
        self.assertEqual(status, 'ALREADY_PATCHED')
    def test_partial_patch_rejected(self):
        with self.assertRaises(ValueError):
            fix.patch(self.original.replace(fix.OLD_TOPK, fix.NEW_TOPK))
    def test_unknown_source_rejected(self):
        with self.assertRaises(ValueError):
            fix.patch('irrelevant source')
    def test_apply_preserves_old_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            f=pathlib.Path(d)/'ir.cpp'
            f.write_bytes(self.original.replace('\n','\r\n').encode())
            before=f.read_bytes()
            cmd=[sys.executable, str(pathlib.Path(fix.__file__).resolve()), str(f), '--apply']
            result=subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode,0,result.stderr+result.stdout)
            self.assertEqual(len(list(pathlib.Path(d).glob('*.bak'))),1)
            self.assertEqual(list(pathlib.Path(d).glob('*.bak'))[0].read_bytes(),before)
            self.assertIn(b'\r\n',f.read_bytes())
            second=subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(second.returncode,0)
            self.assertIn('ALREADY_PATCHED',second.stdout)
if __name__=='__main__':unittest.main(verbosity=2)
