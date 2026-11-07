"""Executable child-process capture and process-tree tests, no Ollama required."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rawrxd_process_runner import run_process


class ProcessRunnerTests(unittest.TestCase):
    def test_01_dual_stream_large_burst_is_bounded_and_not_deadlocked(self):
        code = 'import sys; sys.stdout.buffer.write(b"A"*1000000);sys.stdout.flush();sys.stderr.buffer.write(b"B"*1000000);sys.stderr.flush()'
        result = run_process([sys.executable, '-c', code], 10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 32768)
        self.assertEqual(len(result.stderr), 32768)
        self.assertTrue(result.stdout.endswith('A'*100))
        self.assertTrue(result.stderr.endswith('B'*100))
        self.assertFalse(result.output_limit)

    def test_02_output_flood_fails_closed(self):
        code = 'import sys,time; [sys.stdout.buffer.write(b"X"*16384) for _ in range(1000)]; sys.stdout.flush();time.sleep(10)'
        result = run_process([sys.executable, '-c', code], 6, tail_bytes=1024, max_stream_bytes=65536)
        self.assertFalse(result.timed_out)
        self.assertTrue(result.output_limit)
        self.assertNotEqual(result.returncode, 0)
        self.assertLessEqual(len(result.stdout), 1024)

    def test_03_timeout_interrupts_process(self):
        result = run_process([sys.executable, '-c', 'import time;time.sleep(20)'], 0.4)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 124)

    def test_04_timeout_kills_descendant_tree(self):
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / 'orphan-marker'
            child = f'import time; from pathlib import Path;time.sleep(2);Path({str(marker)!r}).write_text("ORPHAN")'
            parent = f'import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",{child!r}]);time.sleep(15)'
            started = time.monotonic()
            result = run_process([sys.executable, '-c', parent], 0.5)
            self.assertEqual(result.returncode, 124)
            self.assertLess(time.monotonic() - started, 5)
            time.sleep(2.3)
            self.assertFalse(marker.exists(), 'Timeout left a detached descendant writing into workspace')

    def test_05_no_shell_or_argv_expansion(self):
        result = run_process([sys.executable, '-c', 'import sys;print("\t".join(sys.argv[1:]))', '; echo PWNED', 'file with spaces.c'], 3)
        self.assertEqual(result.returncode, 0)
        self.assertIn('; echo PWNED\tfile with spaces.c', result.stdout)


if __name__ == '__main__':
    unittest.main()
