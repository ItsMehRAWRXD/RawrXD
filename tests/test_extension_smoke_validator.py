"""Fail-closed regression tests for the extension smoke transcript validator."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_extension_registry_local import validate_output


class SmokeTranscriptValidation(unittest.TestCase):
    def setUp(self):
        self.valid = "".join(f"PASS {i:02d} test\n" for i in range(1, 61))
        self.valid += "RESULT 60/60 checks; PASS\n"

    def test_valid_transcript(self):
        self.assertTrue(validate_output(self.valid, 0))

    def test_nonzero_exit(self):
        self.assertFalse(validate_output(self.valid, 1))

    def test_missing_gate(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 12 test\n", ""), 0))

    def test_duplicate_gate(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 12 test", "PASS 11 test"), 0))

    def test_failure_line(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 12", "FAIL 12"), 0))

    def test_forged_summary(self):
        self.assertFalse(validate_output(self.valid.replace("RESULT 60/60", "RESULT 59/60"), 0))

    def test_reordered_gates(self):
        self.assertFalse(validate_output(self.valid.replace(
            "PASS 12 test\nPASS 13 test", "PASS 13 test\nPASS 12 test"), 0))

    def test_extra_gate(self):
        self.assertFalse(validate_output(self.valid + "PASS 61 extra\n", 0))

    def test_trailing_noise(self):
        self.assertFalse(validate_output(self.valid + "warning\n", 0))

    def test_embedded_summary(self):
        self.assertFalse(validate_output(self.valid.replace(
            "RESULT 60/60 checks; PASS", "prefix RESULT 60/60 checks; PASS"), 0))


if __name__ == "__main__":
    unittest.main()
