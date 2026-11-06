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


    def test_empty_output(self):
        self.assertFalse(validate_output("", 0))

    def test_summary_only(self):
        self.assertFalse(validate_output("RESULT 60/60 checks; PASS\n", 0))

    def test_success_with_missing_summary(self):
        self.assertFalse(validate_output(self.valid.rsplit("RESULT ", 1)[0], 0))

    def test_wrong_summary_count(self):
        self.assertFalse(validate_output(self.valid.replace("60/60", "61/61"), 0))

    def test_zero_padded_wrong_gate(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 01", "PASS 00"), 0))

    def test_negative_gate_number(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 01", "PASS -1"), 0))

    def test_gate_without_description(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 01 test", "PASS 01 "), 0))

    def test_lowercase_pass(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 01", "pass 01"), 0))

    def test_partial_summary(self):
        self.assertFalse(validate_output(self.valid.replace(" checks; PASS", " checks"), 0))

    def test_extra_blank_line(self):
        self.assertFalse(validate_output(self.valid + "\n", 0))

    def test_prefix_noise(self):
        self.assertFalse(validate_output("noise\n" + self.valid, 0))

    def test_embedded_failure_marker(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 01 test", "FAIL 01 test"), 0))

    def test_wrong_expected_gate_count(self):
        self.assertFalse(validate_output(self.valid, 0, expected=59))

    def test_gate_number_out_of_order(self):
        self.assertFalse(validate_output(self.valid.replace("PASS 60 test", "PASS 59 test"), 0))

    def test_nonzero_exit_even_if_summary_passes(self):
        self.assertFalse(validate_output(self.valid, 137))


if __name__ == "__main__":
    unittest.main()
