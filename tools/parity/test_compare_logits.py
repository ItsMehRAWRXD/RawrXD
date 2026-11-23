import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).with_name("compare_logits.py")
SPEC = importlib.util.spec_from_file_location("compare_logits", MODULE)
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)

HASH_A = "a" * 64
HASH_B = "b" * 64


def fixture(values):
    return {
        "metadata": {"model_sha256": HASH_A, "tokenizer_sha256": HASH_B, "tokens": [1, 7, 9]},
        "positions": [{"position": i, "logits": row} for i, row in enumerate(values)],
    }


class ParityOracleTests(unittest.TestCase):
    def test_identical_logits_pass(self):
        rows = [[0.1, 2.0, -1.0], [3.0, 0.0, -2.0]]
        report = oracle.compare(fixture(rows), fixture(rows))
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["argmax_matches"], 2)
        self.assertEqual(report["minimum_cosine"], 1.0)

    def test_argmax_mismatch_fails(self):
        report = oracle.compare(fixture([[0.0, 2.0, 1.0]]),
                                fixture([[0.0, 1.0, 2.0]]))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["mismatched_positions"], [0])

    def test_metadata_mismatch_rejected(self):
        candidate = fixture([[1.0, 2.0]])
        candidate["metadata"]["tokens"] = [1, 8, 9]
        with self.assertRaises(oracle.InputError):
            oracle.compare(fixture([[1.0, 2.0]]), candidate)

    def test_position_mismatch_rejected(self):
        candidate = fixture([[1.0, 2.0]])
        candidate["positions"][0]["position"] = 1
        with self.assertRaises(oracle.InputError):
            oracle.compare(fixture([[1.0, 2.0]]), candidate)

    def test_non_finite_logits_rejected(self):
        bad = fixture([[1.0, float("nan")]])
        with self.assertRaises(oracle.InputError):
            oracle.compare(bad, bad)

    def test_vocab_mismatch_rejected(self):
        with self.assertRaises(oracle.InputError):
            oracle.compare(fixture([[1.0, 2.0]]), fixture([[1.0, 2.0, 3.0]]))


if __name__ == "__main__":
    unittest.main()
