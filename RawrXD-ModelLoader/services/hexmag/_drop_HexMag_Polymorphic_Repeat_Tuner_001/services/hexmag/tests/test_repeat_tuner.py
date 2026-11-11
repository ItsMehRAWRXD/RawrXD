import unittest

from core.repeat_tuner import FailureSignal, RepeatTuner, generation_id


class RepeatTunerTests(unittest.TestCase):
    def test_retries_are_polymorphic(self):
        tuner = RepeatTuner(max_attempts=6)
        rid = "r1"
        p = tuner.initial(rid)
        fingerprints = {p.fingerprint}

        failures = [
            FailureSignal("contradiction", "A conflicts with B"),
            FailureSignal("counterexample", "boundary input breaks result"),
            FailureSignal("test_failure", "unit test failed"),
            FailureSignal("duplicate_answer", "same candidate"),
        ]

        for attempt, failure in enumerate(failures, start=1):
            p2 = tuner.next(rid, p, [failure], attempt)
            self.assertNotIn(p2.fingerprint, fingerprints)
            self.assertEqual(p2.queue_policy, "Q_BLOCKING")
            self.assertEqual(p2.blocking_passes, 3)
            fingerprints.add(p2.fingerprint)
            p = p2

    def test_failure_directs_strategy(self):
        tuner = RepeatTuner()
        rid = "r2"
        p = tuner.initial(rid)

        p = tuner.next(rid, p, [FailureSignal("contradiction")], 1)
        self.assertEqual(p.strategy, "invariant")

        p = tuner.next(rid, p, [FailureSignal("counterexample")], 2)
        self.assertEqual(p.strategy, "counterexample")

        p = tuner.next(rid, p, [FailureSignal("unsupported_claim")], 3)
        self.assertEqual(p.strategy, "reverse")

        p = tuner.next(rid, p, [FailureSignal("test_failure")], 4)
        self.assertEqual(p.strategy, "repair")

    def test_generation_id_changes(self):
        tuner = RepeatTuner()
        rid = "r3"
        p0 = tuner.initial(rid)
        g0 = generation_id(rid, 0, p0)
        p1 = tuner.next(rid, p0, [FailureSignal("wrong")], 1)
        g1 = generation_id(rid, 1, p1)
        self.assertNotEqual(g0, g1)

    def test_missing_information_does_not_increase_creativity(self):
        tuner = RepeatTuner()
        rid = "r4"
        p0 = tuner.initial(rid)
        p1 = tuner.next(rid, p0, [FailureSignal("missing_information")], 1)
        self.assertEqual(p1.strategy, "evidence-guard")
        self.assertEqual(p1.temperature, 0.0)
        self.assertEqual(p1.candidate_count, 1)


if __name__ == "__main__":
    unittest.main()
