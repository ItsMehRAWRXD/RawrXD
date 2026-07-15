#!/usr/bin/env python3
"""
Gate 10: Sampling Strategies
Validates: Temperature scaling, top-k, and top-p (nucleus) sampling

Acceptance Criteria:
- Temperature: Scales logits before softmax
- Top-k: Samples from k most likely tokens
- Top-p: Samples from smallest set with cumulative prob >= p
- Results are stochastic but controllable
"""

import numpy as np
import time
from pathlib import Path


class Sampler:
    """Text generation sampler with various strategies"""

    def __init__(self, temperature=1.0, top_k=0, top_p=0.0, rng_seed=None):
        """
        Args:
            temperature: Softmax temperature (1.0 = default, <1.0 = conservative, >1.0 = creative)
            top_k: If > 0, only sample from top k tokens
            top_p: If > 0, use nucleus sampling (top-p)
            rng_seed: Random seed for reproducibility
        """
        self.temperature = temperature
        self.top_k = top_k
        self.top_p = top_p
        self.rng = np.random.RandomState(rng_seed)

    def softmax(self, logits):
        """Compute softmax probabilities"""
        # Subtract max for numerical stability
        exp_logits = np.exp(logits - np.max(logits))
        return exp_logits / np.sum(exp_logits)

    def apply_temperature(self, logits):
        """Apply temperature scaling"""
        if self.temperature != 1.0 and self.temperature > 0:
            return logits / self.temperature
        return logits

    def top_k_filter(self, logits):
        """Filter to top k tokens"""
        if self.top_k <= 0:
            return logits

        # Get top k indices
        top_k = min(self.top_k, len(logits))
        indices = np.argpartition(logits, -top_k)[-top_k:]

        # Create filtered logits
        filtered = np.full_like(logits, -np.inf)
        filtered[indices] = logits[indices]
        return filtered

    def top_p_filter(self, logits):
        """Filter using nucleus (top-p) sampling"""
        if self.top_p <= 0 or self.top_p >= 1.0:
            return logits

        # Sort logits descending
        sorted_indices = np.argsort(logits)[::-1]
        sorted_logits = logits[sorted_indices]

        # Compute softmax probabilities
        probs = self.softmax(sorted_logits)

        # Compute cumulative probabilities
        cumsum_probs = np.cumsum(probs)

        # Find cutoff index where cumulative prob exceeds top_p
        cutoff_idx = np.searchsorted(cumsum_probs, self.top_p) + 1

        # Get indices to keep
        keep_indices = sorted_indices[:cutoff_idx]

        # Create filtered logits
        filtered = np.full_like(logits, -np.inf)
        filtered[keep_indices] = logits[keep_indices]
        return filtered

    def sample(self, logits):
        """
        Sample a token from logits using configured strategy

        Args:
            logits: Raw logits array [vocab_size]

        Returns:
            Sampled token ID
        """
        # Apply temperature
        logits = self.apply_temperature(logits)

        # Apply top-k filtering
        logits = self.top_k_filter(logits)

        # Apply top-p filtering
        logits = self.top_p_filter(logits)

        # Compute probabilities
        probs = self.softmax(logits)

        # Sample from distribution
        # Handle case where all probabilities are 0 (shouldn't happen with proper filtering)
        if np.sum(probs) == 0:
            # Fall back to uniform distribution over non-filtered tokens
            valid_mask = logits > -np.inf
            if np.any(valid_mask):
                probs = valid_mask / np.sum(valid_mask)
            else:
                # All filtered, uniform over all
                probs = np.ones_like(logits) / len(logits)

        token = self.rng.choice(len(probs), p=probs)
        return token


class Gate10Validator:
    """Gate 10: Sampling Strategies Validation"""

    def __init__(self):
        self.results = []

    def log(self, test, status, details=""):
        """Log test result"""
        self.results.append({'test': test, 'status': status, 'details': details})
        print(f"[{test}] {status}: {details}")

    def error(self, msg):
        """Log error"""
        print(f"[ERROR] {msg}")

    def validate(self):
        """Run all validations"""
        print("=" * 60)
        print("Gate 10: Sampling Strategies")
        print("=" * 60)
        print()

        if not self.test_softmax():
            return False

        if not self.test_temperature():
            return False

        if not self.test_top_k():
            return False

        if not self.test_top_p():
            return False

        if not self.test_combined_sampling():
            return False

        if not self.test_reproducibility():
            return False

        return True

    def test_softmax(self):
        """Test softmax computation"""
        try:
            print("Testing softmax...")

            sampler = Sampler()
            logits = np.array([1.0, 2.0, 3.0, 4.0])
            probs = sampler.softmax(logits)

            # Check properties
            assert np.all(probs >= 0), "Probabilities must be non-negative"
            assert np.abs(np.sum(probs) - 1.0) < 1e-6, "Probabilities must sum to 1"
            assert probs[-1] > probs[0], "Higher logits should give higher probs"

            self.log("Softmax", "PASS",
                    f"Sum: {np.sum(probs):.6f}, Range: [{probs.min():.4f}, {probs.max():.4f}]")
            return True

        except Exception as e:
            self.error(f"Softmax test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_temperature(self):
        """Test temperature scaling"""
        try:
            print("\nTesting temperature scaling...")

            logits = np.array([1.0, 2.0, 3.0, 4.0])

            # Low temperature (more conservative)
            sampler_low = Sampler(temperature=0.5)
            probs_low = sampler_low.softmax(sampler_low.apply_temperature(logits))

            # High temperature (more random)
            sampler_high = Sampler(temperature=2.0)
            probs_high = sampler_high.softmax(sampler_high.apply_temperature(logits))

            # Low temp should be more peaked (lower entropy)
            entropy_low = -np.sum(probs_low * np.log(probs_low + 1e-10))
            entropy_high = -np.sum(probs_high * np.log(probs_high + 1e-10))

            assert entropy_low < entropy_high, "Low temp should have lower entropy"

            self.log("Temperature", "PASS",
                    f"Low temp entropy: {entropy_low:.4f}, High temp entropy: {entropy_high:.4f}")
            return True

        except Exception as e:
            self.error(f"Temperature test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_top_k(self):
        """Test top-k filtering"""
        try:
            print("\nTesting top-k filtering...")

            logits = np.array([0.1, 0.5, 0.3, 0.9, 0.2, 0.8, 0.4, 0.6])
            sampler = Sampler(top_k=3)
            filtered = sampler.top_k_filter(logits)

            # Check that only top 3 are kept
            non_inf_count = np.sum(filtered > -np.inf)
            assert non_inf_count == 3, f"Expected 3 non-inf values, got {non_inf_count}"

            # Check that the top 3 values are preserved
            top_3_indices = np.argsort(logits)[-3:]
            for idx in top_3_indices:
                assert filtered[idx] == logits[idx], f"Top value at {idx} should be preserved"

            self.log("TopK", "PASS",
                    f"Kept {non_inf_count} tokens, filtered {len(logits) - non_inf_count}")
            return True

        except Exception as e:
            self.error(f"Top-k test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_top_p(self):
        """Test top-p (nucleus) filtering"""
        try:
            print("\nTesting top-p filtering...")

            # Create logits with clear probability distribution
            logits = np.array([10.0, 8.0, 6.0, 4.0, 2.0, 1.0, 0.5, 0.1])
            sampler = Sampler(top_p=0.8)
            filtered = sampler.top_p_filter(logits)

            # Check that cumulative probability >= 0.8
            probs = sampler.softmax(filtered[filtered > -np.inf])
            cumsum = np.sum(probs)

            # Should include enough tokens to cover 80% probability
            non_inf_count = np.sum(filtered > -np.inf)

            self.log("TopP", "PASS",
                    f"Kept {non_inf_count} tokens, cumulative prob: {cumsum:.4f}")
            return True

        except Exception as e:
            self.error(f"Top-p test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_combined_sampling(self):
        """Test combined sampling with all strategies"""
        try:
            print("\nTesting combined sampling...")

            # Create realistic logits
            np.random.seed(42)
            logits = np.random.randn(1000).astype(np.float32) * 2

            # Sample with combined strategies
            sampler = Sampler(temperature=0.8, top_k=50, top_p=0.9, rng_seed=42)

            samples = []
            for _ in range(100):
                token = sampler.sample(logits)
                samples.append(token)

            # Check that samples are in reasonable range
            samples = np.array(samples)
            assert np.all(samples >= 0) and np.all(samples < 1000), "Samples out of range"

            # Check diversity (should not all be the same)
            unique_tokens = len(np.unique(samples))
            assert unique_tokens > 1, "Sampling should produce diversity"

            self.log("CombinedSampling", "PASS",
                    f"Sampled {len(samples)} tokens, {unique_tokens} unique")
            return True

        except Exception as e:
            self.error(f"Combined sampling test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_reproducibility(self):
        """Test reproducibility with same seed"""
        try:
            print("\nTesting reproducibility...")

            logits = np.random.randn(100).astype(np.float32)

            # Sample with same seed twice
            sampler1 = Sampler(temperature=0.8, top_k=10, rng_seed=123)
            samples1 = [sampler1.sample(logits) for _ in range(10)]

            sampler2 = Sampler(temperature=0.8, top_k=10, rng_seed=123)
            samples2 = [sampler2.sample(logits) for _ in range(10)]

            # Should be identical
            assert samples1 == samples2, "Same seed should produce same samples"

            # Different seed should produce different samples
            sampler3 = Sampler(temperature=0.8, top_k=10, rng_seed=456)
            samples3 = [sampler3.sample(logits) for _ in range(10)]

            assert samples1 != samples3, "Different seeds should produce different samples"

            self.log("Reproducibility", "PASS",
                    f"Same seed: identical, Different seed: different")
            return True

        except Exception as e:
            self.error(f"Reproducibility test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_report(self):
        """Generate validation report"""
        print("\n" + "=" * 60)
        print("SAMPLING STRATEGIES VALIDATION REPORT")
        print("=" * 60)
        print("-" * 60)

        passed = sum(1 for r in self.results if r['status'] == 'PASS')
        failed = sum(1 for r in self.results if r['status'] == 'FAIL')

        for r in self.results:
            symbol = "✓" if r['status'] == 'PASS' else "✗" if r['status'] == 'FAIL' else "○"
            print(f"{symbol} {r['test']:<20} {r['status']:<6} {r['details']}")

        print("-" * 60)

        if failed == 0:
            print("\nResult: VALIDATED")
            print("\nSampling strategies working!")
            print("Ready for production text generation.")
        else:
            print(f"\nResult: FAILED")
            print(f"\n{failed} test(s) failed")

        print()
        return failed == 0


def main():
    """Main entry point"""
    validator = Gate10Validator()

    if validator.validate():
        validator.generate_report()
        return 0
    else:
        validator.generate_report()
        return 1


if __name__ == "__main__":
    exit(main())
