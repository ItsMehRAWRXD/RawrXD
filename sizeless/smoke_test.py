"""
RawrXD Sizeless Engine — Smoke Test Harness

Tests:
  1. System detection works on all platforms
  2. Seed generation produces unique seeds per topic
  3. Weight generation works at all sizes
  4. Lazy weights save storage
  5. Inference produces reasonable output
  6. Multiple topics route to different domains
  7. Same prompt produces same seed (deterministic)
  8. Different prompts produce different seeds
  9. All size presets generate correctly
  10. Seed-to-model ratio is extreme (KB → GB)
"""

import json
import os
import sys
import time
import hashlib
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from system_detector import SystemDetector, SystemSpecs
from seed_generator import DynamicSeedGenerator, DynamicSeed
from weight_generator import WeightGenerator, GeneratedModel, LazyWeights
from inference_engine import SizelessInferenceEngine


class SmokeTest:
    """Smoke test harness for the Sizeless Engine."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.results = []

    def test(self, name: str, func, *args, **kwargs) -> bool:
        """Run a single test."""
        try:
            result = func(*args, **kwargs)
            if result:
                self.passed += 1
                status = "PASS"
            else:
                self.failed += 1
                status = "FAIL"
            self.results.append((name, status, ""))
            return result
        except Exception as e:
            self.failed += 1
            self.results.append((name, "FAIL", str(e)))
            return False

    def summary(self) -> str:
        total = self.passed + self.failed + self.skipped
        lines = [
            f"\n{'='*62}",
            f"  SMOKE TEST RESULTS",
            f"  Total: {total}  |  Passed: {self.passed}  |  Failed: {self.failed}  |  Skipped: {self.skipped}",
            f"{'='*62}",
        ]
        for name, status, error in self.results:
            icon = "✓" if status == "PASS" else "✗" if status == "FAIL" else "△"
            line = f"  {icon} {name:50s} {status}"
            if error:
                line += f"\n     Error: {error[:100]}"
            lines.append(line)
        lines.append(f"{'='*62}")
        lines.append(f"  Overall: {'ALL PASSED ✓' if self.failed == 0 else f'{self.failed} FAILURES ✗'}")
        lines.append(f"{'='*62}")
        return "\n".join(lines)


def run_all_tests():
    """Run all smoke tests."""
    test = SmokeTest()
    print(f"\n{'='*62}")
    print(f"  RAWRXD SIZELESS ENGINE — SMOKE TEST SUITE")
    print(f"  Testing: System Detection | Seed Generation | Weight Generation | Inference")
    print(f"{'='*62}")

    # ══════════════════════════════════════════════════════════════════
    # TEST GROUP 1: System Detection
    # ══════════════════════════════════════════════════════════════════
    print(f"\n  ── Test Group 1: System Detection ──")

    def test_system_detection():
        detector = SystemDetector()
        specs = detector.detect()
        assert specs.total_ram_gb > 0, f"RAM should be > 0, got {specs.total_ram_gb}"
        assert specs.cpu_cores > 0, f"CPU cores should be > 0, got {specs.cpu_cores}"
        assert specs.available_ram_gb > 0, f"Available RAM should be > 0"
        assert specs.max_model_size in ["100M", "250M", "500M", "1B", "3B", "7B", "13B", "70B", "170B"]
        assert specs.max_model_params >= 100_000_000
        return True

    test.test("System detection returns valid specs", test_system_detection)

    def test_system_summary():
        detector = SystemDetector()
        specs = detector.detect()
        summary = specs.summary()
        assert "CPU" in summary
        assert "RAM" in summary
        assert "Max Model" in summary
        return True

    test.test("System summary contains key info", test_system_summary)

    def test_system_to_dict():
        detector = SystemDetector()
        specs = detector.detect()
        d = specs.to_dict()
        assert isinstance(d, dict)
        assert "cpu_name" in d
        assert "total_ram_gb" in d
        assert "max_model_size" in d
        return True

    test.test("System specs serializable to dict", test_system_to_dict)

    # ══════════════════════════════════════════════════════════════════
    # TEST GROUP 2: Seed Generation
    # ══════════════════════════════════════════════════════════════════
    print(f"\n  ── Test Group 2: Seed Generation ──")

    def test_seed_generation():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0, "max_model_size": "1B"}
        seed = gen.generate_seed("What is the integral of x^2?", specs)
        assert seed is not None
        assert len(seed.seed_id) > 0
        assert seed.seed_size_bytes > 0
        assert seed.knowledge_domain == "Mathematics & Logic"
        return True

    test.test("Seed generation creates valid seed", test_seed_generation)

    def test_seed_topic_classification():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}

        test_cases = [
            ("What is 2+2?", "Mathematics & Logic"),
            ("Write a Python function", "Programming & Code"),
            ("Tell me a story", "Creative Writing"),
            ("Explain quantum physics", "Science & Physics"),
            ("What happened in 1066?", "History & Events"),
            ("What is the meaning of life?", "Philosophy"),
            ("Translate hello to Spanish", "Languages"),
            ("Describe a C major chord", "Music Theory"),
            ("How does DNA work?", "Biology & Medicine"),
            ("What is the capital of France?", "Geography"),
            ("How does a CPU work?", "Technology"),
            ("What causes a fever?", "Health & Medicine"),
            ("How to start a business?", "Business & Finance"),
            ("Help me learn calculus", "Education"),
            ("Hello, how are you?", "General Knowledge"),
        ]

        for prompt, expected_domain in test_cases:
            seed = gen.generate_seed(prompt, specs)
            assert seed.knowledge_domain == expected_domain, \
                f"'{prompt[:30]}...' → expected '{expected_domain}', got '{seed.knowledge_domain}'"
        return True

    test.test("Topic classification routes correctly (15 domains)", test_seed_topic_classification)

    def test_seed_determinism():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        prompt = "What is the derivative of sin(x)?"
        seed1 = gen.generate_seed(prompt, specs)
        seed2 = gen.generate_seed(prompt, specs)
        assert seed1.seed_id == seed2.seed_id, "Same prompt should produce same seed ID"
        assert seed1.base_seed == seed2.base_seed, "Same prompt should produce same base seed"
        return True

    test.test("Same prompt produces same seed (deterministic)", test_seed_determinism)

    def test_seed_uniqueness():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        prompts = [
            "What is calculus?",
            "Write a Python function",
            "Tell me a story",
            "Explain quantum physics",
            "What is the meaning of life?",
        ]
        seeds = [gen.generate_seed(p, specs) for p in prompts]
        seed_ids = [s.seed_id for s in seeds]
        assert len(set(seed_ids)) == len(seed_ids), "Different prompts should produce different seeds"
        return True

    test.test("Different prompts produce different seeds", test_seed_uniqueness)

    def test_seed_size():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        seed = gen.generate_seed("Test prompt for size checking", specs)
        assert seed.seed_size_bytes < 10240, f"Seed should be < 10KB, got {seed.seed_size_bytes} bytes"
        assert seed.seed_size_bytes > 0, "Seed should have positive size"
        return True

    test.test("Seed is tiny (< 10KB)", test_seed_size)

    def test_seed_architecture():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        seed = gen.generate_seed("Write a Python function", specs)
        assert "hidden_dim" in seed.architecture
        assert "num_layers" in seed.architecture
        assert "num_heads" in seed.architecture
        assert seed.architecture["vocab_size"] == 32000
        return True

    test.test("Seed contains valid architecture", test_seed_architecture)

    def test_seed_compatible_sizes():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        seed = gen.generate_seed("Test", specs)
        assert "100M" in seed.compatible_sizes
        assert "1B" in seed.compatible_sizes
        assert "70B" in seed.compatible_sizes
        return True

    test.test("Seed supports all model sizes", test_seed_compatible_sizes)

    # ══════════════════════════════════════════════════════════════════
    # TEST GROUP 3: Weight Generation
    # ══════════════════════════════════════════════════════════════════
    print(f"\n  ── Test Group 3: Weight Generation ──")

    def test_weight_generation_1b():
        gen = WeightGenerator("test_seed", 42, {"hidden_dim": 2048, "num_layers": 24, "num_heads": 16, "vocab_size": 32000, "ffn_multiplier": 4})
        model = gen.generate("1B", lazy=True)
        # 1B preset with 2048 hidden, 24 layers, 32000 vocab = ~1.34B params (includes embedding + output)
        assert model.actual_params >= 800_000_000, f"1B model should have ~1.3B params, got {model.actual_params}"
        assert model.actual_params <= 2_000_000_000
        assert len(model.layers) > 0
        return True

    test.test("1B model generation produces correct params", test_weight_generation_1b)

    def test_weight_generation_all_sizes():
        gen = WeightGenerator("test_seed", 42, {"hidden_dim": 2048, "num_layers": 24, "num_heads": 16, "vocab_size": 32000, "ffn_multiplier": 4})
        sizes = ["100M", "250M", "500M", "1B", "3B", "7B"]
        for size in sizes:
            model = gen.generate(size, lazy=True)
            expected = WeightGenerator.SIZE_PRESETS[size][0]
            ratio = model.actual_params / expected
            assert 0.5 < ratio < 2.0, f"{size}: expected ~{expected}, got {model.actual_params}"
        return True

    test.test("All size presets generate correctly (6 sizes)", test_weight_generation_all_sizes)

    def test_lazy_weights():
        w = LazyWeights("test", "test_layer", (100, 100), 42)
        val1 = w[(0, 0)]
        val2 = w[(0, 0)]
        assert val1 == val2, "Same position should produce same weight"
        val3 = w[(50, 50)]
        assert val3 != val1, "Different position should produce different weight"
        assert w.cached_count == 2, "Should have cached 2 values"
        assert w.storage_saved_pct > 99.9, "Should have saved >99.9% storage"
        return True

    test.test("Lazy weights are deterministic and save storage", test_lazy_weights)

    def test_lazy_weights_1d():
        w = LazyWeights("test", "test_1d", (100,), 42)
        val = w[50]
        assert isinstance(val, float)
        assert -1.0 <= val <= 1.0
        return True

    test.test("Lazy weights work for 1D tensors", test_lazy_weights_1d)

    def test_weight_determinism():
        gen1 = WeightGenerator("det_test", 42, {"hidden_dim": 768, "num_layers": 12, "num_heads": 12, "vocab_size": 32000, "ffn_multiplier": 4})
        gen2 = WeightGenerator("det_test", 42, {"hidden_dim": 768, "num_layers": 12, "num_heads": 12, "vocab_size": 32000, "ffn_multiplier": 4})
        m1 = gen1.generate("100M", lazy=True)
        m2 = gen2.generate("100M", lazy=True)
        w1 = m1.layers[1].weights["layer_0_q_weight"]
        w2 = m2.layers[1].weights["layer_0_q_weight"]
        assert w1[(0, 0)] == w2[(0, 0)], "Same seed should produce same weights"
        assert w1[(50, 50)] == w2[(50, 50)], "Same seed should produce same weights at any position"
        return True

    test.test("Weight generation is deterministic (same seed = same weights)", test_weight_determinism)

    def test_weight_different_seeds():
        gen1 = WeightGenerator("seed_a", 42, {"hidden_dim": 768, "num_layers": 12, "num_heads": 12, "vocab_size": 32000, "ffn_multiplier": 4})
        gen2 = WeightGenerator("seed_b", 999, {"hidden_dim": 768, "num_layers": 12, "num_heads": 12, "vocab_size": 32000, "ffn_multiplier": 4})
        m1 = gen1.generate("100M", lazy=True)
        m2 = gen2.generate("100M", lazy=True)
        w1 = m1.layers[1].weights["layer_0_q_weight"]
        w2 = m2.layers[1].weights["layer_0_q_weight"]
        assert w1[(0, 0)] != w2[(0, 0)], "Different seeds should produce different weights"
        return True

    test.test("Different seeds produce different weights", test_weight_different_seeds)

    def test_generation_time():
        gen = WeightGenerator("time_test", 42, {"hidden_dim": 2048, "num_layers": 24, "num_heads": 16, "vocab_size": 32000, "ffn_multiplier": 4})
        model = gen.generate("1B", lazy=True)
        assert model.generation_time_ms < 5000, f"1B model should generate in < 5s, took {model.generation_time_ms:.0f}ms"
        return True

    test.test("Model generation is fast (< 5s for 1B)", test_generation_time)

    # ══════════════════════════════════════════════════════════════════
    # TEST GROUP 4: Inference Engine
    # ══════════════════════════════════════════════════════════════════
    print(f"\n  ── Test Group 4: Inference Engine ──")

    def test_inference_engine():
        engine = SizelessInferenceEngine()
        result = engine.infer("What is calculus?", verbose=False)
        assert result is not None
        assert len(result.text) > 0
        assert result.seed_id is not None
        assert result.model_size is not None
        assert result.actual_params > 0
        assert result.memory_mb > 0
        assert result.total_time_ms > 0
        return True

    test.test("Inference engine produces valid output", test_inference_engine)

    def test_inference_topic_routing():
        engine = SizelessInferenceEngine()
        r1 = engine.infer("Write a Python function", verbose=False)
        r2 = engine.infer("Tell me a story", verbose=False)
        assert r1.knowledge_domain != r2.knowledge_domain, \
            f"Different topics should route to different domains: {r1.knowledge_domain} vs {r2.knowledge_domain}"
        return True

    test.test("Different topics route to different domains", test_inference_topic_routing)

    def test_inference_force_size():
        engine = SizelessInferenceEngine()
        r1 = engine.infer("Test", force_size="100M", verbose=False)
        r2 = engine.infer("Test", force_size="7B", verbose=False)
        assert r1.model_size == "100M"
        assert r2.model_size == "7B"
        assert r1.actual_params < r2.actual_params
        assert r1.memory_mb < r2.memory_mb
        return True

    test.test("Force size overrides auto-detection", test_inference_force_size)

    def test_inference_seed_to_model_ratio():
        engine = SizelessInferenceEngine()
        result = engine.infer("Test ratio", verbose=False)
        assert "1:" in result.seed_to_model_ratio
        ratio_parts = result.seed_to_model_ratio.split("1:")
        if len(ratio_parts) > 1:
            ratio_val = float(ratio_parts[1].replace(",", ""))
            assert ratio_val > 1000, f"Seed-to-model ratio should be > 1000:1, got 1:{ratio_val:.0f}"
        return True

    test.test("Seed-to-model ratio is extreme (> 1000:1)", test_inference_seed_to_model_ratio)

    def test_inference_stats():
        engine = SizelessInferenceEngine()
        engine.infer("Test stats", verbose=False)
        engine.infer("More stats", verbose=False)
        stats = engine.get_stats()
        assert stats["inference_count"] == 2
        assert stats["total_inference_time_ms"] > 0
        assert stats["current_model_size"] is not None
        return True

    test.test("Engine tracks inference statistics", test_inference_stats)

    def test_inference_system_detection():
        engine = SizelessInferenceEngine()
        specs = engine.detect_system()
        assert specs is not None
        assert specs.total_ram_gb > 0
        assert specs.cpu_cores > 0
        return True

    test.test("System detection works in engine context", test_inference_system_detection)

    # ══════════════════════════════════════════════════════════════════
    # TEST GROUP 5: Edge Cases
    # ══════════════════════════════════════════════════════════════════
    print(f"\n  ── Test Group 5: Edge Cases ──")

    def test_empty_prompt():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        seed = gen.generate_seed("", specs)
        assert seed is not None
        assert seed.knowledge_domain == "General Knowledge"
        return True

    test.test("Empty prompt routes to General Knowledge", test_empty_prompt)

    def test_very_long_prompt():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        long_prompt = "math " * 1000
        seed = gen.generate_seed(long_prompt, specs)
        assert seed is not None
        assert seed.knowledge_domain == "Mathematics & Logic"
        return True

    test.test("Very long prompt still classifies correctly", test_very_long_prompt)

    def test_special_characters():
        gen = DynamicSeedGenerator()
        specs = {"os": "test", "ram_gb": 16.0}
        seed = gen.generate_seed("!@#$%^&*()_+-=[]{}|;':\",./<>?", specs)
        assert seed is not None
        return True

    test.test("Special characters in prompt handled gracefully", test_special_characters)

    def test_lazy_weights_eager_conversion():
        w = LazyWeights("test", "test_eager", (10, 10), 42)
        eager = w.to_eager()
        assert len(eager) == 100
        assert all(isinstance(v, float) for v in eager)
        return True

    test.test("Lazy weights can convert to eager", test_lazy_weights_eager_conversion)

    def test_model_info():
        gen = WeightGenerator("info_test", 42, {"hidden_dim": 768, "num_layers": 12, "num_heads": 12, "vocab_size": 32000, "ffn_multiplier": 4})
        model = gen.generate("100M", lazy=True)
        info = model.info()
        assert "100M" in info
        assert "params" in info
        assert "MB" in info
        return True

    test.test("Model info string is informative", test_model_info)

    # ══════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════
    print(test.summary())
    return test.failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
