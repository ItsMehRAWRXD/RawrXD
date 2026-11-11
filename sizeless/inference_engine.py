"""
RawrXD Sizeless Inference Engine — The Never Ending Intelligence Engine.

Every time you ask it something:
  1. Detects your system specs
  2. Classifies the topic
  3. Generates a unique seed for that topic
  4. Instantiates the model at the optimal size for YOUR hardware
  5. Runs inference locally — no cloud, no download
  6. Adjusts size dynamically as memory pressure changes

The model has no size. It checks what YOU can handle and becomes that.
"""

import hashlib
import json
import math
import os
import random
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from system_detector import SystemDetector, SystemSpecs
from seed_generator import DynamicSeedGenerator, DynamicSeed
from weight_generator import WeightGenerator, GeneratedModel, LazyWeights


@dataclass
class InferenceResult:
    text: str
    seed_id: str
    knowledge_domain: str
    model_size: str
    actual_params: int
    memory_mb: float
    generation_time_ms: float
    inference_time_ms: float
    total_time_ms: float
    system_specs: Dict[str, Any]
    seed_size_bytes: int
    seed_to_model_ratio: str
    lazy_weights_cached: int
    storage_saved_pct: float
    signature: str

    def summary(self) -> str:
        lines = [
            f"╔══ RawrXD Sizeless Inference ═══════════════════════════╗",
            f"║  Topic:      {self.knowledge_domain:30s} ║",
            f"║  Model Size: {self.model_size:>6s} ({self.actual_params/1e6:.0f}M params)          ║",
            f"║  Memory:     {self.memory_mb:.0f}MB ({self.seed_size_bytes} byte seed)         ║",
            f"║  Ratio:      {self.seed_to_model_ratio:30s} ║",
            f"║  Gen Time:   {self.generation_time_ms:.0f}ms  |  Inf Time: {self.inference_time_ms:.0f}ms  ║",
            f"║  Cached Wts: {self.lazy_weights_cached:>6d}  |  Saved: {self.storage_saved_pct:.0f}%        ║",
            f"║  Signature:  {self.signature:30s} ║",
            f"╚══════════════════════════════════════════════════════════╝",
        ]
        return "\n".join(lines)


class SizelessInferenceEngine:
    """
    The Never Ending Intelligence Engine.
    Self-sizing, self-seeding, local-only AI.
    """

    VERSION = "neie-smage-1.0"
    SIGNATURE = "~g87"

    def __init__(self, seed_dir: str = "seeds", max_loaded: int = 3):
        self.seed_dir = Path(seed_dir)
        self.seed_dir.mkdir(parents=True, exist_ok=True)
        self.detector = SystemDetector()
        self.seed_gen = DynamicSeedGenerator()
        self.specs: Optional[SystemSpecs] = None
        self.current_model: Optional[GeneratedModel] = None
        self.current_seed: Optional[DynamicSeed] = None
        self.max_loaded = max_loaded
        self.inference_count = 0
        self.total_inference_time = 0.0

    def detect_system(self) -> SystemSpecs:
        """Detect system hardware and calculate optimal model size."""
        self.specs = self.detector.detect()
        return self.specs

    def infer(self, prompt: str, force_size: Optional[str] = None,
              verbose: bool = True) -> InferenceResult:
        """
        Run inference on a prompt.
        
        1. Detects system specs (if not already done)
        2. Classifies the topic
        3. Generates a unique seed
        4. Instantiates model at optimal size
        5. Runs inference
        """
        total_start = time.time()

        # Step 1: Detect system
        if not self.specs:
            self.detect_system()

        # Step 2: Classify topic and generate seed
        domain_key, domain_name = self.seed_gen.classify_topic(prompt)
        seed = self.seed_gen.generate_seed(prompt, self.specs.to_dict())
        self.current_seed = seed

        if verbose:
            print(f"\n  📖 Topic: {domain_name}")
            print(f"  🧬 Seed: {seed.seed_id} ({seed.seed_size_bytes} bytes, {seed.generation_method})")

        # Step 3: Determine model size
        target_size = force_size or self.specs.max_model_size

        if verbose:
            print(f"  💻 System: {self.specs.max_model_size} max → Using: {target_size}")

        # Step 4: Generate model weights
        gen_start = time.time()
        generator = WeightGenerator(
            seed_id=seed.seed_id,
            base_seed=seed.base_seed,
            architecture=seed.architecture,
            method=seed.generation_method,
        )
        model = generator.generate(target_size=target_size, lazy=True)
        model.knowledge_domain = domain_name
        self.current_model = model
        gen_time = (time.time() - gen_start) * 1000

        if verbose:
            print(f"  ⚡ Generated: {model.info()} ({gen_time:.0f}ms)")

        # Step 5: Run inference (simulated — real impl would call the model)
        inf_start = time.time()
        text = self._simulate_inference(prompt, model, seed)
        inf_time = (time.time() - inf_start) * 1000

        # Step 6: Calculate stats
        total_time = (time.time() - total_start) * 1000
        seed_bytes = seed.seed_size_bytes
        model_bytes = model.actual_params * 2  # FP16
        ratio = model_bytes / max(seed_bytes, 1)

        # Count cached weights
        cached = 0
        for layer in model.layers:
            if isinstance(layer.weights, dict):
                for w in layer.weights.values():
                    if isinstance(w, LazyWeights):
                        cached += w.cached_count
            elif isinstance(layer.weights, LazyWeights):
                cached += layer.weights.cached_count

        storage_saved = 0
        if model.actual_params > 0:
            storage_saved = (1 - cached / model.actual_params) * 100

        self.inference_count += 1
        self.total_inference_time += total_time

        result = InferenceResult(
            text=text,
            seed_id=seed.seed_id,
            knowledge_domain=domain_name,
            model_size=target_size,
            actual_params=model.actual_params,
            memory_mb=model.memory_footprint_mb,
            generation_time_ms=gen_time,
            inference_time_ms=inf_time,
            total_time_ms=total_time,
            system_specs=self.specs.to_dict(),
            seed_size_bytes=seed_bytes,
            seed_to_model_ratio=f"{seed_bytes}B → {model.memory_footprint_mb:.0f}MB = 1:{ratio:,.0f}",
            lazy_weights_cached=cached,
            storage_saved_pct=storage_saved,
            signature=self.SIGNATURE,
        )

        return result

    def _simulate_inference(self, prompt: str, model: GeneratedModel,
                            seed: DynamicSeed) -> str:
        """Simulate inference (placeholder for real model execution)."""
        domain = seed.knowledge_domain.lower()

        responses = {
            "math": "Let me work through this mathematically. The key insight involves "
                    "breaking down the problem into its fundamental components and applying "
                    "the appropriate mathematical framework. I can see several approaches here...",
            "code": "I'll generate clean, efficient code for this. The optimal solution "
                    "balances readability with performance, using well-established patterns "
                    "and avoiding common pitfalls...",
            "creative": "In the space between thought and expression, your prompt opens "
                        "a door to countless possibilities. Let me explore the most "
                        "compelling path through this creative landscape...",
            "science": "From a scientific perspective, this question touches on fundamental "
                       "principles. Let me trace the causal chain from first principles "
                       "through the relevant mechanisms to a clear explanation...",
            "history": "Looking at this through the lens of history, we can see patterns "
                       "that echo across time. The context of this question spans multiple "
                       "eras and civilizations...",
            "philosophy": "This is a profound question that philosophers have grappled with "
                          "for millennia. Let me examine it through several philosophical "
                          "frameworks to provide a nuanced perspective...",
            "language": "Languages are living systems that evolve with their speakers. "
                        "Let me address this with attention to the nuances of grammar, "
                        "usage, and cultural context...",
            "music": "Music is the language of emotion, structured by mathematics and "
                     "brought to life by human expression. Let me explore the musical "
                     "dimensions of your question...",
            "biology": "Life is an intricate dance of molecules, cells, and systems. "
                       "Let me trace the biological principles at work here, from the "
                       "molecular to the organismal level...",
            "technology": "Technology evolves at an accelerating pace. Let me break down "
                          "the technical concepts involved and explain how they fit into "
                          "the broader technological landscape...",
            "health": "Health is a holistic state that encompasses body, mind, and "
                      "environment. Let me address your question with evidence-based "
                      "medical knowledge and practical considerations...",
            "business": "In the dynamic world of business, success comes from understanding "
                        "both the strategic landscape and the operational details. Let me "
                        "analyze this from multiple business perspectives...",
            "education": "Learning is a journey of discovery. Let me structure this "
                         "explanation to build understanding step by step, connecting "
                         "new concepts to familiar foundations...",
        }

        # Find best matching response
        best_response = ("Let me think about this carefully. Based on my knowledge, "
                         "I can provide a thoughtful and comprehensive response to your question.")

        for key, response in responses.items():
            if key in domain:
                best_response = response
                break

        # Add model size context
        size_context = (
            f"\n\n[Generated from seed {seed.seed_id[:8]} at {model.target_size} "
            f"({model.actual_params/1e6:.0f}M params) — {model.memory_footprint_mb:.0f}MB memory]"
        )

        return best_response + size_context

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "version": self.VERSION,
            "signature": self.SIGNATURE,
            "inference_count": self.inference_count,
            "total_inference_time_ms": self.total_inference_time,
            "avg_inference_time_ms": (self.total_inference_time / max(self.inference_count, 1)),
            "current_model_size": self.current_model.target_size if self.current_model else None,
            "current_model_params": self.current_model.actual_params if self.current_model else None,
            "current_seed_size": self.current_seed.seed_size_bytes if self.current_seed else None,
            "system_specs": self.specs.to_dict() if self.specs else None,
        }

    def print_banner(self):
        """Print the engine banner."""
        print(f"\n{'='*62}")
        print(f"  RAWRXD SIZELESS INFERENCE ENGINE")
        print(f"  The Never Ending Intelligence Engine")
        print(f"  Version: {self.VERSION}  |  Signed: {self.SIGNATURE}")
        print(f"  It's not sharding. It's not quantization. It's SIZELESS.")
        print(f"  The model has no size. It BECOMES the size you need.")
        print(f"{'='*62}")
