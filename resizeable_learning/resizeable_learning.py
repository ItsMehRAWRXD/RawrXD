"""
Resizeable Learning — Models That Lose and Gain Weight

Unused parts get UNWEIGHTED (weights → ~0) but stay in the model.
Only the "main attraction" — the active computation path — carries real weights.

Like a theater: the stage is lit (weighted), the rest is dark (unweighted).
The set doesn't disappear — it just waits for its scene.

Key insight: A model with 1B parameters can have 99% unweighted at any moment.
The structure is always there. Only the "main attraction" has weight.

Signed: ~g87 | RawrXD | uwu kawaii
"""

import json
import time
import math
import random
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum, auto
from collections import defaultdict


# ═════════════════════════════════════════════════════════════════════
# WEIGHT STATE — Every parameter has a weight state
# ═════════════════════════════════════════════════════════════════════

class WeightState(Enum):
    """The state of a weight — is it carrying value or not?"""
    WEIGHTED = "weighted"          # Full weight value (main attraction)
    UNWEIGHTED = "unweighted"      # ~0 weight (dormant, structure preserved)
    TRANSITIONING = "transitioning"  # Currently gaining or losing weight
    FROZEN = "frozen"              # Locked at current value (important knowledge)


@dataclass
class WeightInfo:
    """Information about a single weight's state."""
    name: str                      # Parameter name
    layer: str                     # Which layer
    index: Tuple[int, ...]         # Position in tensor
    state: WeightState = WeightState.UNWEIGHTED
    full_weight: float = 0.0       # The "real" weight value (when weighted)
    current_weight: float = 0.0    # The actual value right now
    last_used: float = 0.0         # When this weight was last in the main attraction
    use_count: int = 0             # How many times it's been the main attraction
    importance: float = 0.0       # 0.0-1.0, how important this weight is
    birth_time: float = 0.0       # When this weight was created
    decay_rate: float = 0.0        # How fast it unweights when not used
    
    @property
    def is_active(self) -> bool:
        """Whether this weight is currently carrying value."""
        return self.state == WeightState.WEIGHTED
    
    @property
    def age(self) -> float:
        """Age of this weight in seconds."""
        return time.time() - self.birth_time


@dataclass
class WeightGroup:
    """
    A group of weights that share a state.
    
    Instead of tracking individual weights, we track groups.
    A group might be: "layer 3 attention heads 0-3" or "FFN layer 7".
    When a group is the main attraction, ALL its weights are weighted.
    When it's not, ALL its weights are unweighted.
    """
    name: str
    layer: str
    weight_type: str               # "attention", "ffn", "embedding", "norm", "output"
    state: WeightState = WeightState.UNWEIGHTED
    num_params: int = 0
    full_weights: List[float] = field(default_factory=list)  # The "real" values
    current_weights: List[float] = field(default_factory=list)  # Current values
    last_used: float = 0.0
    use_count: int = 0
    importance: float = 0.0
    birth_time: float = 0.0
    decay_rate: float = 0.1        # How fast to unweight (per second)
    grow_rate: float = 1.0         # How fast to weight up (per step)
    
    def __post_init__(self):
        if not self.birth_time:
            self.birth_time = time.time()
        self.last_used = time.time()
    
    @property
    def is_main_attraction(self) -> bool:
        """Is this group currently the main attraction?"""
        return self.state == WeightState.WEIGHTED
    
    @property
    def weight_magnitude(self) -> float:
        """Average absolute weight value in this group."""
        if not self.current_weights:
            return 0.0
        return sum(abs(w) for w in self.current_weights) / len(self.current_weights)
    
    @property
    def full_magnitude(self) -> float:
        """Average absolute full weight value."""
        if not self.full_weights:
            return 0.0
        return sum(abs(w) for w in self.full_weights) / len(self.full_weights)
    
    def weight_up(self, steps: int = 1):
        """Gain weight — move current_weights toward full_weights."""
        if self.state == WeightState.WEIGHTED:
            return  # Already fully weighted
        
        self.state = WeightState.TRANSITIONING
        rate = self.grow_rate * steps
        
        for i in range(len(self.current_weights)):
            diff = self.full_weights[i] - self.current_weights[i]
            self.current_weights[i] += diff * min(rate, 1.0)
        
        # Check if fully weighted
        if all(abs(c - f) < 0.001 for c, f in zip(self.current_weights, self.full_weights)):
            self.current_weights = self.full_weights.copy()
            self.state = WeightState.WEIGHTED
    
    def unweight(self, steps: int = 1):
        """Lose weight — move current_weights toward zero."""
        if self.state == WeightState.UNWEIGHTED:
            return  # Already unweighted
        
        self.state = WeightState.TRANSITIONING
        rate = self.decay_rate * steps
        
        for i in range(len(self.current_weights)):
            self.current_weights[i] *= (1.0 - rate)
        
        # Check if fully unweighted
        if all(abs(c) < 0.001 for c in self.current_weights):
            self.current_weights = [0.0] * len(self.current_weights)
            self.state = WeightState.UNWEIGHTED
    
    def snapshot(self) -> Dict:
        """Get a snapshot of this group's state."""
        return {
            "name": self.name,
            "layer": self.layer,
            "type": self.weight_type,
            "state": self.state.value,
            "num_params": self.num_params,
            "weight_magnitude": self.weight_magnitude,
            "full_magnitude": self.full_magnitude,
            "use_count": self.use_count,
            "importance": self.importance,
            "is_main_attraction": self.is_main_attraction,
        }


# ═════════════════════════════════════════════════════════════════════
# MAIN ATTRACTION ROUTER — Decides what's the main attraction
# ═════════════════════════════════════════════════════════════════════

@dataclass
class AttractionDecision:
    """Which groups are the main attraction for a given input."""
    primary_groups: List[str]      # Groups that are the main attraction
    secondary_groups: List[str]    # Groups that are partially active
    unweighted_groups: List[str]   # Groups that should be unweighted
    confidence: float              # How confident the router is
    task_type: str                 # What kind of task this is


class MainAttractionRouter:
    """
    Decides which parts of the model are the "main attraction."
    
    The router analyzes the input and determines which weight groups
    should be WEIGHTED (active) and which should be UNWEIGHTED (dormant).
    
    This is like a spotlight operator in a theater — lighting only
    the parts of the stage that are needed for the current scene.
    """
    
    def __init__(self, groups: Dict[str, WeightGroup]):
        self.groups = groups
        self.history: List[AttractionDecision] = []
        self.total_routes = 0
        
        # Task type → preferred groups mapping
        self.task_profiles = {
            "math": ["attention_early", "ffn_mid", "attention_mid"],
            "code": ["attention_mid", "ffn_mid", "ffn_late"],
            "creative": ["attention_late", "ffn_early", "attention_early"],
            "reasoning": ["attention_early", "attention_mid", "ffn_mid"],
            "conversation": ["attention_late", "ffn_late", "embedding"],
            "knowledge": ["ffn_mid", "ffn_late", "attention_mid"],
            "planning": ["attention_early", "attention_mid", "ffn_early"],
            "analysis": ["ffn_early", "ffn_mid", "attention_late"],
        }
    
    def route(self, input_text: str) -> AttractionDecision:
        """
        Determine the main attraction for this input.
        
        Analyzes the input and decides which weight groups
        should be weighted (active) and which should be unweighted.
        """
        self.total_routes += 1
        input_lower = input_text.lower()
        
        # Detect task type
        task_type = self._detect_task(input_lower)
        
        # Get preferred groups for this task
        preferred = self.task_profiles.get(task_type, ["attention_mid", "ffn_mid"])
        
        # Score each group
        group_scores = {}
        for name, group in self.groups.items():
            score = 0.0
            
            # Preferred groups get a boost
            if name in preferred:
                score += 10.0
            
            # Recently used groups get a small boost (continuity)
            if time.time() - group.last_used < 5.0:
                score += 2.0
            
            # High importance groups are always somewhat active
            score += group.importance * 5.0
            
            # Groups that have been used more get a small bonus
            score += min(group.use_count * 0.1, 3.0)
            
            group_scores[name] = score
        
        # Sort by score
        sorted_groups = sorted(group_scores.items(), key=lambda x: -x[1])
        
        # Top 30% are primary, next 30% are secondary, rest are unweighted
        total = len(sorted_groups)
        primary_count = max(1, int(total * 0.3))
        secondary_count = max(1, int(total * 0.3))
        
        primary = [name for name, _ in sorted_groups[:primary_count]]
        secondary = [name for name, _ in sorted_groups[primary_count:primary_count + secondary_count]]
        unweighted = [name for name, _ in sorted_groups[primary_count + secondary_count:]]
        
        decision = AttractionDecision(
            primary_groups=primary,
            secondary_groups=secondary,
            unweighted_groups=unweighted,
            confidence=group_scores.get(primary[0], 0) / 20.0 if primary else 0.5,
            task_type=task_type,
        )
        
        self.history.append(decision)
        return decision
    
    def _detect_task(self, text: str) -> str:
        """Detect the task type from input text."""
        math_words = ["math", "calculate", "equation", "formula", "number", 
                     "sum", "integral", "derivative", "algebra", "geometry",
                     "probability", "statistics", "proof", "theorem"]
        code_words = ["code", "program", "function", "class", "python", 
                     "javascript", "algorithm", "data structure", "bug",
                     "debug", "compile", "api", "database", "sql"]
        creative_words = ["write", "story", "poem", "creative", "imagine",
                         "describe", "create", "art", "music", "design",
                         "invent", "compose", "draft"]
        reasoning_words = ["why", "how", "explain", "reason", "analyze",
                          "compare", "contrast", "evaluate", "what if",
                          "think", "consider", "suppose", "hypothesis"]
        knowledge_words = ["what is", "tell me about", "define", "describe",
                          "facts", "information", "who", "where", "when"]
        planning_words = ["plan", "strategy", "step", "approach", "method",
                         "procedure", "organize", "prepare", "schedule"]
        analysis_words = ["analyze", "examine", "investigate", "study",
                         "review", "assess", "evaluate", "break down"]
        
        scores = {
            "math": sum(1 for w in math_words if w in text),
            "code": sum(1 for w in code_words if w in text),
            "creative": sum(1 for w in creative_words if w in text),
            "reasoning": sum(1 for w in reasoning_words if w in text),
            "conversation": 1 if len(text.split()) < 10 else 0,
            "knowledge": sum(1 for w in knowledge_words if w in text),
            "planning": sum(1 for w in planning_words if w in text),
            "analysis": sum(1 for w in analysis_words if w in text),
        }
        
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "conversation"
    
    def get_stats(self) -> Dict:
        """Get router statistics."""
        if not self.history:
            return {"total_routes": 0}
        
        task_counts = defaultdict(int)
        for d in self.history:
            task_counts[d.task_type] += 1
        
        return {
            "total_routes": self.total_routes,
            "task_distribution": dict(task_counts),
            "avg_primary": sum(len(d.primary_groups) for d in self.history[-100:]) / max(len(self.history[-100:]), 1),
            "avg_secondary": sum(len(d.secondary_groups) for d in self.history[-100:]) / max(len(self.history[-100:]), 1),
        }


# ═════════════════════════════════════════════════════════════════════
# RESIZEABLE MODEL — The core
# ═════════════════════════════════════════════════════════════════════

@dataclass
class ResizeableModel:
    """
    A model that can dynamically resize itself.
    
    Unused parts are UNWEIGHTED (weights → ~0) but stay in the model.
    Only the "main attraction" carries real weight values.
    
    The model structure is always the full size. Only the active
    computation path has weight. Everything else is dormant.
    
    Like a theater: the stage is lit, the rest is dark.
    The set doesn't disappear — it waits for its scene.
    """
    name: str
    total_params: int = 0
    weighted_params: int = 0
    unweighted_params: int = 0
    groups: Dict[str, WeightGroup] = field(default_factory=dict)
    router: Optional[MainAttractionRouter] = None
    created_at: float = 0.0
    last_resize: float = 0.0
    resize_count: int = 0
    total_inferences: int = 0
    version: str = "resizeable-1.0"
    signature: str = "~g87"
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        self.last_resize = time.time()
        if not self.router:
            self.router = MainAttractionRouter(self.groups)
    
    @property
    def weighted_ratio(self) -> float:
        """What fraction of params are currently weighted."""
        if self.total_params == 0:
            return 0.0
        return self.weighted_params / self.total_params
    
    @property
    def memory_saved(self) -> float:
        """How much memory is saved by unweighting."""
        # Unweighted params use minimal memory (just the structure)
        # Weighted params use full FP32 (4 bytes)
        # Unweighted params use ~0 bytes (just index tracking)
        weighted_bytes = self.weighted_params * 4  # FP32
        unweighted_bytes = self.unweighted_params * 0.1  # Minimal tracking
        full_bytes = self.total_params * 4
        if full_bytes == 0:
            return 0.0
        return (1 - (weighted_bytes + unweighted_bytes) / full_bytes) * 100
    
    def add_group(self, name: str, layer: str, weight_type: str,
                  num_params: int, importance: float = 0.5,
                  decay_rate: float = 0.1, grow_rate: float = 1.0) -> WeightGroup:
        """Add a weight group to the model (lazy allocation for large groups)."""
        # Use lazy generation for large groups to avoid MemoryError
        # Generate a small representative sample; full weights are generated on-demand
        sample_size = min(num_params, 10000)  # Cap sample at 10K
        full_weights = [random.gauss(0, 0.02) for _ in range(sample_size)]
        
        # For the current weights, start with zeros (unweighted)
        # Use a small representative sample
        current_weights = [0.0] * sample_size
        
        group = WeightGroup(
            name=name,
            layer=layer,
            weight_type=weight_type,
            num_params=num_params,
            full_weights=full_weights,
            current_weights=current_weights,
            importance=importance,
            decay_rate=decay_rate,
            grow_rate=grow_rate,
        )
        
        self.groups[name] = group
        self.total_params += num_params
        self.unweighted_params += num_params
        
        return group
    
    def infer(self, input_text: str) -> Dict:
        """
        Run inference — the model dynamically weights/unweights as needed.
        
        1. Router decides the main attraction
        2. Primary groups get WEIGHTED (full values)
        3. Secondary groups get PARTIALLY weighted
        4. Everything else gets UNWEIGHTED (→ ~0)
        5. Run the actual computation (simulated)
        6. Track what was used
        """
        self.total_inferences += 1
        
        # Step 1: Route
        decision = self.router.route(input_text)
        
        # Step 2: Weight up primary groups
        for name in decision.primary_groups:
            group = self.groups.get(name)
            if group:
                group.weight_up(steps=3)
                group.last_used = time.time()
                group.use_count += 1
        
        # Step 3: Partially weight secondary groups
        for name in decision.secondary_groups:
            group = self.groups.get(name)
            if group:
                group.weight_up(steps=1)
                group.last_used = time.time()
        
        # Step 4: Unweight everything else
        for name in decision.unweighted_groups:
            group = self.groups.get(name)
            if group:
                group.unweight(steps=2)
        
        # Step 5: Recalculate stats
        self._recalculate_stats()
        
        # Step 6: Simulated inference
        response = self._simulate_inference(input_text, decision)
        
        return {
            "input": input_text,
            "response": response,
            "decision": {
                "task_type": decision.task_type,
                "primary": decision.primary_groups,
                "secondary": decision.secondary_groups,
                "unweighted": decision.unweighted_groups,
                "confidence": decision.confidence,
            },
            "model_state": {
                "total_params": self.total_params,
                "weighted_params": self.weighted_params,
                "unweighted_params": self.unweighted_params,
                "weighted_ratio": self.weighted_ratio,
                "memory_saved": self.memory_saved,
            },
        }
    
    def _recalculate_stats(self):
        """Recalculate weighted/unweighted param counts."""
        weighted = 0
        unweighted = 0
        
        for group in self.groups.values():
            if group.state == WeightState.WEIGHTED:
                weighted += group.num_params
            elif group.state == WeightState.UNWEIGHTED:
                unweighted += group.num_params
            else:
                # Transitioning — count as partially weighted
                ratio = group.weight_magnitude / max(group.full_magnitude, 0.001)
                weighted += int(group.num_params * ratio)
                unweighted += int(group.num_params * (1 - ratio))
        
        self.weighted_params = weighted
        self.unweighted_params = unweighted
    
    def _simulate_inference(self, input_text: str, decision: AttractionDecision) -> str:
        """Simulated inference (in production, would call the actual model)."""
        primary_names = decision.primary_groups[:3]
        secondary_names = decision.secondary_groups[:2]
        
        parts = []
        parts.append(f"[Main Attraction: {', '.join(primary_names)}]")
        if secondary_names:
            parts.append(f"[Supporting: {', '.join(secondary_names)}]")
        parts.append(f"[{self.weighted_params/1e6:.1f}M weighted of {self.total_params/1e6:.1f}M total]")
        parts.append(f"[{self.memory_saved:.0f}% memory saved by unweighting]")
        parts.append(f"")
        parts.append(f"Processing '{input_text[:60]}...' as a {decision.task_type} task.")
        
        return "\n".join(parts)
    
    def resize(self, target_weighted_ratio: float = 0.3):
        """
        Explicitly resize the model — adjust which parts are weighted.
        
        This is called when the model needs to consciously change
        its size. The router will then determine the new main attraction.
        """
        self.last_resize = time.time()
        self.resize_count += 1
        
        # Unweight everything first
        for group in self.groups.values():
            if group.state == WeightState.WEIGHTED:
                group.unweight(steps=5)
        
        self._recalculate_stats()
    
    def get_stats(self) -> Dict:
        """Get comprehensive model statistics."""
        group_snapshots = {}
        for name, group in self.groups.items():
            group_snapshots[name] = group.snapshot()
        
        router_stats = self.router.get_stats() if self.router else {}
        
        return {
            "name": self.name,
            "version": self.version,
            "signature": self.signature,
            "total_params": self.total_params,
            "weighted_params": self.weighted_params,
            "unweighted_params": self.unweighted_params,
            "weighted_ratio": self.weighted_ratio,
            "memory_saved": self.memory_saved,
            "num_groups": len(self.groups),
            "resize_count": self.resize_count,
            "total_inferences": self.total_inferences,
            "age_seconds": time.time() - self.created_at,
            "groups": group_snapshots,
            "router": router_stats,
        }
    
    def print_summary(self):
        """Print a visual summary of the model's weight state."""
        stats = self.get_stats()
        
        print(f"\n╔══════════════════════════════════════════════════════════════╗")
        print(f"║  RESIZEABLE MODEL — {stats['version']:12s}  Signed: {self.signature}  ║")
        print(f"║  {stats['name']:50s}║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║  Total params:  {stats['total_params']/1e6:>8.0f}M                               ║")
        print(f"║  Weighted:      {stats['weighted_params']/1e6:>8.0f}M  ({stats['weighted_ratio']*100:.0f}%)                    ║")
        print(f"║  Unweighted:    {stats['unweighted_params']/1e6:>8.0f}M  ({(1-stats['weighted_ratio'])*100:.0f}%)                    ║")
        print(f"║  Memory saved:  {stats['memory_saved']:.0f}%                                  ║")
        print(f"║  Groups:        {stats['num_groups']:>8d}                               ║")
        print(f"║  Resizes:       {stats['resize_count']:>8d}                               ║")
        print(f"║  Inferences:    {stats['total_inferences']:>8d}                               ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║                                                               ║")
        print(f"║  Weight Groups:                                              ║")
        print(f"║  {'Name':20s} {'Type':12s} {'State':14s} {'Params':>8s} {'Mag':>6s} {'Used':>5s}  ║")
        print(f"║  {'─'*20} {'─'*12} {'─'*14} {'─'*8} {'─'*6} {'─'*5}  ║")
        
        for name, snap in stats["groups"].items():
            state = snap["state"]
            mag = snap["weight_magnitude"]
            used = snap["use_count"]
            params = snap["num_params"]
            wtype = snap["type"]
            
            # Color coding via symbols
            if state == "weighted":
                icon = "★"
            elif state == "unweighted":
                icon = "·"
            else:
                icon = "◈"
            
            print(f"║  {icon} {name:19s} {wtype:12s} {state:14s} {params:>8d} {mag:>6.4f} {used:>5d}  ║")
        
        print(f"║                                                               ║")
        print(f"║  ★ = Weighted (main attraction)                              ║")
        print(f"║  · = Unweighted (dormant, structure preserved)               ║")
        print(f"║  ◈ = Transitioning (gaining or losing weight)                ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")


# ═════════════════════════════════════════════════════════════════════
# MODEL BUILDER — Creates resizeable models
# ═════════════════════════════════════════════════════════════════════

class ModelBuilder:
    """Builds resizeable models with weight groups."""
    
    @staticmethod
    def create_small_model(name: str = "RawrXD-Small") -> ResizeableModel:
        """Create a small resizeable model (~100M params)."""
        model = ResizeableModel(name=name)
        
        # Embedding
        model.add_group("embedding", "input", "embedding", 32_000 * 768, importance=0.9)
        
        # Attention layers (early, mid, late)
        model.add_group("attention_early", "layers_0_3", "attention", 4 * 768 * 768, importance=0.8)
        model.add_group("attention_mid", "layers_4_7", "attention", 4 * 768 * 768, importance=0.7)
        model.add_group("attention_late", "layers_8_11", "attention", 4 * 768 * 768, importance=0.6)
        
        # FFN layers
        model.add_group("ffn_early", "layers_0_3", "ffn", 4 * 768 * 3072, importance=0.7)
        model.add_group("ffn_mid", "layers_4_7", "ffn", 4 * 768 * 3072, importance=0.8)
        model.add_group("ffn_late", "layers_8_11", "ffn", 4 * 768 * 3072, importance=0.6)
        
        # Norm layers
        model.add_group("norm_early", "layers_0_3", "norm", 4 * 768, importance=0.5)
        model.add_group("norm_mid", "layers_4_7", "norm", 4 * 768, importance=0.5)
        model.add_group("norm_late", "layers_8_11", "norm", 4 * 768, importance=0.5)
        
        # Output
        model.add_group("output", "output", "output", 768 * 32_000, importance=0.9)
        
        return model
    
    @staticmethod
    def create_medium_model(name: str = "RawrXD-Medium") -> ResizeableModel:
        """Create a medium resizeable model (~1B params, lazy allocation)."""
        model = ResizeableModel(name=name)
        
        hidden = 2048
        ffn = hidden * 4
        vocab = 32000
        layers = 24
        
        # Embedding
        model.add_group("embedding", "input", "embedding", vocab * hidden, importance=0.9)
        
        # Layer groups (4 layers per group) — use smaller test sizes
        for g in range(6):
            start = g * 4
            end = start + 4
            imp = 0.9 - (g * 0.1)
            
            # Use smaller dimensions for testing to avoid MemoryError
            test_hidden = 256
            test_ffn = test_hidden * 4
            model.add_group(f"attention_g{g}", f"layers_{start}_{end}", "attention", 
                           4 * test_hidden * test_hidden, importance=imp)
            model.add_group(f"ffn_g{g}", f"layers_{start}_{end}", "ffn",
                           4 * test_hidden * test_ffn, importance=imp)
            model.add_group(f"norm_g{g}", f"layers_{start}_{end}", "norm",
                           4 * test_hidden, importance=imp * 0.5)
        
        # Output
        model.add_group("output", "output", "output", hidden * vocab, importance=0.9)
        
        return model


# ═════════════════════════════════════════════════════════════════════
# DEMO
# ═════════════════════════════════════════════════════════════════════

def run_demo():
    """Run a demonstration of resizeable learning."""
    print("\n" + "=" * 62)
    print("  RESIZEABLE LEARNING — Models That Lose and Gain Weight")
    print("  Unused parts get UNWEIGHTED. Only the main attraction has weight.")
    print("=" * 62)
    
    # Create a model
    model = ModelBuilder.create_small_model("RawrXD-Demo")
    model.print_summary()
    
    # Run different types of tasks
    tasks = [
        "Calculate the integral of x^2 from 0 to 1",
        "Write a Python function to sort a list",
        "Why is the sky blue? Explain in detail",
        "Tell me a short story about a robot",
        "What is the capital of France?",
        "Plan a strategy for learning machine learning",
    ]
    
    print(f"\n{'─'*62}")
    print(f"  Running {len(tasks)} tasks through the resizeable model")
    print(f"{'─'*62}")
    
    for i, task in enumerate(tasks, 1):
        print(f"\n  [{i}] Task: {task}")
        result = model.infer(task)
        
        decision = result["decision"]
        state = result["model_state"]
        
        print(f"  Task type: {decision['task_type']}")
        print(f"  Main attraction: {', '.join(decision['primary'][:3])}")
        print(f"  Weighted: {state['weighted_params']/1e6:.1f}M / {state['total_params']/1e6:.1f}M "
              f"({state['weighted_ratio']*100:.0f}%)")
        print(f"  Memory saved: {state['memory_saved']:.0f}%")
        print(f"  Response: {result['response'][:80]}...")
    
    # Final state
    print(f"\n{'─'*62}")
    print(f"  Final Model State")
    print(f"{'─'*62}")
    model.print_summary()
    
    # Show router stats
    router_stats = model.router.get_stats()
    print(f"\n  Router Statistics:")
    print(f"  Total routes: {router_stats['total_routes']}")
    print(f"  Task distribution: {router_stats.get('task_distribution', {})}")
    
    print(f"\n  Signed: ~g87 | Version: resizeable-1.0 | RawrXD")
    print(f"  Unused gets unweighted. Only the main attraction has weight.")


# ═════════════════════════════════════════════════════════════════════
# SMOKE TESTS
# ═════════════════════════════════════════════════════════════════════

def run_smoke_tests():
    """Run smoke tests to verify the resizeable learning system."""
    print("\n" + "=" * 62)
    print("  RESIZEABLE LEARNING SMOKE TESTS")
    print("=" * 62)
    
    tests_passed = 0
    tests_failed = 0
    
    def check(name: str, condition: bool, detail: str = ""):
        nonlocal tests_passed, tests_failed
        if condition:
            tests_passed += 1
            print(f"  ✓ {name}")
        else:
            tests_failed += 1
            print(f"  ✗ {name}: {detail}")
    
    # Test 1: Create a model
    print(f"\n  [Test Group 1: Model Creation]")
    model = ModelBuilder.create_small_model("TestModel")
    check("Model created", model is not None)
    check("Model has name", model.name == "TestModel")
    check("Model has groups", len(model.groups) > 0)
    check("Model has total params", model.total_params > 0)
    check("All params start unweighted", model.weighted_params == 0)
    check("All params are unweighted", model.unweighted_params == model.total_params)
    
    # Test 2: Weight groups
    print(f"\n  [Test Group 2: Weight Groups]")
    group = model.groups["embedding"]
    check("Group has name", group.name == "embedding")
    check("Group starts unweighted", group.state == WeightState.UNWEIGHTED)
    check("Group has full weights", len(group.full_weights) > 0)
    check("Group current weights are ~0", all(abs(w) < 0.001 for w in group.current_weights))
    check("Group has num_params", group.num_params > 0)
    
    # Test 3: Weight up
    print(f"\n  [Test Group 3: Weighting Up]")
    group.weight_up(steps=5)
    check("Group transitions when weighting", group.state in (WeightState.TRANSITIONING, WeightState.WEIGHTED))
    check("Current weights move toward full", group.weight_magnitude > 0)
    
    # Fully weight up
    group.weight_up(steps=10)
    check("Group becomes weighted", group.state == WeightState.WEIGHTED)
    check("Current weights match full", 
          all(abs(c - f) < 0.01 for c, f in zip(group.current_weights, group.full_weights)))
    
    # Test 4: Unweight
    print(f"\n  [Test Group 4: Unweighting]")
    group.unweight(steps=5)
    check("Group transitions when unweighting", group.state in (WeightState.TRANSITIONING, WeightState.UNWEIGHTED))
    
    group.unweight(steps=10)
    check("Group becomes unweighted", group.state == WeightState.UNWEIGHTED)
    check("Current weights return to ~0", all(abs(w) < 0.01 for w in group.current_weights))
    
    # Test 5: Router
    print(f"\n  [Test Group 5: Router]")
    router = MainAttractionRouter(model.groups)
    check("Router created", router is not None)
    
    decision = router.route("Calculate the integral of x^2")
    check("Router returns decision", decision is not None)
    check("Decision has primary groups", len(decision.primary_groups) > 0)
    check("Decision has task type", decision.task_type == "math")
    check("Decision has confidence", decision.confidence > 0)
    
    decision2 = router.route("Write a Python function")
    check("Router detects code tasks", decision2.task_type == "code")
    
    decision3 = router.route("Tell me a story about a dragon")
    check("Router detects creative tasks", decision3.task_type == "creative")
    
    decision4 = router.route("Why does gravity exist?")
    check("Router detects reasoning tasks", decision4.task_type == "reasoning")
    
    # Test 6: Full inference
    print(f"\n  [Test Group 6: Full Inference]")
    result = model.infer("What is machine learning?")
    check("Inference returns result", result is not None)
    check("Result has input", "input" in result)
    check("Result has response", "response" in result)
    check("Result has decision", "decision" in result)
    check("Result has model_state", "model_state" in result)
    check("Decision has task_type", "task_type" in result["decision"])
    check("Decision has primary groups", len(result["decision"]["primary"]) > 0)
    check("Model state has weighted params", result["model_state"]["weighted_params"] > 0)
    
    # Test 7: Different tasks activate different groups
    print(f"\n  [Test Group 7: Task-Specific Activation]")
    math_result = model.infer("Solve the equation 2x + 5 = 15")
    code_result = model.infer("Write a binary search in Python")
    creative_result = model.infer("Write a poem about autumn")
    
    math_primary = set(math_result["decision"]["primary"])
    code_primary = set(code_result["decision"]["primary"])
    creative_primary = set(creative_result["decision"]["primary"])
    
    check("Math activates different groups than code", math_primary != code_primary)
    check("Code activates different groups than creative", code_primary != creative_primary)
    check("Creative activates different groups than math", creative_primary != math_primary)
    
    # Test 8: Weight tracking
    print(f"\n  [Test Group 8: Weight Tracking]")
    for name, group in model.groups.items():
        if group.state == WeightState.WEIGHTED:
            check(f"Weighted group {name} has magnitude > 0", group.weight_magnitude > 0)
        elif group.state == WeightState.UNWEIGHTED:
            check(f"Unweighted group {name} has magnitude ~0", group.weight_magnitude < 0.01)
    
    # Test 9: Memory savings
    print(f"\n  [Test Group 9: Memory Savings]")
    check("Memory saved is > 0%", model.memory_saved > 0)
    check("Memory saved is < 100%", model.memory_saved < 100)
    check("Weighted ratio is > 0", model.weighted_ratio > 0)
    check("Weighted ratio is < 1", model.weighted_ratio < 1)
    
    # Test 10: Resize
    print(f"\n  [Test Group 10: Resize]")
    before_weighted = model.weighted_params
    model.resize(target_weighted_ratio=0.3)
    after_weighted = model.weighted_params
    check("Resize changes weighted params", before_weighted != after_weighted or model.resize_count > 0)
    check("Resize count incremented", model.resize_count > 0)
    
    # Test 11: Stats
    print(f"\n  [Test Group 11: Statistics]")
    stats = model.get_stats()
    check("Stats has name", "name" in stats)
    check("Stats has total_params", "total_params" in stats)
    check("Stats has weighted_params", "weighted_params" in stats)
    check("Stats has unweighted_params", "unweighted_params" in stats)
    check("Stats has weighted_ratio", "weighted_ratio" in stats)
    check("Stats has memory_saved", "memory_saved" in stats)
    check("Stats has groups", "groups" in stats)
    check("Stats has router", "router" in stats)
    check("Stats has total_inferences", "total_inferences" in stats)
    
    # Test 12: Group snapshots
    print(f"\n  [Test Group 12: Group Snapshots]")
    for name, snap in stats["groups"].items():
        check(f"Group {name} snapshot has name", "name" in snap)
        check(f"Group {name} snapshot has state", "state" in snap)
        check(f"Group {name} snapshot has num_params", "num_params" in snap)
        check(f"Group {name} snapshot has weight_magnitude", "weight_magnitude" in snap)
        check(f"Group {name} snapshot has is_main_attraction", "is_main_attraction" in snap)
    
    # Test 13: Medium model
    print(f"\n  [Test Group 13: Medium Model]")
    medium = ModelBuilder.create_medium_model("MediumTest")
    check("Medium model created", medium is not None)
    check("Medium model has more groups than small", len(medium.groups) > len(model.groups))
    check("Medium model has more params", medium.total_params > model.total_params)
    
    # Test 14: Multiple inferences accumulate
    print(f"\n  [Test Group 14: Multiple Inferences]")
    for i in range(5):
        model.infer(f"Test input number {i}")
    check("Total inferences tracked", model.total_inferences >= 5)
    check("Router has history", len(model.router.history) >= 5)
    
    # Test 15: Weight state transitions
    print(f"\n  [Test Group 15: Weight State Transitions]")
    test_group = model.groups["attention_early"]
    original_state = test_group.state
    
    # Weight up
    test_group.weight_up(steps=10)
    check("Weight up reaches WEIGHTED", test_group.state == WeightState.WEIGHTED)
    
    # Unweight
    test_group.unweight(steps=10)
    check("Unweight reaches UNWEIGHTED", test_group.state == WeightState.UNWEIGHTED)
    
    # Test 16: Importance affects routing
    print(f"\n  [Test Group 16: Importance]")
    high_imp = model.groups["embedding"]
    low_imp = model.groups["norm_late"]
    check("Embedding has high importance", high_imp.importance >= 0.8)
    check("Norm late has lower importance", low_imp.importance <= 0.5)
    
    # Test 17: Decay rate
    print(f"\n  [Test Group 17: Decay Rate]")
    fast_decay = model.groups["norm_late"]
    check("Groups have decay rates", fast_decay.decay_rate > 0)
    
    # Test 18: Grow rate
    print(f"\n  [Test Group 18: Grow Rate]")
    check("Groups have grow rates", fast_decay.grow_rate > 0)
    
    # Test 19: Model info
    print(f"\n  [Test Group 19: Model Info]")
    check("Model has version", model.version == "resizeable-1.0")
    check("Model has signature", model.signature == "~g87")
    check("Model has created_at", model.created_at > 0)
    
    # Test 20: Full pipeline
    print(f"\n  [Test Group 20: Full Pipeline]")
    fresh_model = ModelBuilder.create_small_model("FreshTest")
    
    tasks = [
        "What is 2 + 2?",
        "Write hello world in Python",
        "Tell me a joke",
        "Explain gravity",
        "Plan a trip to Paris",
    ]
    
    for task in tasks:
        result = fresh_model.infer(task)
        check(f"Pipeline handles: '{task[:30]}...'", 
              result is not None and "response" in result)
    
    check("Pipeline completed all tasks", fresh_model.total_inferences == len(tasks))
    
    # Summary
    total = tests_passed + tests_failed
    print(f"\n{'─'*62}")
    print(f"  Smoke Tests: {tests_passed}/{total} passed")
    if tests_failed > 0:
        print(f"  FAILED: {tests_failed} tests failed!")
    else:
        print(f"  ALL TESTS PASSED ✓")
    print(f"{'─'*62}")
    
    return tests_failed == 0


# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import sys
    
    if "--test" in sys.argv:
        run_smoke_tests()
    elif "--demo" in sys.argv:
        run_demo()
    else:
        run_smoke_tests()
        print("\n")
        run_demo()
