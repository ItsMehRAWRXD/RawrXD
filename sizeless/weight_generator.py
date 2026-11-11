"""
Lazy Weight Generator — Generates model weights on-the-fly from a seed.

Instead of storing billions of floats, we store the RULES to generate them.
Each weight is deterministically derived from (layer, row, col, seed) via SHA-256.

This means:
  - Same seed + same position = same weight (always)
  - Different seed = completely different model
  - No storage needed — weights are COMPUTED, not STORED
  - The model has no size. It BECOMES the size you need.
"""

import hashlib
import math
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable, Iterator


@dataclass
class GeneratedLayer:
    name: str
    layer_type: str
    shape: Tuple[int, ...]
    weights: Any = None
    param_count: int = 0
    is_lazy: bool = True


@dataclass
class GeneratedModel:
    seed_id: str
    target_size: str
    actual_params: int
    layers: List[GeneratedLayer]
    config: Dict[str, Any]
    generation_time_ms: float
    memory_footprint_mb: float
    knowledge_domain: str = ""

    def info(self) -> str:
        return (f"Model[{self.target_size}] "
                f"{self.actual_params / 1e6:.0f}M params "
                f"{self.memory_footprint_mb:.0f}MB "
                f"({self.knowledge_domain})")


class LazyWeights:
    """
    Lazy weight container — generates weights on-access.
    This is what makes the model "sizeless."
    """

    def __init__(self, seed_id: str, layer_name: str, shape: Tuple[int, ...],
                 base_seed: int, method: str = "hash_procedural"):
        self.seed_id = seed_id
        self.layer_name = layer_name
        self._shape = shape
        self._base_seed = base_seed
        self._method = method
        self._cache: Dict[Tuple[int, ...], float] = {}
        self._total_size = 1
        for s in shape:
            self._total_size *= s

    def __getitem__(self, indices) -> float:
        if isinstance(indices, int):
            indices = (indices,)
        if indices in self._cache:
            return self._cache[indices]
        value = self._generate_at(indices)
        self._cache[indices] = value
        return value

    def _generate_at(self, indices: Tuple[int, ...]) -> float:
        """Generate a single weight value at specific indices."""
        key = f"{self.layer_name}:{indices[0]}:{indices[1] if len(indices) > 1 else 0}:{self._base_seed}"
        hash_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        raw = struct.unpack('I', hash_bytes[:4])[0]
        normalized = (raw / 0xFFFFFFFF) * 2.0 - 1.0
        scale = math.sqrt(6.0 / max(indices[0] + (indices[1] if len(indices) > 1 else 0) + 2, 1))
        return normalized * scale

    def to_eager(self) -> List[float]:
        """Convert lazy weights to eager (fully materialized)."""
        result = []
        if len(self._shape) == 1:
            for i in range(self._shape[0]):
                result.append(self[i])
        elif len(self._shape) == 2:
            for i in range(self._shape[0]):
                for j in range(self._shape[1]):
                    result.append(self[(i, j)])
        return result

    @property
    def shape(self) -> Tuple[int, ...]:
        return self._shape

    @property
    def size(self) -> int:
        return self._total_size

    @property
    def cached_count(self) -> int:
        return len(self._cache)

    @property
    def storage_saved_pct(self) -> float:
        if self._total_size == 0:
            return 0.0
        return (1 - len(self._cache) / self._total_size) * 100


class WeightGenerator:
    """Generates model weights from a seed at any requested scale."""

    SIZE_PRESETS = {
        "100M":  (100_000_000,   768,  12,  12),
        "250M":  (250_000_000,  1024,  16,  16),
        "500M":  (500_000_000,  1280,  20,  20),
        "1B":    (1_000_000_000, 2048,  24,  16),
        "3B":    (3_000_000_000, 3200,  32,  32),
        "7B":    (7_000_000_000, 4096,  32,  32),
        "13B":   (13_000_000_000, 5120, 40, 40),
        "70B":   (70_000_000_000, 8192, 80, 64),
        "170B":  (170_000_000_000, 12288, 96, 96),
    }

    def __init__(self, seed_id: str, base_seed: int, architecture: Dict[str, Any],
                 method: str = "hash_procedural"):
        self.seed_id = seed_id
        self.base_seed = base_seed
        self.architecture = architecture
        self.method = method

    def generate(self, target_size: str = "1B", lazy: bool = True) -> GeneratedModel:
        """Generate a model at the requested size."""
        start = time.time()

        if target_size not in self.SIZE_PRESETS:
            raise ValueError(f"Unknown size: {target_size}")

        target_params, hidden_dim, num_layers, num_heads = self.SIZE_PRESETS[target_size]
        arch = self.architecture
        
        # For small models (< 1B), use preset dimensions directly
        # For larger models, blend with seed architecture
        if target_params <= 1_000_000_000:
            # Use preset values for small models
            pass  # hidden_dim, num_layers, num_heads already correct
        else:
            # For larger models, use seed architecture as reference
            hidden_dim = max(hidden_dim, arch.get("hidden_dim", hidden_dim))
            num_layers = max(num_layers, arch.get("num_layers", num_layers))
            num_heads = max(num_heads, arch.get("num_heads", num_heads))
        
        head_dim = hidden_dim // num_heads
        vocab_size = arch.get("vocab_size", 32000)
        ffn_dim = hidden_dim * arch.get("ffn_multiplier", 4)

        layers = []
        actual_params = 0

        # Embedding
        emb = self._make_layer("embedding", "embedding", (vocab_size, hidden_dim), lazy)
        layers.append(emb)
        actual_params += emb.param_count

        # Transformer layers
        for i in range(num_layers):
            layer_params = 0
            sub_weights = {}
            weight_shapes = {
                f"q_weight": (hidden_dim, hidden_dim),
                f"k_weight": (hidden_dim, hidden_dim),
                f"v_weight": (hidden_dim, hidden_dim),
                f"o_weight": (hidden_dim, hidden_dim),
                f"ffn_up_weight": (hidden_dim, ffn_dim),
                f"ffn_down_weight": (ffn_dim, hidden_dim),
                f"norm1_weight": (hidden_dim,),
                f"norm2_weight": (hidden_dim,),
            }
            for wname, wshape in weight_shapes.items():
                lname = f"layer_{i}_{wname}"
                if lazy:
                    sub_weights[lname] = LazyWeights(
                        self.seed_id, lname, wshape,
                        self.base_seed + i * 1000, self.method
                    )
                layer_params += wshape[0] * (wshape[1] if len(wshape) > 1 else 1)

            layer = GeneratedLayer(
                name=f"layer_{i}", layer_type="transformer",
                shape=(hidden_dim, hidden_dim),
                weights=sub_weights, param_count=layer_params, is_lazy=lazy,
            )
            layers.append(layer)
            actual_params += layer_params

        # Output
        out = self._make_layer("output", "output", (hidden_dim, vocab_size), lazy)
        layers.append(out)
        actual_params += out.param_count

        gen_time = (time.time() - start) * 1000
        bytes_per_param = 2 if lazy else 4
        memory_mb = (actual_params * bytes_per_param) / (1024 * 1024)

        config = {
            "target_size": target_size, "actual_params": actual_params,
            "hidden_dim": hidden_dim, "num_layers": num_layers,
            "num_heads": num_heads, "head_dim": head_dim,
            "vocab_size": vocab_size, "ffn_dim": ffn_dim, "lazy": lazy,
            "method": self.method,
        }

        return GeneratedModel(
            seed_id=self.seed_id, target_size=target_size,
            actual_params=actual_params, layers=layers, config=config,
            generation_time_ms=gen_time, memory_footprint_mb=memory_mb,
        )

    def _make_layer(self, name: str, ltype: str, shape: Tuple[int, ...],
                    lazy: bool) -> GeneratedLayer:
        param_count = shape[0] * (shape[1] if len(shape) > 1 else 1)
        if lazy:
            weights = LazyWeights(self.seed_id, name, shape, self.base_seed, self.method)
        else:
            weights = None
        return GeneratedLayer(
            name=name, layer_type=ltype, shape=shape,
            weights=weights, param_count=param_count, is_lazy=lazy,
        )
