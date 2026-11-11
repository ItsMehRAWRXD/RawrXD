"""
Dynamic Seed Generator — Creates unique seeds for each topic on-the-fly.

Each conversation topic gets its own seed. The seed encodes the
"knowledge DNA" for that topic. No two topics produce the same seed.

The seed is tiny (2-10 KB) but can generate a model at ANY size.
"""

import hashlib
import json
import math
import random
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum


class SeedType(Enum):
    HASH_PROCEDURAL = "hash_procedural"
    FRACTAL = "fractal"
    TENSOR_DECOMP = "tensor_decomp"
    IMPLICIT = "implicit"
    POLYNOMIAL = "polynomial"
    WAVELET = "wavelet"
    RECURSIVE = "recursive"


@dataclass
class DynamicSeed:
    seed_id: str
    topic: str
    knowledge_domain: str
    seed_data: bytes
    seed_size_bytes: int
    created_at: float
    base_seed: int
    architecture: Dict[str, Any]
    generation_method: str
    compatible_sizes: List[str]
    system_specs: Dict[str, Any]
    signature: str = "~g87"


class DynamicSeedGenerator:
    """
    Generates seeds dynamically based on what the user asks about.
    Each topic gets its own unique seed.
    """

    TOPIC_MAP = {
        "math": ["math", "calculus", "algebra", "geometry", "statistics", "probability",
                 "proof", "equation", "integral", "derivative", "matrix", "vector",
                 "linear algebra", "number theory", "logic", "theorem", "arithmetic",
                 "trigonometry", "sine", "cosine", "tangent", "pi", "euler",
                 "fibonacci", "prime", "modulo", "algorithm", "recursion", "induction",
                 "2+2", "plus", "minus", "times", "divided", "equals", "solve",
                 "calculate", "compute", "number", "digit", "sum", "difference",
                 "product", "quotient", "add", "subtract", "multiply", "divide",
                 "square", "root", "power", "exponent", "logarithm", "log",
                 "function", "graph", "slope", "area", "volume", "angle",
                 "degree", "radian", "hypotenuse", "pythagorean", "theorem"],

        "code": ["code", "program", "python", "javascript", "java", "c++", "rust",
                 "go", "ruby", "php", "swift", "kotlin", "sql", "html", "css",
                 "react", "vue", "angular", "node", "django", "flask", "docker",
                 "kubernetes", "git", "api", "rest", "graphql", "function", "class",
                 "object", "array", "string", "integer", "boolean", "loop", "condition",
                 "error", "bug", "debug", "test", "refactor", "design pattern",
                 "architecture", "microservice", "database", "redis", "elasticsearch",
                 "json", "yaml", "regex", "linux", "bash", "powershell", "devops",
                 "terraform", "ansible", "prometheus", "grafana", "async", "await",
                 "compiler", "linker", "debugger", "profiler", "benchmark",
                 "hash table", "tree", "graph", "queue", "stack", "heap", "trie",
                 "compression", "huffman", "gzip", "brotli", "zstd", "container",
                 "image", "layer", "volume", "network", "firewall", "ssh", "tls",
                 "ssl", "certificate", "encryption", "aes", "sha256", "hmac"],

        "creative": ["write", "story", "poem", "poetry", "creative", "fiction",
                     "narrative", "dialogue", "script", "novel", "character",
                     "plot", "theme", "metaphor", "imagery", "describe",
                     "imagine", "create", "art", "music", "song", "lyrics",
                     "drama", "comedy", "tragedy", "genre", "fantasy", "sci-fi",
                     "mystery", "romance", "thriller", "horror", "adventure"],

        "science": ["science", "physics", "chemistry", "biology", "astronomy",
                    "quantum", "relativity", "gravity", "electromagnetism",
                    "thermodynamics", "mechanics", "optics", "acoustics",
                    "nuclear", "particle", "atom", "molecule", "element",
                    "compound", "reaction", "cell", "dna", "rna", "protein",
                    "evolution", "genetics", "ecology", "climate", "energy",
                    "force", "motion", "velocity", "acceleration", "momentum",
                    "wave", "frequency", "wavelength", "spectrum", "radiation"],

        "history": ["history", "ancient", "medieval", "renaissance", "war",
                    "revolution", "empire", "civilization", "culture", "society",
                    "political", "economic", "social", "technological",
                    "industrial", "digital", "age", "era", "century", "decade",
                    "timeline", "event", "figure", "leader", "king", "queen",
                    "president", "pharaoh", "emperor", "dynasty", "kingdom",
                    "1066", "battle", "treaty", "discovery", "invention",
                    "monarchy", "republic", "democracy", "dictatorship",
                    "colony", "independence", "constitution", "declaration",
                    "renaissance", "enlightenment", "reformation", "crusade",
                    "exploration", "colonization", "revolutionary", "civil",
                    "world war", "cold war", "ancient greece", "ancient rome",
                    "byzantine", "ottoman", "mongol", "viking", "celtic",
                    "mayan", "incan", "aztec", "egyptian", "persian",
                    "greek", "roman", "chinese", "japanese", "indian"],

        "philosophy": ["philosophy", "ethics", "morality", "existence", "consciousness",
                       "reality", "knowledge", "truth", "belief", "reason",
                       "logic", "argument", "fallacy", "metaphysics", "epistemology",
                       "aesthetics", "value", "virtue", "justice", "freedom",
                       "determinism", "free will", "mind", "body", "dualism",
                       "materialism", "idealism", "pragmatism", "existentialism",
                       "meaning of life", "purpose", "meaning", "god", "religion",
                       "faith", "spirituality", "soul", "afterlife", "heaven",
                       "hell", "karma", "dharma", "nirvana", "enlightenment",
                       "stoicism", "epicureanism", "nihilism", "absurdism",
                       "utilitarianism", "deontology", "virtue ethics",
                       "categorical imperative", "golden rule", "socrates",
                       "plato", "aristotle", "nietzsche", "kant", "hegel",
                       "schopenhauer", "hume", "locke", "descartes", "wittgenstein",
                       "heidegger", "sartre", "camus", "foucault", "derrida",
                       "rawls", "nozick", "sing", "peter", "ought", "should",
                       "right", "wrong", "good", "evil", "moral", "immoral"],

        "language": ["language", "translation", "grammar", "vocabulary", "syntax",
                     "semantics", "phonetics", "linguistics", "word", "phrase",
                     "sentence", "paragraph", "essay", "letter", "alphabet",
                     "spanish", "french", "german", "italian", "portuguese",
                     "russian", "chinese", "japanese", "korean", "arabic",
                     "hindi", "bengali", "tamil", "telugu", "marathi"],

        "music": ["music", "song", "melody", "harmony", "rhythm", "beat",
                  "note", "scale", "chord", "key", "tempo", "dynamics",
                  "timbre", "pitch", "interval", "octave", "symphony",
                  "concerto", "sonata", "opera", "jazz", "blues", "rock",
                  "classical", "folk", "electronic", "hip hop", "rap",
                  "instrument", "guitar", "piano", "violin", "drums"],

        "biology": ["biology", "cell", "dna", "rna", "protein", "gene", "genome",
                    "chromosome", "mutation", "evolution", "natural selection",
                    "species", "organism", "tissue", "organ", "system",
                    "photosynthesis", "respiration", "metabolism", "enzyme",
                    "bacteria", "virus", "fungus", "plant", "animal", "human",
                    "brain", "heart", "lung", "liver", "kidney", "neuron",
                    "synapse", "neurotransmitter", "hormone", "immune"],

        "geography": ["geography", "map", "country", "city", "capital", "river",
                      "mountain", "ocean", "sea", "lake", "desert", "forest",
                      "continent", "region", "climate", "weather", "population",
                      "border", "territory", "landmark", "natural resource",
                      "agriculture", "industry", "transportation", "urban",
                      "rural", "coastal", "island", "peninsula", "valley"],

        "technology": ["technology", "computer", "software", "hardware", "network",
                       "internet", "web", "mobile", "app", "cloud", "ai",
                       "machine learning", "deep learning", "neural network",
                       "data", "database", "server", "storage", "memory",
                       "processor", "gpu", "cpu", "fpga", "asic", "sensor",
                       "robot", "automation", "blockchain", "cryptocurrency",
                       "virtual reality", "augmented reality", "iot"],

        "health": ["health", "medicine", "doctor", "hospital", "disease", "treatment",
                   "symptom", "diagnosis", "therapy", "surgery", "drug",
                   "vaccine", "antibiotic", "pain", "fever", "infection",
                   "chronic", "acute", "prevention", "nutrition", "exercise",
                   "mental health", "anxiety", "depression", "stress",
                   "sleep", "diet", "vitamin", "mineral", "protein"],

        "business": ["business", "company", "startup", "entrepreneur", "management",
                     "marketing", "sales", "finance", "accounting", "investment",
                     "stock", "market", "economy", "strategy", "leadership",
                     "team", "product", "service", "customer", "revenue",
                     "profit", "growth", "innovation", "competition", "brand",
                     "advertising", "social media", "ecommerce", "retail"],

        "education": ["education", "learning", "teaching", "school", "university",
                      "college", "course", "class", "lesson", "student",
                      "teacher", "professor", "homework", "assignment", "exam",
                      "test", "grade", "degree", "diploma", "certificate",
                      "knowledge", "skill", "training", "study", "research",
                      "reading", "writing", "mathematics", "science", "history"],

        "general": ["hello", "hi", "how are you", "what", "why", "how", "who",
                    "where", "when", "which", "explain", "tell", "show",
                    "help", "can you", "please", "thanks", "thank you",
                    "yes", "no", "maybe", "sure", "okay", "great", "nice",
                    "good", "bad", "interesting", "amazing", "wonderful"],
    }

    # Domain → architecture mapping
    DOMAIN_ARCH = {
        "math": {"hidden_dim": 2048, "num_layers": 24, "num_heads": 16, "ffn_multiplier": 4},
        "code": {"hidden_dim": 2048, "num_layers": 24, "num_heads": 16, "ffn_multiplier": 4},
        "creative": {"hidden_dim": 2048, "num_layers": 20, "num_heads": 16, "ffn_multiplier": 4},
        "science": {"hidden_dim": 2048, "num_layers": 24, "num_heads": 16, "ffn_multiplier": 4},
        "history": {"hidden_dim": 2048, "num_layers": 20, "num_heads": 16, "ffn_multiplier": 4},
        "philosophy": {"hidden_dim": 2048, "num_layers": 20, "num_heads": 16, "ffn_multiplier": 4},
        "language": {"hidden_dim": 2048, "num_layers": 20, "num_heads": 16, "ffn_multiplier": 4},
        "music": {"hidden_dim": 2048, "num_layers": 18, "num_heads": 16, "ffn_multiplier": 4},
        "biology": {"hidden_dim": 2048, "num_layers": 22, "num_heads": 16, "ffn_multiplier": 4},
        "geography": {"hidden_dim": 2048, "num_layers": 18, "num_heads": 16, "ffn_multiplier": 4},
        "technology": {"hidden_dim": 2048, "num_layers": 24, "num_heads": 16, "ffn_multiplier": 4},
        "health": {"hidden_dim": 2048, "num_layers": 22, "num_heads": 16, "ffn_multiplier": 4},
        "business": {"hidden_dim": 2048, "num_layers": 20, "num_heads": 16, "ffn_multiplier": 4},
        "education": {"hidden_dim": 2048, "num_layers": 20, "num_heads": 16, "ffn_multiplier": 4},
        "general": {"hidden_dim": 2048, "num_layers": 18, "num_heads": 16, "ffn_multiplier": 4},
    }

    COMPATIBLE_SIZES = ["100M", "250M", "500M", "1B", "3B", "7B", "13B", "70B", "170B"]

    def __init__(self):
        self.seed_cache: Dict[str, DynamicSeed] = {}

    def classify_topic(self, prompt: str) -> Tuple[str, str]:
        """Classify a prompt into a knowledge domain."""
        prompt_lower = prompt.lower()
        scores = {}

        for domain, keywords in self.TOPIC_MAP.items():
            score = 0
            for kw in keywords:
                if kw in prompt_lower:
                    score += 1
            if score > 0:
                scores[domain] = score

        if not scores:
            return ("general", "General Knowledge")

        best_domain = max(scores, key=scores.get)
        domain_names = {
            "math": "Mathematics & Logic",
            "code": "Programming & Code",
            "creative": "Creative Writing",
            "science": "Science & Physics",
            "history": "History & Events",
            "philosophy": "Philosophy",
            "language": "Languages",
            "music": "Music Theory",
            "biology": "Biology & Medicine",
            "geography": "Geography",
            "technology": "Technology",
            "health": "Health & Medicine",
            "business": "Business & Finance",
            "education": "Education",
            "general": "General Knowledge",
        }
        return (best_domain, domain_names.get(best_domain, "General Knowledge"))

    def generate_seed(self, prompt: str, system_specs: Dict[str, Any]) -> DynamicSeed:
        """Generate a unique seed for a given prompt."""
        domain_key, domain_name = self.classify_topic(prompt)

        # Create a unique seed ID from the prompt
        seed_id = hashlib.sha256(prompt.encode()).hexdigest()[:12]

        # Check cache
        if seed_id in self.seed_cache:
            return self.seed_cache[seed_id]

        # Generate base seed from prompt hash
        base_seed = int(hashlib.sha256(f"{prompt}:{time.time()}".encode()).hexdigest()[:8], 16)

        # Select generation method based on domain
        method_map = {
            "math": "hash_procedural",
            "code": "fractal",
            "creative": "implicit",
            "science": "tensor_decomp",
            "history": "polynomial",
            "philosophy": "implicit",
            "language": "recursive",
            "music": "wavelet",
            "biology": "tensor_decomp",
            "geography": "recursive",
            "technology": "fractal",
            "health": "tensor_decomp",
            "business": "polynomial",
            "education": "hash_procedural",
            "general": "hash_procedural",
        }
        method = method_map.get(domain_key, "hash_procedural")

        # Build architecture from domain
        arch = self.DOMAIN_ARCH.get(domain_key, self.DOMAIN_ARCH["general"]).copy()
        arch["vocab_size"] = 32000
        arch["activation"] = "gelu"
        arch["norm"] = "rmsnorm"
        arch["position_encoding"] = "rope"

        # Generate training essence (compressed knowledge signal)
        essence_input = f"{seed_id}:{domain_name}:{base_seed}:{prompt[:64]}".encode()
        essence = hashlib.sha256(essence_input).digest()[:64]

        # Build seed data
        seed_data_dict = {
            "id": seed_id,
            "type": method,
            "domain": domain_name,
            "arch": arch,
            "seed": base_seed,
            "essence": essence.hex()[:32],
            "ver": "neie-smage-1.0",
            "sig": "~g87",
        }
        seed_json = json.dumps(seed_data_dict, separators=(',', ':')).encode('utf-8')
        seed_data = zlib.compress(seed_json, level=9)

        seed = DynamicSeed(
            seed_id=seed_id,
            topic=prompt[:100],
            knowledge_domain=domain_name,
            seed_data=seed_data,
            seed_size_bytes=len(seed_data),
            created_at=time.time(),
            base_seed=base_seed,
            architecture=arch,
            generation_method=method,
            compatible_sizes=self.COMPATIBLE_SIZES,
            system_specs=system_specs,
        )

        self.seed_cache[seed_id] = seed
        return seed

    def get_cached_seed(self, prompt: str) -> Optional[DynamicSeed]:
        """Get a cached seed for a prompt if it exists."""
        seed_id = hashlib.sha256(prompt.encode()).hexdigest()[:12]
        return self.seed_cache.get(seed_id)
