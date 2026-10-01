# RAWRXD_B72_MODEL_ADMISSION_CENSUS_001

## Purpose

The first TPS test in this session found four models that would not load. That
was measured against an early binary. This gate re-tests all of them against the
consolidated current binary and classifies each failure as either a **corrupt or
stale artifact** (nothing for the engine to fix) or a **real engine defect**
(architecture support gap or invalid admission logic).

```ini
RAWRXD_B72_MODEL_ADMISSION_CENSUS_001=COMPLETE
EXE_SHA256 = 23916D21D28A91FA95270F8A365E458BDFBBEABCE9E576F22608127CC4CFC83A
GIT_HEAD   = 9b843bf039f917040d1c7aeae4eaa3aea090870d
```

## Result: all four still fail — none was a stale-binary artifact

| Model | Size | Classification | Engine fault? |
|---|---|---|---|
ministral3_q4_0 | 4.84 GB | ARCHITECTURE_NOT_REGISTERED | YES — feature gap |
gemma3-1b-Q2_K | 0.65 GB | OVER_STRICT_ADMISSION_GEOMETRY | YES — invalid invariant |
Codestral-22B-Q4_K_M | 11.79 GB | NUMERICAL_NON_FINITE_AT_22B | YES — correctness defect |
gptoss20b | 12.85 GB | MOE_EXPERT_LAYOUT_UNSUPPORTED | YES — feature gap |
Qwen3.5-40B-Q4_K_M | 6.01 GB | TRUNCATED_ARTIFACT | **NO** |

Four of five are genuine engine gaps. One is a bad file, and it is not the
engine's fault.

## Evidence per model

### 1. ministral3_q4_0 — architecture not registered (FEATURE GAP)

```ini
ROPE_ARCH=mistral3  ROPE_THETA_GLOBAL=1000000.0 SLIDING_WINDOW=0
MODEL ADMISSION REJECTED arch=mistral3 reason=UnknownArchitecture
  field=canonicalName detail=architecture not recognized: mistral3
```

The GGUF parses and its rope parameters are read correctly, so metadata handling
works; the architecture simply has no entry in the admission registry. Nothing
is wrong with the model. Adding support means implementing the forward family,
not fixing a parser.

### 2. gemma3-1b-Q2_K — the admission geometry invariant is invalid (ENGINE BUG)

```ini
MODEL ADMISSION REJECTED arch=gemma3 reason=MalformedMetadata
  field=numHeads*headDim detail=inconsistent
  geometry: numHeads*headDim != hiddenDim
```

The file is a valid GGUF v3 with sane metadata:

```ini
GGUF magic=0x46554747 version=3 tensors=340 kvPairs=31
gemma3.attention.head_count    = 4
gemma3.attention.head_count_kv = 1
```

The rejected invariant `numHeads * headDim == hiddenDim` assumes every
architecture uses the classic MHA geometry where query width equals hidden width.
gemma3 does not: it sets `head_dim` independently of `hidden_size`, so the
identity simply does not hold for it. The model is being rejected for not
satisfying an assumption the architecture was never required to satisfy.

This is a false rejection — the engine cannot load a model it is otherwise
equipped to run, and the guard that rejects it is stricter than the format
requires.

### 3. Codestral-22B-Q4_K_M — non-finite output at 22B (CORRECTNESS DEFECT)

```ini
admission      = OK
geometry       = 56 layers, hidden 6144
generated=0 promptTokens=13 prefillMs=0.0 decodeMs=0.0
               cancelled=0 completed=0 status=4
```

Status 4 is `InternalError`, raised at prefill token 0. This is the
`LinearW: non-finite output` defect observed in the original TPS test and it is
unchanged. It is the highest-severity item here: per
`RAWRXD_QK_PROJECTION_PARITY_BACKEND_GATE`, no backend may execute until
Q/K/V projection parity holds, and this fails inside the projection path.

### 4. gptoss20b — MoE expert tensor layout unsupported (FEATURE GAP)

```ini
GGUF load failed: unsupported/malformed GGML tensor type or shape
  blk.0.ffn_down_exps.weight
```

The `_exps` suffix denotes fused MoE expert tensors. The loader rejects them at
parse time. A real capability gap, not a defect.

### 5. Qwen3.5-40B-Q4_K_M — the file is truncated (NOT AN ENGINE DEFECT)

```ini
file_bytes            = 6,448,907,579  (6.01 GB)
declared parameters   = 40B
Q4_K_M is ~4.8 bits/weight => expected ~24 GB
IMPLIED_BITS_PER_WEIGHT = 1.29
GGUF magic=0x46554747 version=3 tensors=1275
```

The header is valid and declares 1275 tensors, but the file is ~1.29 bits per
declared parameter — roughly a quarter of a Q4_K_M file. The engine's diagnostic
is exactly right:

```ini
GGUF tensor range outside mapped shard: blk.19.ffn_up.weight
```

The tensor table promises data past the end of the mapping. This is a truncated
download. No engine change can make it load, and attempting to would mean
reading unmapped memory. **This model should be excluded from test matrices, not
"fixed."**

## Common signature worth noting

Every failing run prints:

```ini
[INIT] Deep2Engine::initialize hiddenDim=0 vocabSize=0 numLayers=0 numHeads=0
```

Geometry is zero at `initialize()` time in all cases, including the ones that
go on to read rope parameters correctly. So admission is rejecting models
before geometry has been populated into engine config, and the gemma3 rejection
in particular may be a symptom of `headDim` never being filled in rather than a
wrong formula. That is the first thing to check before "fixing" the invariant —
relaxing the guard without populating geometry would let a genuinely malformed
model through.

## What is worth doing, in order

```ini
1. B73  investigate Codestral non-finite at 22B
        correctness, blocks the Q/K/V parity gate
2. B74  trace gemma3 headDim population vs the admission invariant
        do NOT simply relax the guard until the geometry source is confirmed
3.      register mistral3 / gptoss MoE layouts
        feature work, per-architecture
SKIP   Qwen3.5-40B — replace the file
```

## Scope

This gate certifies only the re-test and classification above against the
hashed binary. It does not certify any other dirty-tree change, and it makes no
claim that any of these models now works. None of them does.

```ini
B72_COMMITTED=NO
B72_PUSHED=NO
```