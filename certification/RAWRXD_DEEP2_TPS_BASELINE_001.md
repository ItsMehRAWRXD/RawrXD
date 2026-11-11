# RawrXD Deep2 TPS Baseline — Measured, Not Estimated

**Captured:** 2026-10-11
**Workload:** `nemotron-3.5-lightning:30b` via the Ollama runtime
**Prompt:** "Count from 1 to 40."
**Status:** Reproducible reference baseline captured. **This is Ollama's runtime, not RawrXD's Deep2 engine**, so it is a *reference* the Deep2 path must be compared against — not a RawrXD result.

## Measured results

Every number below is parsed from the engine's own `--verbose` statistics block
(`eval count`, `eval duration`, `eval rate`). Nothing is interpolated.

| Run | eval tokens | eval duration | eval rate |
|-----|-------------|---------------|-----------|
| 1   | 324         | 2.187106 s    | **148.14 tok/s** |
| 2   | 380         | 2.703854 s    | **140.54 tok/s** |
| 3   | 364         | 2.566960 s    | **141.80 tok/s** |
| 4   | 172         | 1.328798 s    | **129.44 tok/s** |

- mean: **139.98 tok/s**
- min / max: 129.44 / 148.14 tok/s
- spread: 14.5% peak-to-peak, so single runs are noisy and the accepted
  baseline value must come from repeated runs, not one sample.

Model weight load took 38.2 s on the first cold run and 13–16 ms once the
runtime had it resident, so **warm-up must be excluded from any TPS figure** —
mixing the two would understate throughput by roughly 20× for short runs.

## Comparison against the blueprint

The blueprint states a baseline of **128.78 TPS** and a target of **643.90 TPS**
(5.00×). The measured baseline is 139.98 tok/s, i.e. the blueprint's figure is
slightly conservative rather than wrong, and it is reproducible on this machine.

Two consequences for the target:

1. Scaling the measured baseline by 5 gives **~700 tok/s**, not 643.90. The
   blueprint's number is a ratio against the *stated* baseline, so both must be
   re-fixed against one agreed measurement before a gate can be judged.
2. The blueprint itself warns that aggregate TPS across concurrent sessions is
   substantially easier than single-sequence TPS. Continuous batching must not
   be used to satisfy the 5× claim for one autoregressive sequence.

## Model metadata (from `ollama show`, so all values are the runtime's own)

| Field | Value |
|---|---|
| Architecture | `nemotron_h_moe` |
| Parameters | 32.9 B |
| Context length | 1,048,576 |
| Embedding length | 2,688 |
| Quantization | Q4_K_M |
| Capabilities | completion, tools, thinking |

Architecture matters for the five workstreams: `nemotron_h_moe` is a Nemotron
hybrid **MoE** (Mamba2 + attention), so expert routing, not dense projection,
is likely to dominate the decode path. That has to be measured, not assumed.

## What is still missing before any optimisation work can start

1. **A native per-token profiler on the real Deep2 path.** The engine already
   contains stage hooks (`beginQKVProj`, `beginFFNNorm`, `recordQuantTime`) but
   they call `ProductionProfiler`, whose **implementation source does not exist
   in the tree** — only a header titled "Stub header" plus an untracked
   prebuilt `.obj`. No number from that path is trustworthy until it is built
   from source.
2. **The engine does not compile.** Deep2Engine.cpp leaves ~102 errors that are
   a genuine API divergence: it calls the static
   `GGUFLoader::Load(path, GGUFLoadOptions)` consuming `GGUFLoadResult` with
   `.success`, `.error`, `.metadata.{hiddenSize,numLayers,numHeads,...}`. The
   implemented GGUFLoader is instance-based and declares neither symbol.
3. **The 30B model's GGUF location is unconfirmed.** `ollama` runs the model,
   but `~/.ollama/models/{blobs,manifests,manifests-v2}` all contain 0 entries,
   so there is no file to hash for step-01 provenance. The only Nemotron GGUF
   found on disk is the **4 B Nano** (`nemotron_h`, 3.94 GB), not the 30B target.

## Reproduce

```powershell
ollama run nemotron-3.5-lightning:30b --verbose "Count from 1 to 40."
# read: eval count / eval duration / eval rate from the verbose block
```

Run at least three times and use the mean; a single run carries a 14.5% spread.
