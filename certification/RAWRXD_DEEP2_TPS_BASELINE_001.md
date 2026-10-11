# RawrXD Deep2 TPS Baseline -- Measured, Not Estimated

**Captured:** 2026-10-11
**Workload:** `nemotron-3.5-lightning:30b` via the Ollama runtime
**Prompt:** "Count from 1 to 40."
**Status:** Reproducible reference baseline captured. **This is Ollama's runtime, not RawrXD's Deep2 engine**, so it is a *reference* the Deep2 path must be compared against -- not a RawrXD result.

## Step 01 -- baseline frozen, with content verification

The model's real file was located from the runtime's own Modelfile:

```
FROM F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3
```

| Field | Value |
|---|---|
| Path | `F:\OllamaModels\blobs\sha256-5c19f628...` |
| SHA256 | `5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3` |
| Size | 25,430,738,944 bytes (23.68 GiB) |

**The SHA256 matches the filename.** Ollama names blobs by their content digest,
so this is independent confirmation that the hash is the file's real digest and
not a copied value. Hash time was 40.3 s for 23.68 GiB, i.e. a full read rather
than a metadata-only hash.

Note on discovery: the blob has **no file extension**, so any search filtered to
`*.gguf` finds nothing. That is why the model initially appeared absent.

## Step 01 -- architecture metadata, cross-validated

Read by the RawrXD GGUF parser from the file bytes, then compared against the
runtime's own `/api/show` response. All 9 comparable fields agree:

| Field | GGUF parser (from file) | Ollama API (independent) |
|---|---|---|
| architecture | `nemotron_h_moe` | `nemotron_h_moe` |
| context_length | 1,048,576 | 1,048,576 |
| embedding_length | 2,688 | 2,688 |
| block_count (layers) | 53 | 53 |
| attention.head_count | 32 | 32 |
| vocab_size | 131,072 | 131,072 |
| rope.dimension_count | 84 | 84 |
| expert_count | **128** | **128** |
| expert_used_count | **6** | **6** |

Parser also reports 417 tensors and 44 metadata keys from the same file.

### Why the MoE shape decides the optimisation order

| Field | Value | Consequence |
|---|---|---|
| expert_count | 128 | 128 experts, so routing table is large |
| expert_used_count | 6 | only 6 active per token -> 4.7% of experts |
| expert_shared_count | 1 expert, 3712-dim | shared expert always active |
| expert_feed_forward_length | 1856 | per-expert FFN is small |
| ssm (Mamba2) inner_size / state_size | 4096 / 128 | attention AND SSM blocks in the same 53 layers |
| nextn_predict_layers | 1 | speculative next-token layer present |

**128 experts with 6 active per token means expert dispatch and weight
selection dominate, not dense projection.** With only 4.7% of experts active per
token, resident-expert locality is the single highest-leverage target -- a
non-resident expert stall costs far more than compute on the 6 that are used.
Any first optimisation should therefore be measured against routing locality,
not kernel throughput.

## Measured throughput

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

Cold weight load took 38.2 s on the first run and 13-16 ms once resident, so
**warm-up must be excluded from any TPS figure** -- mixing the two understates
throughput by roughly 20x for short runs.

## Comparison against the blueprint

The blueprint states a baseline of **128.78 TPS** and a target of **643.90 TPS**
(5.00x). The measured baseline is 139.98 tok/s, i.e. the blueprint's figure is
slightly conservative rather than wrong, and it is reproducible on this machine.

Two consequences for the target:

1. Scaling the measured baseline by 5 gives **~700 tok/s**, not 643.90. The
   blueprint's number is a ratio against the *stated* baseline, so both must be
   re-fixed against one agreed measurement before a gate can be judged.
2. The blueprint itself warns that aggregate TPS across concurrent sessions is
   substantially easier than single-sequence TPS. Continuous batching must not
   be used to satisfy the 5x claim for one autoregressive sequence.

## What is still missing before any optimisation work can start

1. **A native per-token profiler on the real Deep2 path.** The engine already
   contains stage hooks (`beginQKVProj`, `beginFFNNorm`, `recordQuantTime`) but
   they call `ProductionProfiler`, whose **implementation source does not exist
   in the tree** -- only a header titled "Stub header" plus an untracked
   prebuilt `.obj`. No number from that path is trustworthy until it is built
   from source.
2. **The engine does not compile.** Deep2Engine.cpp leaves ~102 errors that are
   a genuine API divergence: it calls the static
   `GGUFLoader::Load(path, GGUFLoadOptions)` consuming `GGUFLoadResult` with
   `.success`, `.error`, `.metadata.{hiddenSize,numLayers,numHeads,...}`. The
   implemented GGUFLoader is instance-based and declares neither symbol.
3. **Step 01 provenance is now CLOSED** (see above): the 30B file is located,
   hashed, content-verified against its own digest name, and its metadata is
   cross-validated against the runtime. The 4 B Nano GGUF is *not* the target and
   was only a stand-in used before the real blob was found.

## Reproduce

```powershell
# Location + hash
ollama show nemotron-3.5-lightning:30b --modelfile   # read the FROM path
Get-FileHash "<that path>" -Algorithm SHA256

# Metadata from the file itself
tools\build_baseline\gguf_baseline.exe "<that path>"

# Throughput (repeat; a single run carries a 14.5% spread)
ollama run nemotron-3.5-lightning:30b --verbose "Count from 1 to 40."
# read: eval count / eval duration / eval rate from the verbose block
```

Run at least three times and use the mean; a single run cannot judge a gate.
