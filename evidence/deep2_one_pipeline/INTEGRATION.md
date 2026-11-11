# RAWRXD_DEEP2_ONE_PIPELINE — integration status

One executable: `tools/deep2_pipeline.exe` (build: `tools/build_deep2_pipeline.bat`).

It loads a real GGUF itself — no Deep2 server, no OpenAI-compatible sidecar, no
simulated tokens — and runs the whole pipeline in one process:

```
[1] INGEST     universal_gguf Ingest(): metadata, tensor roles, sha256 provenance
[2] EVIDENCE   imagined<->conceived loop, verifier bound to real tensor bytes
[3] RESIDENCY  ElasticResidencyManager register + lease under a pressure budget
[4] PAGES      flash-frozen versioned publication of the REAL tensor bytes
[5] EXECUTE    runtime graph executor: prefill + decode, quant dispatch GPU/CPU
[6] KV COW     per-step KV pages, session fork, frozen snapshot immutable
[7] FREEZE     validate + deterministic replay, byte-exact vs the model bytes
[8] PERSIST    temp + flush + fsync + atomic rename + read-back verification
[9] RECEIPT    evidence/deep2_one_pipeline/PIPELINE_RECEIPT.txt (fail-closed)
```

## Verified run (this repo, this machine)

| Stage | Evidence |
| --- | --- |
| Model | `tinyllama_tinyllama-1.1b-chat-v1.0` GGUF, 608 MiB, 201 tensors, 22 layers, F32/Q4_0/Q6_K |
| Ingest | `resolved=201`, sha256 `da3087fb…`, arch geometry derived from metadata |
| Bind | `ops_bound=311/311`, `weights_resolved=201/201`, unbound=0 |
| Execution | GPU: `used_gpu=1`, `gpu_calls=1853`, `cpu_calls=0`, `gpu_ms=2030`, `submits=600`, `dev_peak=598 MB` |
| Tokens | real argmax decode with advancing positions (8,9,10,11), text printed |
| Residency | 201 tensors registered; pressure pass forced real evictions (`ghost_hits=45`, `evictions_deferred=171`) |
| Pages | stale-CAS rejected, correct CAS bumped v0→v1→v2, corruption rejected, restore root-equality |
| Byte-exactness | 15/15 replayed pages `memcmp`-equal to the model's own tensor bytes |
| Persistence | 15/15 pages written, fsynced, renamed, read back byte-identical |
| Concurrency | 4/4 independent COW branches validated (own stream per session) |
| Result | **CPU 52/52 PASS**, **GPU 51/51 PASS**, 7.7 s end to end |

```
deep2_pipeline.exe --model <gguf> --decode 4 --pages 24 --budget-frac 0.5 \
    --evidence evidence/deep2_one_pipeline
```

## What is connected, and what is not

| Subsystem | Status |
| --- | --- |
| Concept loop + rainbow concept index | Connected (verifier returns real tensor evidence) |
| Flash-frozen snapshot publication | Connected (over real GGUF tensor bytes) |
| Concurrent coordinator / bridge | Connected (real `RuntimeAdapter` implementation) |
| Runtime graph executor + quant dispatch | Connected (real prefill/decode, GPU receipts) |
| ElasticResidencyManager leases | Connected (real register/acquire/release, evictions) |
| Real GGUF loading | Connected (via `universal_gguf`, memory-mapped) |
| Numerical parity vs llama.cpp | **Not claimed** — no reference logits compared in this run |
| Q2_K / Q3_K native GPU kernels | **Not connected** — those kinds still fall back to CPU by design |
| Concurrent GPU dispatch | **Not exercised** — `--concurrent-gpu` exists but is OFF by default because the G04 `ExecuteQuantDot` deadlock under concurrent prefetch + batch is still open. The run reports it as not exercised rather than claiming it. |
| Multi-agent KV COW | Partially: session fork + distinct roots proven for the page layer; a shared KV *engine* with per-agent copy-on-write of the live cache is not wired |
| GPU synchronization / cross-device replication | Not implemented |
| Emulator VAT/MMIO | Not implemented |
| Durable crash-safe NVMe journaling | Not implemented: pages are durable per file (fsync + rename), but there is no write-ahead log or group commit, so a crash mid-snapshot cannot be rolled forward |

## Honest scope statements

* Nothing here reconstructs information that is not in the model file. A page is
  published from bytes that are already in the GGUF; the frozen snapshot only
  preserves them, and `restore()` never invents missing bytes.
* FNV-1a fingerprints in the prototype are non-cryptographic. The byte-exactness
  checks in stages [4]/[7] are `memcmp` against the source bytes, not a hash
  comparison, so a hash collision could not pass them.
* The verifier in stage [2] rejects a candidate unless the candidate names a
  tensor that exists in this model *and* the page bytes match it exactly.
  Generated hypotheses are therefore never stored as verified model data.
* Token text in the receipt is the model's own vocabulary entry for the argmax
  token; the model is 1.1B and was fed deterministic vocabulary tokens, so the
  emitted text is genuine model output, not fluent English.
* The host `Deep2_FP16_GEMV` fallback compiled into this binary (and the
  residency `Trace*` stubs) exist because `QuantKernelRegistry` and
  `ElasticResidencyManager` reference them at link time. They are only invoked
  when an FP16 tensor is dispatched; the receipt names the path that ran.
