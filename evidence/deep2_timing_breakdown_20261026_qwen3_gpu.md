# Deep2 timing breakdown — Qwen3 Q4_K_M GPU witness

This receipt records the timing instrumentation already exposed by
`QuantDot::BackendCounters()` and the production `deep2_bench_tps` path. It is
not a performance certification or a model-quality certification.

## Provenance

- Source root: `F:\rawrxd`
- Branch: `fix/deep2-multimodel-safety-20261025`
- Source HEAD at inspection: `9fa781fe811d391359f999f121bfdebe8eaf3aa0`
- Benchmark: `F:\rawrxd\tools\deep2_bench_tps.exe`
- Benchmark SHA-256: `4E0CC7717BDA23887E2BE58130DB7AEBD21B1A3F2660BBBDE691CD8F03978813`
- Model: `F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf`
- Model SHA-256: `713D3A7A93F306763A6DE2B5E9F9350E3AEEE3BBFE8C3EE0066B61939FEAA332`
- Backend: Vulkan-native, device index `0`, AMD Radeon AI PRO R9700
- Environment: `DEEP2_GPU_FORWARD_TRACE=1`, `DEEP2_KV_F32=1`
- Command: `deep2_bench_tps.exe --model <model> --tokens "1 185" --decode 3 --runs 1 --device 0`
- Raw log: `F:\rawrxd\tmp_build\timing_qwen3_gpu_20261026.log`

## Observed result

The run exited `0`, produced finite logits, completed with zero in-flight GPU
descriptor sets, and reported zero CPU calls or fallbacks.

| Boundary | Wall / device evidence |
|---|---:|
| Model bind (excluded from TPS) | 20,114.1 ms |
| Prefill, 2 positions | 8,571.2 ms wall |
| Prefill device timeline | 2,796.9 ms |
| Prefill host fence wait | 3,043.5 ms |
| Prefill submit recording | 12.4 ms / 543 submits |
| Decode, 2 forward passes | 2,900.7 ms wall |
| Decode device timeline | 2,703.0 ms |
| Decode host fence wait | 2,753.1 ms |
| Decode submit recording | 8.3 ms / 290 submits |
| Decode throughput | 0.689 tokens/s |
| Executor GPU operations | 1,012 |
| CPU operations / fallbacks | 0 / 0 |
| Weight-cache hits / misses | 759 / 253 |
| Host-to-device upload | 4,475.8 MB |
| Device memory live / peak | 4,454.8 / 4,454.8 MB |

The benchmark emitted `gpu_time_share=47.9%` for the combined prefill+decode
wall interval. Decode alone was `93.2%` device-time share by the benchmark's
reported timeline. The `kernel_ms` and `wait_ms` counters are host-wait aliases
in this implementation; `gpu_ms` is the device timestamp timeline. These
figures overlap and must not be added as independent wall-clock buckets.

## Reverse-engineered bottleneck

1. **Submission recording is not the bottleneck.** Submit time was 20.7 ms
   across prefill and decode, while the combined wall interval was 11,471.9 ms.

2. **Decode is serialized around completed GPU work.** Each decode forward pass
   took about 1,450 ms wall, with about 1,351.5 ms of device timeline and about
   1,376.6 ms of host fence wait. This is consistent with one-token-at-a-time
   execution and synchronization, not a queue-submission storm.

3. **The current benchmark is per-position, not batched prefill.** It executes
   `ExecuteToken` once for each prompt token. The two prompt positions produced
   543 submits, while the two decode positions produced 290 submits. The
   executor recorded 253 GPU operations per position (`1012 / 4`).

4. **Residency is materially active but not yet the dominant measured decode
   cost.** 253 first-use misses uploaded about 4.38 GiB; 759 later dispatches
   were served by cache hits. A warm-cache multi-run witness is still needed
   before assigning the remaining decode time to residency misses.

## Correct next optimization experiment

Run the same binary, model, tokens, device, and decode count with one cold run
and at least one warm run. Compare only the prefill/decode boundary deltas,
cache misses, upload bytes, `gpu_ms`, and `wait_ms`. Then compare a separate
batched-prefill witness. Do not infer a 10% gain from GPU dispatch counts or
from bind time.

Current evidence establishes a real GPU execution and a timing breakdown. It
does not establish numerical parity, sustained quality, dual-GPU execution,
or the requested performance target.

## Label-semantics rerun

After correcting the timing labels, the same command was rebuilt and rerun
against the same model. The updated executable was:

- Benchmark SHA-256: `98BB125A1904543F1C725A86F11BBF2BDC1012B7D043B238DE328F25B4A00205`
- Raw log: `F:\rawrxd\tmp_build\timing_qwen3_gpu_20261026_labels.log`
- Exit: `0`

The rerun reported `device_gpu_ms=5456.5`, `host_wait_ms=6238.2`,
`submit_ms=20.4`, and `legacy_kernel_ms_is_host_wait=6238.2`. It completed
with `gpu_calls=1012`, `cpu_calls=0`, finite logits, and zero in-flight
descriptor sets. The wall-time variation between the two short runs is
expected for a cold, per-position witness; it is not a performance trend.
