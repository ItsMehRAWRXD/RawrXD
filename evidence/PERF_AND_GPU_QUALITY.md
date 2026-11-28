# Deep2 performance + GPU-vs-CPU quality (2026-11-28)

Real measurement on the built `deep2_openai_server.exe` (tinyllama-1.1b-chat Q4_K_M, CPU).

## Throughput (CPU)
```
POST /v1/chat/completions  max_tokens=32
  completion_tokens=32  prompt_tokens=21  elapsed=4.12 s
  => ~7.8 tokens/s (decode incl. prefill)
  content: "In the year 2050, the world was a different place. The skies were filled
            with flying robots, their sleek bodies gle"  (COHERENT)
```
Server log: `[POST /v1/chat/completions] 200  4055.50 ms`.

## Finding: GPU (Vulkan) path produces GARBLED output
Same model, `--vulkan`:
```
content "\nWHEREASPBasedeeding"  (GIBBERISH), 8 tokens / 2.2 s, HTTP 200
```
CPU output is coherent; Vulkan output is garbled. This is a real GPU-path quality/correctness
discrepancy (likely a Vulkan quant-dot / shader dispatch issue), NOT a build defect. Candidate
for a separate Deep2 GPU-kernel correctness fix (cf. Package 9 quant dispatch gaps).

## G15 (150 TPS) status
~7.8 TPS (CPU, tinyllama Q4) is far below the 150 TPS target — consistent with the ledger's
G15 BLOCKED (~4.5 TPS). This is a performance/model gap, not a pipeline defect.

## State
Measured real TPS; identified a GPU-vs-CPU correctness discrepancy. COMMITTED=1 PUSHED=0.
NOT_APPLICABLE: fixing GPU quality / reaching 150 TPS — separate model/kernel/perf workstreams.