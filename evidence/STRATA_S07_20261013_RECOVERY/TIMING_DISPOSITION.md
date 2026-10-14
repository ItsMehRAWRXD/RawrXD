# S07 measurement disposition

24-token INT8-KV matched pair: token-identical 24/24; zero drafts proposed, accepted or rejected. Drafting was inactive; no acceleration inference.

64-token INT8-KV matched pair: token-identical 64/64; 4 proposals in 1 chain, 0 accepted, 1 rejected. The target token replaced the rejected draft. Both completed with zero CPU fallback and finite final logits. Draft verification acceptance remains unexercised.

Recorded wall-time decode TPS: plain 4.07, speculative 1.52. These timings are NOT certified as an isolated speed comparison. A second deep2_strata_bench.exe process was found concurrently running from D: against the same GPU during this session. GPU occupancy of the earlier windows was not captured, so the paired timings cannot establish a causal speculative speedup/slowdown.

The extra 128-token run from this session was interrupted after discovering contention. Do not count its incomplete transcript as a receipt. The unrelated D: benchmark was left running.

Harness repairs: throughput now includes draft lookup and verification-loop wall time; JSON string fields escape Windows paths correctly. Older receipt files were preserved.

S07: OPEN. Required remaining evidence: exclusive-device matched repeated runs, real accepted drafts, token-stream equivalence, acceptance/rejection accounting, and measured throughput benefit. Current implementation verifies one target token per forward and does not implement batched target verification.

## Final checked pair

Use FINAL_COMPARISON.json and the s07_spec128_checked / s07_plain128_checked_final transcripts and provenance, not the invalid s07_plain128_checked control. Both final runs have explicit empty pre/post Strata process snapshots, no monitor interference, identical executable SHA-256 A684C5C3FC92B9DA6696CE695C7637CF0C6B6B8FFCD791038B873D463DEF3216, and exit 0. Every prefill/decode ExecuteToken result was checked for nonfinite logits by this executable.

Complete output streams: 128/128 identical. Three verification chains produced 12 draft proposals: zero accepted, three verified rejections, nine proposals discarded without verification after the chain broke. Each path used 128 decode target forwards (160 including the shared 32-token prefill). Neither path reported CPU fallback; INT8 KV savings stayed 71.88%.

Plain decode wall time 34267.3 ms (3.74 TPS); speculative 33210.6 ms (3.85 TPS). Measured inference total (ingest/bind + prefill + decode): plain 46329.9 ms, speculative 44969.7 ms. Process-wall observations include monitor polling granularity and startup/teardown: plain 48166.5 ms, speculative 46361.6 ms.

The single pair's decode ratio is 1.0318, but there were no accepted drafts and no reduction in target forwards. It does not certify speculative acceleration; earlier isolated pairs also showed reversed timing direction. Repeated controlled measurements and accepted-draft/batched-verification coverage remain required. S07 remains OPEN.

The speculative receipt's original speedup field references the invalid earlier control (baseline_tps=3.18) and must be ignored. FINAL_COMPARISON.json recomputes the ratio against the valid matching control. Original logs were preserved, not edited.

Isolation monitoring detects the named Strata benchmark processes; it is not proof that every unrelated background application was idle. No Ollama model runner was observed in the process spot check, but the Ollama service was running. No 150 TPS or 671B claim follows from these TinyLlama results.
