# S054 GPU command dependency batching audit

The retained R9700/RX7800XT benchmark receipts show the current decode path records one wait per submission (`2955` submits and `2955` waits for the 16-token run). The counter-semantics receipt also confirms that the reported Vulkan-submission and dispatch counters are aliased, so they must not be treated as independent submission counts.

Existing retained benchmark evidence:

- R9700 rebuilt run: `gpu_calls=3460`, `submits=3265`, `waits=3265`, `cpu_calls=0`.
- RX7800XT rebuilt run: `gpu_calls=3460`, `submits=3265`, `waits=3265`, `cpu_calls=0`.
- The benchmark reports separate host-wait and device-timeline fields.

This establishes the instrumentation boundary and a serialization hotspot, but it is not a fresh A/B proof of dependency batching on the current executable. No command-scheduling change is made in this sprint.

```ini
S054=BASELINE_CAPTURED_RUNTIME_AB_OPEN
GPU_FALLBACKS=0_IN_RETAINED_REBUILT_RUNS
SUBMISSION_WAIT_SERIALIZATION=OBSERVED
COUNTER_ALIASING=DOCUMENTED
CURRENT_SHA_AB=NOT_RUN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
