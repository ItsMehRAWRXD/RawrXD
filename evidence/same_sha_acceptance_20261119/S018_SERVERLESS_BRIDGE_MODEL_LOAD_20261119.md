# S018 — Serverless Deep2 bridge model load

Date: 2026-11-19  
Source evidence: `evidence/TOP25_C08_C09_DEEP2.log`

## Observed result

The existing in-process probe loaded the exact local GGUF and completed a
generation without an HTTP inference server:

```text
init=1 load=1 gen=1 gen_len=27
model=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
Backend: Deep2Engine (GPU forward active)
GPU Forward Real: 1
GPU Forward Q4K Ops: 1072
GPU Forward Q6K Ops: 168
GPU Forward Fallbacks: 0
GPU Vulkan Submissions: 8
GPU Queue Submits (actual): 248
GPU Devices: 1
GPU Fit Accepted: 1
GPU Fit Lane: GPU_SINGLE
```

The model identity is retained in the log and the response artifact hash is
`9CBAE7F8896D83EB3A81E4EE3D0AEB842A3195D3F66260B5DE7F077866F86C3A`.
The log hash is
`6CC74D4CA50C84620E21173D289E8D584B7EE1C9219D85B38DE35A8F09A67485`.

## Scope and limitation

This closes the model-load evidence for the serverless bridge and records real
GPU-forward counters from the retained probe. It is not a fresh run against
the S016 source commit: the current native IDE executable is still the
pre-S016 locked binary, SHA
`6DAAAA50459BE130DCB9EF1A74967BF803BA23433CAEC2890DB0870F5F6E56A`.

Fresh executable rebuild/runtime retest remains open because the IDE linker
was blocked by that running/locked artifact.

```ini
SERVERLESS_MODEL_LOAD=PASS_REPORTED
MODEL_IDENTITY=PASS
HTTP_INFERENCE_REQUIRED=NO
GPU_FORWARD_COUNTERS=RETAINED_PASS
FRESH_S016_EXECUTABLE=NOT_AVAILABLE
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
