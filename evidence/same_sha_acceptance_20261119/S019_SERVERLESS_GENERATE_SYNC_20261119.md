# S019 — Serverless Deep2 synchronous generation

Date: 2026-11-19  
Retained request receipt: `evidence/TOP25_C08_C09_DEEP2.log`

## Result

The in-process probe completed `Deep2Bridge::GenerateSync("ping", 8)` after
loading the configured TinyLlama GGUF:

```ini
init=1
load=1
gen=1
gen_len=27
GPU_Forward_Real=1
GPU_GEMV_Dispatches=8
CPU_GEMV_Fallbacks=0
GPU_Vulkan_Submissions=8
GPU_Queue_Submits=248
GPU_Forward_Fallbacks=0
EXIT=0 (reported by the probe receipt)
```

The generated response artifact is 27 bytes and hashes to
`9CBAE7F8896D83EB3A81E4EE3D0AEB842A3195D3F66260B5DE7F077866F86C3A`.
The request log hashes to
`6CC74D4CA50C84620E21173D289E8D584B7EE1C9219D85B38DE35A8F09A67485`.

## Qualification

This is retained runtime evidence from the existing probe, not a fresh
execution against the S016 source commit. The current executable hash is
`6DAAAA50459BE1300DCB9EF1A74967BF803BA23433CAEC2890DB0870F5F6E56A`; a new
link is still blocked by the locked output file.

```ini
SERVERLESS_GENERATE_SYNC=PASS_REPORTED
NONEMPTY_OUTPUT=PASS
GPU_FORWARD=PASS_REPORTED
CPU_FALLBACKS=0
FRESH_EXECUTABLE_RETEST=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
