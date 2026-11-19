# IDE GPU fit admission versus forward activation

```ini
SOURCE_SHA=578788a3f600cc64a26d00af81f09ba19a28caaa
EXECUTABLE_SHA256=C5176E9EC359F42260D6787D640FDA3F400CE96FEBDC6334014126B5CD61F08C
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
RAWRXD_GPU_POLICY=SOLO
BUILD=PASS
SERVERLESS_CHAT=PASS
VULKAN_INITIALIZED=1
VULKAN_ENABLED=1
GPU_FIT_ACCEPTED=1
GPU_FIT_LANE=GPU_SINGLE
GPU_PLAN_ACTIVE=0
GPU_PLAN_SLOTS=0/0
GPU_DISPATCHES=0
GPU_FORWARD_REAL=0
```

The authoritative fit plan now reports `GPU_SINGLE`, so admission is successful. The remaining failure is after admission: the resident forward plan is not activated and generation records no GPU work. This is the next source-level boundary; the run does not justify claiming GPU IDE inference.
