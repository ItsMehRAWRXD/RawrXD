# IDE GPU policy retest

```ini
SOURCE_SHA=578788a3f600cc64a26d00af81f09ba19a28caaa
EXECUTABLE_SHA256=02B76B62CE49A1A486E690CFD6DDEDC255053545E1C51101A2005AE79D6CD395
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
RAWRXD_GPU_POLICY=SOLO
SERVERLESS_CHAT=PASS
VULKAN_INITIALIZED=1
VULKAN_ENABLED=1
GPU_DEVICES=1
GPU_PLAN_ACTIVE=0
GPU_PLAN_SLOTS=0/0
GPU_DISPATCHES=0
GPU_FORWARD_REAL=0
```

Explicit SOLO policy reduced the opened device set to one but did not activate the fit plan or resident forward path. The next blocker is inside model-fit admission/commit, not GPU policy selection.
