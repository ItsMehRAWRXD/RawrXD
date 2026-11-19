# IDE GPU-forward diagnostic

```ini
SOURCE_SHA=ef8ea5fcd1b178e6e8b593ec7104e405a9c05744
EXECUTABLE_SHA256=02B76B62CE49A1A486E690CFD6DDEDC255053545E1C51101A2005AE79D6CD395
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
SERVERLESS_CHAT=PASS
VULKAN_INITIALIZED=1
VULKAN_ENABLED=1
GPU_PLAN_ACTIVE=0
GPU_PLAN_SLOTS=0/0
GPU_FORWARD_REAL=0
GPU_DISPATCHES=0
CPU_FALLBACKS=0
```

The bridge now distinguishes initialized Vulkan from actual GPU-forward execution. This run proves the unresolved condition is model admission/forward-plan activation (Vulkan is enabled, but the plan is inactive), not Vulkan device discovery. No forced plan or fallback suppression was added.
