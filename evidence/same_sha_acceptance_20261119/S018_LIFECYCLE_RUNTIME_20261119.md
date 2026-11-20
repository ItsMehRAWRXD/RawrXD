# S018 standalone bridge lifecycle

The dedicated CMake target was added and built in the isolated S019 tree.

```ini
SOURCE_HEAD_BEFORE_BUILD=45d128abb6
BUILD_DIR=F:\rawrxd\build_s019_ltt_20261119
TARGET=deep2_bridge_lifecycle_test
CONFIGURE=PASS
BUILD=PASS
EXECUTABLE=F:\rawrxd\build_s019_ltt_20261119\bin\Release\deep2_bridge_lifecycle_test.exe
EXECUTABLE_SHA256=2130FA1D48694B744C25B491314324A3BA4950E95A68B700474D31EBF5A9FCC0
MODEL=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
MODEL_SHA256=9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0
RUNTIME_EXIT=6
GPU_QUEUE_SUBMITS=202
BRIDGE_STREAM_CHARS=0
GENERATED_TOKENS=0
CPU_FALLBACKS=0
FORWARD_RESULT=FAIL_ZERO_HIDDEN_STATE
LIFECYCLE_ACCEPTANCE=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

The harness reached model load and the bridge worker, but the first request
failed closed at `B3_FAIL prefill hidden state invalid pos=0`; the harness then
returned exit `6` because no token was emitted. Queue submissions were observed,
but `gemv_ok=0`, so this is not a successful GPU inference result.
