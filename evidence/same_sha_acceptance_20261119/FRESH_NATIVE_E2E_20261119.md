# Fresh native E2E recovery result

## Source and build

```ini
SOURCE_SHA=fd3ab5d84191de822f82b19525953e017c12d3f3
BRANCH=evidence/quantized-tinyllama-parity-20261119
BUILD_DIR=build_e2e_recovery_20261119
CMAKE_CONFIGURE=PASS
TARGET=RawrXD-Win32IDE-Native
EXECUTABLE=build_e2e_recovery_20261119/bin/Release/RawrXD-Win32IDE-Native.exe
EXECUTABLE_SHA256=62AF30DB416244326C3AA811EBAF60B54A6AAF6729A8A2ECF7EA4B495F9179B7
EXECUTABLE_BYTES=2710528
```

## GUI request

The fresh executable launched successfully. The prompt was entered through the production input control `1202`, and the actual transcript control `1203` displayed a nonempty response. The response was explicitly identified by the IDE as `Ollama: response received`; the model selector remained `Local models / Ollama / bigdaddyg-productivity-local:latest`.

Therefore this is a GUI response PASS but a Deep2 GPU E2E FAIL for this run: the request was routed to Ollama, not the native Deep2 bridge. No request-attributable Deep2 Vulkan dispatch witness was observed.

```ini
FRESH_GUI_LAUNCH=PASS
INPUT_CONTROL=1202
TRANSCRIPT_CONTROL=1203
TRANSCRIPT_RESPONSE=PASS
BACKEND=OLLAMA
NATIVE_DEEP2_BRIDGE=NOT_REACHED
GPU_DISPATCH_WITNESS=NOT_OBSERVED
SERVERLESS_DEEP2_GUI_E2E=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
