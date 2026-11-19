# S015 — Win32IDE Deep2 bridge inventory

Date: 2026-11-19  
Source SHA: `1580afce9bbd83f9d02f4bc0f7e71ed2612d963c`

## Result

The checkout has a real in-process bridge, but it is distributed across
`Win32IDE_Deep2Bridge` and the lifecycle command handler; there is no symbol
named `Win32IDE_Deep2Bridge` (the implementation is `Deep2Bridge`). The model
probe path is configurable through `RAWRXD_DEEP2_PROBE_MODEL` and does not
require an HTTP inference server.

## Verified source path

```
Win32IDE_lifecycle.cpp
  WM_COMMAND / IDM_DEEP2_GGUF_PROBE (9614)
    initializeDeep2Bridge()
    Deep2Bridge::LoadModel(modelPath)
    Deep2Bridge::GenerateSync("ping", 8)
      Deep2Engine::generateText(...)

Win32IDE_Deep2Bridge.cpp
  Deep2Bridge::Initialize()
    Deep2Engine::initialize()
    Deep2Engine::enableVulkan()
  Deep2Bridge::LoadModel()
  Deep2Bridge::GenerateStream()/GenerateSync()
  Deep2Bridge::GetModelInfo()
```

Relevant files inspected:

- `src/win32app/Win32IDE_lifecycle.cpp`
- `src/win32app/Win32IDE_Deep2Bridge.h`
- `src/win32app/Win32IDE_Deep2Bridge.cpp`
- `src/deep2/Deep2Engine.h`
- `src/deep2/Deep2Bridge.hpp` (separate `rawr::Deep2Bridge` API; not the Win32
  bridge used by the probe)

## Existing runtime evidence

`evidence/same_sha_acceptance_20261119/IDE_CHAT_ACCEPTANCE.md` records a real
serverless IDE request against TinyLlama with the HTTP inference server stopped:

```
init=1 load=1 gen=1 gen_len=9
Backend: Deep2Engine (GPU active)
```

The same receipt explicitly corrects the GPU interpretation: the run had
`GPU Cmd Dispatches: 0`, `GPU Queue Submits: 0`, and `GPU Forward Real: 0`.
Therefore this is evidence of in-process Deep2 CPU execution, not GPU-forward
acceptance. The receipt also records the generated response and executable SHA
`823EFF628D361C5D739EA5EC7A1FFFAF9FE564B21EBF696AAFAB92F23CD24231`.

## S015 disposition

```
BRIDGE_SOURCE=FOUND
MODEL_PATH=CONFIGURABLE
HTTP_SERVER_REQUIRED=NO
SERVERLESS_IDE_CHAT=PASS_REPORTED_CPU_PATH
IDE_GPU_FORWARD=OPEN
GPU_DISPATCHES_IN_EXISTING_RECEIPT=0
SOURCE_CHANGE_THIS_SPRINT=NONE
```

No kernel or bridge rewrite is justified by this inventory alone. The next
implementation target is the executor-selection boundary between
`Deep2Engine::generateText/generateStream` and the runtime graph executor:
the IDE bridge opens Vulkan devices, but the exercised request does not enter
the measured GPU-forward path.
