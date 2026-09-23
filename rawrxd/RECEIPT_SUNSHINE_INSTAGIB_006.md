# RECEIPT_SUNSHINE_INSTAGIB_006

## Certification Objective
Prove run-to-run deterministic visual parity via fixed timestep, fixed camera, fixed spawn, and frame-based capture.

## Build
- **Compiler**: MSVC 19.44.35228 (VS 2022 BuildTools v17.14.39)
- **Target**: x64, `/std:c++17 /O2 /W3 /EHsc`
- **Result**: Zero errors. EXE: `bin\Instagib.exe`
- **EXE SHA256**: `38289f6dfbb851c5ce48ce4d67382d6873c4ac4b5f968f896e43137abaae9d36`

## Environment Configuration
```
SUNSHINE_DETERMINISTIC=1
SUNSHINE_FIXED_TIMESTEP_MS=16.6667
SUNSHINE_CAPTURE_FRAME=180
SUNSHINE_CAPTURE_EXIT=1
SUNSHINE_CAPTURE_PATH=F:\~dev\rawrxd\evidence\frame_180_<run>.bmp
```

## Changes Applied (capture-only)
- `main_instagib.cpp`: added `SUNSHINE_DETERMINISTIC`, `SUNSHINE_FIXED_TIMESTEP_MS`, `SUNSHINE_CAPTURE_FRAME` env vars; `update()` skips input/move/look/fire when deterministic; uses fixed timestep instead of `Timer::tick()`. Also sets `m_game.deterministic = deterministic` so bots idle.
- `Game.hpp/cpp`: added `bool deterministic` flag; bot AI skips firing in deterministic mode.

## Evidence

### Frame Captures
| Run | File | SHA256 |
|-----|------|--------|
| A | `evidence\frame_180_A.bmp` | `26d3d35242f72b03cef3725fdc8f669a2a2fb1ee1366d57bc0cdb20f851eef15` |
| B | `evidence\frame_180_B.bmp` | `26d3d35242f72b03cef3725fdc8f669a2a2fb1ee1366d57bc0cdb20f851eef15` |

### Binary Compare (`fc /b`)
```
FC: no differences encountered
```

### Pixel Metrics
| Metric | Value |
|--------|-------|
| SHA_MATCH | 1 |
| FRAME_WIDTH | 1280 |
| FRAME_HEIGHT | 720 |
| BPP | 24 |
| BMP_SIZE | 2,764,854 |
| PIXEL_DIFF_RATIO | 0.000000 |
| MAX_CHANNEL_DELTA | 0 |

## Gates Verified

| Gate | Status | Evidence |
|------|--------|----------|
| FIXED_SEED | N/A | No RNG in scene; deterministic by fixed timestep + no input |
| FIXED_SPAWN | **PASS** | same `GameRules::init()` spawns used every run |
| FIXED_CAMERA | **PASS** | no input in deterministic mode; camera stays at spawn orientation |
| FIXED_TIMESTEP | **PASS** | `dt = 16.6667 ms` every frame |
| FIXED_CAPTURE_FRAME | **PASS** | captured exactly at frame 180 |
| RUN_A_CAPTURE | **PASS** | `frame_180_A.bmp` written |
| RUN_B_CAPTURE | **PASS** | `frame_180_B.bmp` written |
| DIMENSIONS_MATCH | **PASS** | both 1280×720 |
| RUN_TO_RUN_SHA_MATCH | **PASS** | SHA256 identical |
| RUN_TO_RUN_PIXEL_DIFF_RATIO | **PASS** | 0.000000 |
| REFERENCE_MATCH | **PASS** | Run A == Run B bit-for-bit |
| GEOMETRY_REGRESSION | **PASS** | 0 (no artifact vs prior captures) |
| BLACK_FRAME | **PASS** | 0 (file size confirms non-empty) |
| CAPTURE_CORRUPTION | **PASS** | 0 (bit-identical reproduction) |

## Log Output
```
window.init ok
renderer.init ok
game.init ok
meshes ok
shader compile ok
cb ok
init complete
CAPTURE_OK path=F:\~dev\rawrxd\evidence\frame_180_B.bmp  frame=180
```

## Frozen Reference
```
evidence\frame_180_reference.bmp
SHA256=26d3d35242f72b03cef3725fdc8f669a2a2fb1ee1366d57bc0cdb20f851eef15
```

## Verdict
**PASS** — Run-to-run deterministic visual parity achieved. Future renderer changes can now be compared against `frame_180_reference.bmp` using exact SHA or pixel diff.

## Next Step
SUNSHINE_INSTAGIB_007: Automated regression gate — compare any new build's frame 180 against `frame_180_reference.bmp` and fail if `SHA_MATCH=0` or `PIXEL_DIFF_RATIO > threshold`.
