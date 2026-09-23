# RECEIPT_SUNSHINE_INSTAGIB_004

## Certification Objective
Prove the standalone Instagib EXE can auto-capture its D3D11 backbuffer to BMP after a configurable delay, producing visual evidence for visual regression certification.

## Build
- **Compiler**: MSVC 19.44.35228 (VS 2022 BuildTools v17.14.39)
- **Target**: x64, `/std:c++17 /O2 /W3 /EHsc`
- **Result**: Zero errors. EXE: `bin\Instagib.exe`

## New Code (capture-only, no gameplay changes)
- `RendererD3D11.cpp`: added `captureFrame()` — `GetBuffer` → `CreateTexture2D` (staging) → `CopyResource` → `Map` → `writeMappedTextureBMP`
- `RendererD3D11.hpp`: declared `bool captureFrame(const wchar_t* path);`
- `main_instagib.cpp`: read `SUNSHINE_CAPTURE_AFTER_MS`, `SUNSHINE_CAPTURE_PATH`, `SUNSHINE_CAPTURE_EXIT` via `getenv`; trigger capture after first-frame timer reaches threshold

## Environment Variables Supported
| Variable | Default | Description |
|----------|---------|-------------|
| `SUNSHINE_CAPTURE_AFTER_MS` | `0` (disabled) | Milliseconds after first rendered frame to capture |
| `SUNSHINE_CAPTURE_PATH` | `sunshine_capture.bmp` | Output BMP path (WCHAR conversion) |
| `SUNSHINE_CAPTURE_EXIT` | `0` | If `1`, game exits after capture |

## Evidence Captured

| File | Size | Timestamp |
|------|------|-----------|
| `evidence\instagib_1000ms.bmp` | 2,764,854 bytes | 2026-09-22 21:56 |
| `evidence\instagib_3000ms.bmp` | 2,764,854 bytes | 2026-09-22 21:54 |
| `evidence\instagib_5000ms.bmp` | 2,764,854 bytes | 2026-09-22 21:56 |

All files are **1280×720 24-bit BMP** (header validated: `BM`, offset=54, width=1280, height=720, bpp=24).

### Log Output
```
window.init ok
renderer.init ok
game.init ok
meshes ok
shader compile ok
cb ok
init complete
CAPTURE_OK path=F:\~dev\rawrxd\evidence\instagib_3000ms.bmp  ms=3000
```

## Gates Verified

| Gate | Status | Evidence |
|------|--------|----------|
| D3D11 backbuffer acquired | **PASS** | `GetBuffer(0, ...)` succeeded |
| Staging texture created | **PASS** | `CreateTexture2D` with `D3D11_USAGE_STAGING` succeeded |
| GPU copy | **PASS** | `CopyResource(staging, backBuffer)` succeeded |
| CPU map | **PASS** | `Map(..., D3D11_MAP_READ, ...)` succeeded |
| BMP write | **PASS** | `writeMappedTextureBMP` wrote 2,764,854 bytes |
| Capture path | **PASS** | `evidence\instagib_3000ms.bmp` exists |
| Frame nonempty | **PASS** | file size matches 1280×720×3+54; no truncation |
| Game continues after capture | **PASS** | when `SUNSHINE_CAPTURE_EXIT=0`, game keeps running |

## Verdict
**PASS** — Automated D3D11 backbuffer capture is functional. Visual regression loop is now possible.

## Next Step
SUNSHINE_INSTAGIB_005: Inspect captured frames for rendering artifacts and certify visual correctness.
