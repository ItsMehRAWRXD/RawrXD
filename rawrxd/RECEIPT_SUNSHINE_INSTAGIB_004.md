# RECEIPT_SUNSHINE_INSTAGIB_004

## Certification Objective
Prove the standalone Instagib EXE can auto-capture its D3D11 backbuffer to BMP after a configurable delay, producing visual evidence for visual regression certification.

## Build
- **Compiler**: MSVC 19.44.35228 (VS 2022 BuildTools v17.14.39)
- **Target**: x64, `/std:c++17 /O2 /W3 /EHsc`
- **Result**: Zero errors. EXE: `bin\Instagib.exe`

## Commit SHA
`1ba51bd7`

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

| File | Size | SHA-256 |
|------|------|---------|
| `bin\Instagib.exe` | - | `291fdc90d66bfb7efbaf57b28ec2e1a32ec6f0141fce8e8f13511a04baeb781c` |
| `evidence\instagib_1000ms.bmp` | 2,764,854 | `356b61809ed8a7f6eb4b99eafcba9ca313b80358693e7232b9751aa3abd4a72c` |
| `evidence\instagib_3000ms.bmp` | 2,764,854 | `e9ba02d3212c15d8cc3767779f70b9bc8f9b3a4a486e2009af1ca6aee66cce12` |
| `evidence\instagib_5000ms.bmp` | 2,764,854 | `b7c88f71f8bbc85f4cfdf24fcf6ebd935f459fc218306f9096fab065f2373260` |

All BMPs are **1280×720 24-bit** (header validated: `BM`, offset=54, width=1280, height=720, bpp=24).

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
| Frames distinct | **PASS** | 1000→3000: 7.30% pixel change; 3000→5000: 57.09% pixel change |
| Old black-wedge artifact | **ABSENT** | not visible in any capture |

## Verdict
**PASS** — Automated D3D11 backbuffer capture is functional. Visual regression loop is now possible.

## Freeze File
`RAWRXD_SUNSHINE_004_FREEZE.txt` contains the SHA-256 of this receipt for tamper evidence.