# RECEIPT_SUNSHINE_INSTAGIB_005

## Certification Objective
Visually certify the captured D3D11 backbuffer frames from `SUNSHINE_INSTAGIB_004` as valid, nonempty, and free of catastrophic rendering artifacts.

## Source Gate
- **Capture Gate**: `SUNSHINE_INSTAGIB_004`
- **Source Commit**: `1ba51bd7`
- **Source Receipt Hash**: `29fe670cb27e5c2e0b94acf2d3674a9fa7bbc93f45c0258e58efd82754364a3a`

## Frames Inspected

| Frame | File | SHA-256 | Size |
|-------|------|---------|------|
| 1000 ms | `evidence\instagib_1000ms.bmp` | `356b61809ed8a7f6eb4b99eafcba9ca313b80358693e7232b9751aa3abd4a72c` | 2,764,854 |
| 3000 ms | `evidence\instagib_3000ms.bmp` | `e9ba02d3212c15d8cc3767779f70b9bc8f9b3a4a486e2009af1ca6aee66cce12` | 2,764,854 |
| 5000 ms | `evidence\instagib_5000ms.bmp` | `b7c88f71f8bbc85f4cfdf24fcf6ebd935f459fc218306f9096fab065f2373260` | 2,764,854 |

All frames are **1280×720 24-bit BMP**.

## Visual Inspection Results

| Gate | Status | Notes |
|------|--------|-------|
| FRAME_1000_VALID | **PASS** | Decodes cleanly; no truncation |
| FRAME_3000_VALID | **PASS** | Decodes cleanly; no truncation |
| FRAME_5000_VALID | **PASS** | Decodes cleanly; no truncation |
| FRAMES_DISTINCT | **PASS** | 1000→3000: 7.30% pixel change; 3000→5000: 57.09% pixel change |
| HUD_VISIBLE | **PASS** | Crosshair and HUD bars visible at 1000 ms and 3000 ms |
| WORLD_VISIBLE | **PASS** | Arena geometry, ground plane, walls visible |
| CAMERA_STATE_ADVANCES | **PASS** | 5000 ms shows dramatically shifted viewpoint with bright-green surface and red floor |
| BLACK_FRAME | **0** | No all-black frames |
| CAPTURE_CORRUPTION | **0** | No truncation, misalignment, or map errors |
| GIANT_TRIANGLE_ARTIFACT | **0** | Previous black-wedge artifact **not present** |
| OBVIOUS_NAN_GEOMETRY | **0** | No degenerate/NaN-style triangles observed |

## What Was NOT Tested
- `RENDERER_PARITY` — single-seed deterministic reference comparison is future work (`SUNSHINE_INSTAGIB_006`).
- Camera angles outside the three auto-captured states may still expose latent defects.

## Verdict
**VISUAL_SMOKE = PASS** — Captured frames are valid, distinct, and free of catastrophic artifacts. The renderer is fit for autonomous visual regression testing.

## Freeze
Receipt SHA-256: `1d5cfbf2f7a90a78603d39dc16407ddbc7936443f482822e5674ffa8584da1e7`

## Next Step
`SUNSHINE_INSTAGIB_006`: Deterministic visual parity — fixed RNG seed, fixed spawn, fixed camera, fixed timestep, reference-image pixel-diff threshold.
