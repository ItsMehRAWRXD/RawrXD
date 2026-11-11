# GPU_STATE — HOST_STABILITY_DIAGNOSTIC_001

Sources: `raw/gpu_pnp.txt`, `raw/dxdiag.txt`

## PnP Display devices (Status)

| FriendlyName | Status |
|--------------|--------|
| Virtual Display Driver | OK |
| AMD Radeon(TM) Graphics (iGPU) | OK |
| AMD Radeon AI PRO R9700 | OK |
| AMD Radeon RX 7800 XT | OK |

## DxDiag (summary)

- Report time: 2026-11-02, 08:24:34 local
- Machine: ASRock X870E Taichi · Ryzen 9 9950X3D2 · 65536 MB RAM
- Display Tab 1/3/4: No problems found
- Display Tab 2 (Virtual Display): unsigned UMDF note (`mttvdd.dll`) — not a TDR proof
- Note: **“DxDiag Previously: Crashed in system information (stage 3)”** — soft historical signal only
- Primary card in report: AMD Radeon AI PRO R9700 · Device Problem Code: No Problem

## Reset / TDR evidence

**None confirmed** in this pass (no Kernel-Power GPU reset events; no WHEA; no dxgkrnl extract).  
WER ProgramData archive includes historical `AppCrash_atieclxx.exe` (AMD) — outside proven hang-window causality; recorded under DUMP_ARTIFACTS only.

## Assessment

GPU present and Started/OK. Insufficient evidence for GPU-reset-driven HOST_UNSTABLE.
