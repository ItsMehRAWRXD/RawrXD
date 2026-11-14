# W7 Strata HIP + Ollama — Disposition

```text
PROMOTE=0 CERTIFIED=0 TIP_CLIMB=HOLD GATE_STOP=1
INVENT_PASS=0 NOT_RUN!=PASS CROSS_SHA_CREDIT=0
TIP=966783dc64c0 ASOF=2026-11-14T12:02:05-05:00
```

## Strata (HIP)

| Gate | Result | Evidence |
|------|--------|----------|
| Hardware present | YES (R9700 + RX 7800 XT + iGPU) | WMI VideoController |
| HIP runtime load | PASS via `amdhip64_6.dll` | `probe/hip_probe2.out.txt` |
| Legacy `amdhip64.dll` | FAIL err=126 | same |
| hipInit / device count | PASS / n=2 | same |
| Memcopy H2D/D2H verify | PASS | `probe/hip_memcpy.out.txt` |
| hipcc / ROCm SDK | ABSENT | Program Files probe |
| Native Strata HIP model E2E | **EXPLICIT_UNSUPPORTED** | no compiled HIP kernels; host fallback ≠ HIP model PASS |

**STRATA_HIP_DISPOSITION=`PARTIAL`** — runtime + bench PASS; model E2E EXPLICIT_UNSUPPORTED until HIP kernels exist.

Product fix landed: loaders now try `amdhip64_6.dll` after `amdhip64.dll`.

## Ollama

| Gate | Result | Evidence |
|------|--------|----------|
| `/api/version` | PASS 0.40.16 | `probe/ollama_version.json` |
| `/api/tags` | PASS HTTP 200 | `probe/ollama_tags.json` |
| `/api/generate` | PASS (`OK`) | `probe/ollama_gen.json` |
| Agent tool emission | PASS (`calculator` / `2+2`) | `probe/ollama_tool.json` |
| Post-tool final chat | TIMEOUT (not credited) | curl 28 |

**OLLAMA_DISPOSITION=`PASS`** — reliable local integration + agent tool-use emission measured.

## Program

```text
WS7_STRATA_HIP_OLLAMA=PARTIAL
ALL_BACKENDS_COMPLETE=0
PROMOTE=0
```
