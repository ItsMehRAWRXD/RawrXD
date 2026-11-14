# STRATA_HIP_OLLAMA_001 — WS7 matrix row

```text
PROMOTE=0 CERTIFIED=0 COMPETITIVE_PASS=0
NOT_RUN!=PASS CROSS_SHA_CREDIT=0 TIP_CLIMB=HOLD
```

| Track | Status | Evidence | Notes |
|-------|--------|----------|-------|
| HIP unversioned amdhip64.dll | FAIL | hip/DLL_PROBE.txt | err=126 |
| HIP amdhip64_6 runtime | PASS | hip/w7_hip_probe2.out.txt | hipInit n=2 |
| HIP memcpy bench | PASS | hip/w7_hip_memcpy.out.txt | verify_ok=1 |
| Strata HIP model E2E | EXPLICIT_UNSUPPORTED | W7 DISPOSITION | no hipcc kernels |
| Model compatibility | PARTIAL | MODEL_COMPAT.csv | 5/6 REAP tags |
| Ollama fair generate | MEASURED | ollama/FAIR_GENERATE.csv | equal prompt/32/0 |
| Ollama agent tools | MEASURED_EMISSION | AGENT_TOOL.csv + W7 ollama_tool.json | PASS_TOOL |
| Fair H2H competitive | HELD=0 | H2H_RATIOS.csv | EQUAL_EVAL=1 caveat |
| Prior REAP_STRATA bench | PARTIAL retained | ../REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001/ | COMPETITIVE_PASS=0 |

Board: `WS7_STRATA_HIP_OLLAMA=RELATED/PARTIAL` ≠ CERTIFIED.
Sibling absorb also: `W7_STRATA_HIP_OLLAMA_001`.
