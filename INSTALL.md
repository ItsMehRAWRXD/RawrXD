# RawrXD — Local Installation (fail-closed)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **RELEASE=HELD**

This guide documents the **measured local product path** used in
`evidence/PRODUCTION_MATURITY_TOP25_001/`. It does **not** claim winget,
Homebrew, Docker Hub, or MSI channels are verified. Those remain
**UNVERIFIED** until a receipt lands under this evidence pack.

Authority: `evidence/PRODUCTION_MATURITY_TOP25_001/LAW.txt` ·
`NOT_RUN != PASS` · no invented maturity %.

---

## What you get (product binaries)

| Artifact | Path (after ninja build) | Role |
|----------|--------------------------|------|
| CLI | `build_ninja\bin\rawr.exe` | Primary inference CLI (`rawr run` / `list` / `paths`) |
| Optional | `build_ninja\bin\reap_export_sidecar.exe` | REAP physical export tooling |

There is **no** sealed public installer receipt in this pack. Treat
`DISTRIBUTION_MANIFEST.yaml` as **historical / non-authoritative** (hashes
and “PRODUCTION READY” text are not current cert).

---

## System requirements (measured host class)

| Item | Minimum for dense smoke | Notes |
|------|-------------------------|-------|
| OS | Windows 10/11 x64 | Primary measured platform |
| Toolchain | VS 2022 BuildTools + CMake + Ninja | See AGENTS.md for `ml64.exe` path |
| RAM | 16 GB+ free for small dense models | Large MoE needs far more / REAP |
| GPU | Optional | Dense smoke used `RAWRXD_HOST_DECODE=1` when Vulkan blocked |
| Models | Local GGUF on disk | No mandatory cloud API |

---

## Build from source (authoritative path)

From a Developer PowerShell / VsDevCmd (`x64`):

```powershell
cd G:\~dev\rawrxd   # or your clone root

# Configure once (Ninja + RelWithDebInfo matches lab cache)
cmake -G Ninja -S . -B build_ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build CLI
ninja -C build_ninja bin/rawr.exe
```

Verify:

```powershell
.\scripts\Verify-RawrLocalInstall.ps1
# or manually:
.\build_ninja\bin\rawr.exe
# prints Usage: rawr list | show | paths | run ...
```

Optional: add `build_ninja\bin` to the **user** PATH for this session/dev box:

```powershell
.\scripts\Install-RawrDevPath.ps1
```

---

## First inference (dense)

Use a local GGUF. Example shape (paths are machine-local):

```powershell
$env:RAWRXD_HOST_DECODE = "1"   # only if Vulkan/GPU path is blocked
.\build_ninja\bin\rawr.exe run <path-to-llama-gguf> -p "Hello" --max-tokens 8
```

**Measured (not a top-25 claim):** dense Llama-3.2 unload smoke in this pack
(`cli_llama32_smoke_post.*`) reported:

- `EXIT=0`
- Prefill ≈ **3.21 tok/s** · Decode ≈ **3.19 tok/s** · E2E ≈ **0.46 TPS**
  (3 tokens / 6549.39 ms)

Cite the err log; do not generalize to MoE or competitor ranking.

---

## MoE / REAP retention (onboarding hazard)

Large MoE models (e.g. MiniMax-M2.7) often need `--reap` / retained-expert
policy. Uniform low retain (**R=27**) has **measured** independent load
`FUNCTIONAL_PASS` but **SEMANTIC_COHERENCE=FAIL** — see
`REAP_ALL_16GB_001/INDEP_SMOKE_SEAL.txt`.

Do **not** tell new users that REAP16 prefix retention is “production ready.”

Env knobs operators hit during onboarding (document; do not invent defaults):

| Knob | Meaning |
|------|---------|
| `RAWRXD_REAP_RETAINED` | Retained expert count override |
| `RAWRXD_HOST_DECODE` | Force CPU host decode |
| `WEIGHT_BUDGET` | Weight residency budget string |

Details: `docs/RAWRXD_REAP_CLI_CONTRACT.md` ·
`ONBOARDING_RETENTION_GAPS.txt` in this evidence pack.

---

## Unverified / do-not-advertise (until receipt)

- `winget install RawrXD.RawrXD`
- Homebrew / apt / rpm package URLs in older docs
- Docker Hub `rawrxd/rawrxd:latest`
- MSI/`setup.exe` wizard paths without SHA + smoke receipt
- Any “Top 25” or “100% production” marketing line

---

## Related docs

| Doc | Role |
|-----|------|
| `evidence/PRODUCTION_MATURITY_TOP25_001/STATUS.txt` | P4 recognition readiness |
| `evidence/PRODUCTION_MATURITY_TOP25_001/DISTRIBUTION_NOTES.txt` | Distro honesty |
| `evidence/PRODUCTION_MATURITY_TOP25_001/SCOREBOARD.md` | Measured gates |
| `evidence/TOP25_OPS_001/STATUS.txt` | Install/docs/distro/retention gap board |
| `evidence/COMPETITIVE_BENCH_001/STATUS.txt` | Competitive smoke inventory (PROMOTE=0) |
| `docs/guides/installation.md` | Legacy guide — defer to this file |

`PROMOTE=0` · `TIP_CLIMB=HOLD` · `NOT_RUN!=PASS`
