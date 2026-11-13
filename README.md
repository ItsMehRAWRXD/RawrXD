# RawrXD

Local-first Sovereign IDE + inference CLI (Windows x64 primary).

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **RELEASE=HELD** · **TIP_CLIMB=HOLD**

This README is the **first-impression** surface for Top-25 recognition readiness.
It does **not** claim Top-25 ranking, 100% production maturity, or published package-manager installs.

## Install (authority)

See **[INSTALL.md](INSTALL.md)** — build with CMake/Ninja → `build_ninja\bin\rawr.exe` (or another measured `bin\rawr.exe`).

```powershell
cmake -G Ninja -S . -B build_ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build_ninja bin/rawr.exe
.\scripts\Verify-RawrLocalInstall.ps1
.\build_ninja\bin\rawr.exe --help
```

Optional: [`docs/guides/LOCAL_INSTALL.md`](docs/guides/LOCAL_INSTALL.md) · [`distribution/README.md`](distribution/README.md) (`NOT_PUBLISHED`).

## What is measured

| Area | Status | Where |
|------|--------|--------|
| Dense CLI unload smoke | PASS (historical witness) | `evidence/PRODUCTION_MATURITY_TOP25_001/cli_llama32_smoke_post.*` |
| MiniMax semantic / STREAM_CORRECTNESS | NOT_PASS / OPEN | `evidence/PRODUCTION_MATURITY_TOP25_001/SCOREBOARD.md` |
| GUI four-panel | FAIL_CLOSED | `evidence/FOUR_PANEL_COMPLETION_001` |
| Install / docs / distribution / retention ops | MEASURED_PARTIAL | `evidence/PRODUCTION_MATURITY_TOP25_001/TOP25_RECOGNITION_OPS_001/` · `evidence/TOP25_OPS_001/` |
| Package managers (winget/choco/brew) | NOT_PUBLISHED | `distribution/` |
| Top-25 recognition rollup | NOT_READY | `evidence/PRODUCTION_MATURITY_TOP25_001/STATUS.txt` |

`NOT_RUN != PASS`. Feature checklists ≠ production %.

## Product surfaces

- **CLI:** `rawr` — `list` / `show` / `paths` / `run` / `chat` / `agent` / `serve`
- **IDE:** Win32 native (`src/win32app/`) — maturity not certified
- **Inference:** Deep2 / GGUF local models — no mandatory cloud API

## Evidence & law

- `evidence/PRODUCTION_MATURITY_TOP25_001/LAW.txt`
- `evidence/PRODUCTION_MATURITY_TOP25_001/STATUS.txt`
- `evidence/PRODUCTION_MATURITY_TOP25_001/SCOREBOARD.md`
- `AGENTS.md` (assembler path + promote gates)

## License

See `LICENSE` in this repository when present.
