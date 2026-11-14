# Getting Started with RawrXD Sovereign — HISTORICAL / REDIRECT

**STATUS:** `HISTORICAL` · **ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **RELEASE=HELD**

> **Fail-closed:** Package-manager, service, and HTTP-API blocks that once lived here are
> **NOT_PUBLISHED** / **NOT_RUN**. Do not treat them as green install or inference paths.
> **CLEAN_VM=ABSENT** (invent forbidden). Version drift documented only —
> `evidence/PRODUCTION_MATURITY_TOP25_001/VERSION_DRIFT.txt`.
>
> **Authoritative install:** repo-root [`INSTALL.md`](../../INSTALL.md) · pointer [`LOCAL_INSTALL.md`](LOCAL_INSTALL.md)  
> Evidence: `evidence/PRODUCTION_MATURITY_TOP25_001/` · `NOT_RUN != PASS`

---

## Quick Start (authority)

```powershell
.\scripts\Verify-RawrLocalInstall.ps1
.\build_ninja\bin\rawr.exe --help
.\build_ninja\bin\rawr.exe paths
```

See [`INSTALL.md`](../../INSTALL.md) for build steps and measured release zip names.
Product CLI path: `build_ninja\bin\rawr.exe` (not a winget/choco/brew install).

---

## Package managers / services / HTTP API — HISTORICAL (NOT_PUBLISHED)

Winget, Chocolatey, Homebrew, APT, Windows/macOS services, and `localhost:8080` curl/Python
snippets previously shown in this guide are **non-authoritative drafts**. They have **no**
clean-VM witness and **no** published index listing under this evidence pack.

**Use instead:** local build → `build_ninja\bin\rawr.exe` per [`INSTALL.md`](../../INSTALL.md).  
Distribution honesty: [`distribution/README.md`](../../distribution/README.md) (`NOT_PUBLISHED=1`).

A fixed marketing `--version` string is **not** asserted here (`NOT_RUN!=PASS`).

---

## Legacy sections below this line — HISTORICAL (do not follow)

Prior revisions of this file advertised service YAML under `%ProgramData%` / `/etc/rawrxd`,
`rawrxd-cli model pull`, HTTP `localhost:8080` load/health/metrics, Grafana `:3000`, and
Linux service troubleshooting. Those paths are **NOT_RUN** under
`evidence/PRODUCTION_MATURITY_TOP25_001/` and must not be cited as install or inference receipts.

**Measured first inference (local CLI):** see [`INSTALL.md`](../../INSTALL.md) and tip pin
`build_ninja\bin\rawr.exe` / `rawr_gpufwd_*.exe` under the CLI valuation pack.

---

*RawrXD Getting Started — HISTORICAL redirect · ASOF 2026-11-13 · PROMOTE=0*
