# RawrXD distribution (fail-closed)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **PUBLISHED=0** · **DRAFT_SHA_BOUND=1**

These files are **draft packaging recipes**. They are **not** proof of community-index publication.

| Channel | Path | Measured state |
|---------|------|----------------|
| Winget | `winget/RawrXD.RawrXD.yaml` | `NOT_PUBLISHED` · `DRAFT_SHA_BOUND` to `RawrXD-14.7.3-Windows-x64.zip` SHA `DDEB7D50…563B829D` |
| Chocolatey | `chocolatey/` | `NOT_PUBLISHED` · `DRAFT_SHA_BOUND` same zip SHA; MSI claim removed |
| Homebrew | `homebrew/rawrxd.rb` | `NOT_PUBLISHED` · Windows SHA bound; **macOS asset ABSENT**; `FORMULA_INSTALLABLE=0` |
| APT / YUM | `linux-repos/` | `UNPROVEN` |
| GitHub Releases | measured zips | See SHA table below |

## Measured SHA-256 (downloaded 2026-11-13)

| Tag | Asset | Bytes | SHA-256 |
|-----|--------|------:|---------|
| v14.7.3 | `RawrXD-14.7.3-Windows-x64.zip` | 910960 | `DDEB7D50840C1097B2C79A5702C54C115BD076B108F9C43D15BCB4BE563B829D` |
| v1.0.0 | `RawrXD-v1.0.0-Release.zip` | 26277121 | `3B692DDC9F14D75D373CB682CE1968B9B3E25074327254F88CFE910DE8BDE7D5` |

Witness: `evidence/PRODUCTION_MATURITY_TOP25_001/TOP25_RECOGNITION_OPS_001/release_assets/SHA256.txt` · `DRAFT_SHA_BOUND.txt`

## Publish gate (still open)

1. ~~Real artifact URL that downloads~~ (done for the two zips above)
2. ~~Bound SHA-256 (no PLACEHOLDER)~~ (DRAFT_SHA_BOUND)
3. Clean-machine install witness — **ABSENT**
4. Community index listing (winget/choco/brew) — **NOT_CLAIMED**

Until (3)+(4): use repo-root `INSTALL.md`.

```
NOT_PUBLISHED=1
DRAFT_SHA_BOUND=1
PROMOTE=0
CERTIFIED=0
NOT_RUN!=PASS
```
