# RawrXD distribution (fail-closed)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **PUBLISHED=0**

These files are **draft packaging recipes**. They are **not** proof of community-index publication.

| Channel | Path | Measured state |
|---------|------|----------------|
| Winget | `winget/RawrXD.RawrXD.yaml` | `NOT_PUBLISHED` — `InstallerSha256=PLACEHOLDER_SHA256`; `winget search RawrXD` → no package |
| Chocolatey | `chocolatey/` | `NOT_PUBLISHED` — `checksum64=PLACEHOLDER_SHA256`; claimed MSI absent on `v1.0.0` |
| Homebrew | `homebrew/rawrxd.rb` | `NOT_PUBLISHED` — `sha256=PLACEHOLDER_SHA256` |
| APT / YUM | `linux-repos/` | `UNPROVEN` — repo scripts present; no clean-VM install witness here |
| GitHub Releases | `github-releases/` | Checklist aspirational; real assets measured as zips on some tags |

## Authority

Witness: `evidence/PRODUCTION_MATURITY_TOP25_001/TOP25_RECOGNITION_OPS_001/MEASURE.txt`

Known release assets (sample):

- `v1.0.0` → `RawrXD-v1.0.0-Release.zip` (**not** `RawrXD-1.0.0-x64.msi`)
- `v14.7.3` → `RawrXD-14.7.3-Windows-x64.zip`

## Publish gate (required before claiming install)

1. Real artifact URL that `HTTP 200`s.
2. Bound SHA-256 (no `PLACEHOLDER_*`).
3. Clean-machine install witness logged under evidence.
4. Then update docs to match **exact** asset names.

Until then: use `docs/guides/LOCAL_INSTALL.md`.

```
NOT_PUBLISHED=1
PROMOTE=0
CERTIFIED=0
NOT_RUN!=PASS
```
