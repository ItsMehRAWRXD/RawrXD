# RECEIPT — WIN32IDE_RC_PREP_001

```
ASOF_UTC=2026-10-28
MODE=PHASE_10_PREP_ONLY
PROMOTE=0
PRODUCT_CERTIFIED=0
RC_PASS=NOT_CLAIMED
TIP_CLIMB=HOLD
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
```

## Done (prep)

| Item | Result |
|------|--------|
| Inventory packaging/installer/cmake/regression | `INVENTORY.md` |
| OPEN vs sealed checklist | `CHECKLIST.md` |
| Dry-run ZIP (tip freeze EXE+PDB+LICENSE) | `dry_run/RawrXD-Win32IDE_TIP_FREEZE_748B_dry_run.zip` |
| Dry-run ZIP SHA-256 | `A731765E6BEDA6B0588A49E7D030ABA9157E42B5CD99CB443A314802C9CBA061` |
| Dry-run script | `scripts/rc_prep_dry_run_package.ps1` |

## Not done (explicit)

- RC certify
- PROMOTE
- Installer compile (Inno/NSIS/WiX)
- `cmake --install` product path
- GhostText absorb
- Closing closure-matrix OPEN/BLOCKED rows

## Law

`DRY_RUN_ZIP ≠ RC_PASS ≠ PRODUCT_CERTIFIED ≠ PROMOTE`  
`NOT_RUN != PASS`
