# RAWRXD_FULL_AUDIT_001 â€” Compact discovery package

## Identity
- Generated UTC: 2026-11-10T06:21:25.9932702Z
- Workspace: `F:\rawrxd`
- RC4 exe: `F:\rawrxd\release\RawrXD-readiness-rc4\RawrXD-Win32IDE-Native-Ext.exe`
- RC4 SHA-256: `78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596` (expected `78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596`; match=True)
- Certified 4DE0 exe: `F:\rawrxd\release\RawrXD-4DE06F9F-rc1\RawrXD-Win32IDE-Native-Ext.exe`
- Certified SHA-256: `4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6` (expected `4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6`; match=True)
- PROMOTE=0 Â· TIP_CLIMB=HOLD Â· CERTIFIED_4DE0=IMMUTABLE

## Collector scope
- Read-only scan of `src`, `include`, `tools`, `scripts`, `config`, `cmake`, selected evidence trees, and `~dev/rawrxd/src` if present.
- Excluded: node_modules, most `build_*` trees, model/weight dirs, secrets by name heuristic.
- Files scanned (inventory rows): 6403
- Files hashed: 5078
- This package supports **discovery / build-inclusion mapping**. It does **not** by itself prove runtime PASS for every feature.

## Outputs
- FILE_MANIFEST.csv
- SOURCE_SYMBOLS.csv
- FEATURE_FLAGS.csv
- COMMAND_REGISTRY.csv
- MODEL_BACKENDS.csv
- DEEP2_FEATURES.csv
- CMAKE_TARGET_GRAPH.txt
- COMPILE_COMMANDS.json
- STUBS_AND_TODOS.csv
- DUPLICATE_IMPLEMENTATIONS.csv
- EVIDENCE_INDEX.csv
- RC4_SHA256.txt
- config_snapshots/

## Audit law
`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`
`NOT_RUN != PASS`

## Next verification (not performed by this collector)
1. Map which files from FILE_MANIFEST / CMAKE_TARGET_GRAPH / COMPILE_COMMANDS actually link into RC4 `78E187â€¦`.
2. Classify each Deep2/IDE feature: verified / unverified / unreachable / stub / experimental / duplicate / broken.
3. Run RC4 runtime gates (Computer Use GUI E2E, G02â€“G14, agent repair, G15) against the exact SHA.