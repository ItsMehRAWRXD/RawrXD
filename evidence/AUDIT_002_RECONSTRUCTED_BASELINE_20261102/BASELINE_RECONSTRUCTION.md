# AUDIT_002 Reconstructed Current Baseline

Status: RECONSTRUCTED_UNVERIFIED

Date: 2026-11-02
Repository: F:\rawrxd
HEAD: $head
Working-tree status entries: $status
Manifest: CURRENT_SOURCE_MANIFEST.csv
Manifest SHA-256: $manifestHash

## Scope

This is a newly generated current-source baseline. It is not the missing historical AUDIT_002 manifest and does not validate the reported historical count of 261 OPENISH translation units.

The manifest includes tracked implementation translation units with extensions .c, .cc, .cpp, .cxx, .cu, .m, and .mm. Headers are excluded from the translation-unit count. Every included file existed at generation time and has a SHA-256 hash.

## Classification rules

- CURRENT_TRACKED_SOURCE: tracked implementation file present in the current working tree.
- BuildMembership=UNVERIFIED: no claim is made that the file belongs to a target.
- Missing files are not silently synthesized.
- Historical OPENISH classifications are not assigned.
- A later build-graph pass may replace BuildMembership only with direct compile-command or target evidence.

## Result

Current tracked implementation translation units: 4077.
Historical OPENISH_261: UNVERIFIED.
Historical manifest recovery: FAILED.
Reclassification: HELD pending independent validation.
