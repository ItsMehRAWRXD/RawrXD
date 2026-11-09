# EXTENSIONHOST_INTEGRATION_REPAIR_001 — next gate

## Current status

`PATCH_PREPARATION=COMPLETE`  
`SOURCE_MODIFIED=0`  
`BUILD_EXECUTED=0`  
`RUNTIME_EXECUTED=0`  
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0` · `PRODUCT_RUNTIME=NOT_REVALIDATED`

## Required next authorization

Authorize implementation on a separate candidate branch/worktree. After review, authorize a candidate-only configure/build. Execution must remain held until that separate authorization is granted.

## Candidate gate order

1. Review this patch package.
2. Apply source changes only on candidate branch/worktree.
3. Record SHA-256 for every modified source file.
4. Configure/build candidate and verify target/deployment manifest.
5. Run focused tests R01–R12.
6. Run `EXTENSION_RUNTIME_MATRIX_003` against the exact candidate SHA.
7. Only then continue the IDE feature matrix and 261-TU audit residuals.

No implementation or runtime PASS is claimed by this package.

