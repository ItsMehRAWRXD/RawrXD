# Stub reconciliation inventory (BATCH_1)

HEAD_AT_INVENTORY: `a078e3b87be6b22ed1fa6fce6a20bfdd980e4441`

| Metric | Measured | Expected | Match |
|---|---|---|---|
| TOTAL_STUBS | 446 | 446 | yes |
| CMAKE_COMPILED | 68 | 68 | yes |
| NEVER_COMPILED | 378 | 378 | yes |
| SHIPPING_IDE | 25 | 25 | yes |
| STUB_ONLY_TARGETS | 17 | 17 | yes |
| LNK2019_MAIN_FAILURES | 4 | 5 | NO |

## Classification

| Class | Count |
|---|---|
| A_ORPHAN | 378 |
| B_BUILD_METADATA_GHOST | 26 |
| D_STUB_ONLY_TARGET | 17 |
| E_SHIPPING_STUB | 25 |

## Action

| Action | Count | Batch |
|---|---|---|
| CANDIDATE_PROVEN_DEAD_REMOVED_FROM_TARGET | 25 | BATCH_3 |
| QUARANTINE_FROM_ACTIVE_TREE | 378 | BATCH_5 |
| REMOVE_FROM_CMAKE_AND_QUARANTINE | 26 | BATCH_4 |
| REMOVE_TARGET_FROM_ACTIVE_BUILD_AND_QUARANTINE | 17 | BATCH_2 |

## Batch load

| Batch | Entries |
|---|---|
| BATCH_2 | 17 |
| BATCH_3 | 25 |
| BATCH_4 | 26 |
| BATCH_5 | 378 |
