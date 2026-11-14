# STORAGE_RECOVERY_BATCH_001

ASOF_UTC=2026-11-14T18:13:46Z
PROMOTE=0
CERTIFIED=0
MODE=RECOVERED

## Cleanup Batch — Disposable Run Dumps

| Path | Bytes | Referenced by cert manifest |
|------|-------|-----------------------------|
| F:\rawrxd\__run_output30.txt | 2417123835 | NO (per STORAGE_AUDIT_001 Batch 2, LOW risk) |
| F:\rawrxd\__run_output31.txt | 2417121533 | NO |
| F:\rawrxd\__run_output32.txt | 2417116421 | NO |
| F:\rawrxd\__run_output33.txt | 2417116543 | NO |
| F:\rawrxd\__run_output34.txt | 2417123642 | NO |
| F:\rawrxd\__run_output35.txt | 2417123835 | NO |
| F:\rawrxd\__run_output.txt | 779707691 | NO |

Total reclaimed: ~19,738,998,440 bytes (~18.4 GiB)
Free before: 21,032,767,488 bytes (19.59 GB)
Free after:  39,329,984,320 bytes (39.33 GB)

## Protected (not deleted)

- tmp_safetensors/ (~29 GiB) — LFS shard mapping unconfirmed (STORAGE_AUDIT_001)
- .worktrees/ (13 dirs, ~21 GB) — certified EXEs referenced by enterprise evidence
- nemotron-3.5-lightning duplicate GGUF (24.2 GB) — sealed cert evidence
- dummy_200b.gguf (400 GiB cited in audit) — does not exist on F:
- models/ unique weights — KEEP per audit
- Sealed evidence directories — KEEP