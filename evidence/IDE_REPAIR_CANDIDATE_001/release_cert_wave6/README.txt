RELEASE_CERT_WAVE6=97_TO_100
PROMOTE=0
CERTIFIED=0
PACKAGE_ID=RawrXD-readiness-rc5b
PRIMARY_IDE_SHA256=6E59E91A2D23A3BC666345DF5168F66DDCAC1FD1C25F46A64E33773EC78A4C4C

CONTENTS=
  STATUS.txt
  WEIGHTED_ACCEPTANCE_LEDGER.txt   <- B1–B6 all EARNED=0; receipt_path pointers only
  SHA_LEDGER_TEMPLATE.txt          <- FILLED fresh hashes (12 members)
  CLEAN_MACHINE_CHECKLIST.txt
  Verify-PackageIntegrity.ps1
  Invoke-CleanMachineSmoke.ps1
  INDEPENDENT_VERIFIER_GAPS.txt
  README.txt
  runs/verify_20261110-095000/
  runs/clean_machine_20261110-095000/
  runs/rollback_rehash_20261110-095000/

EXECUTED_BUILDER_HOST=
  PASS_INTEGRITY_ONLY (clean extract)
  SMOKE_LAUNCH_ONLY
  PASS_ROLLBACK_REHASH_ONLY
  HOST_NOT_INDEPENDENT (DISTINCT_VM=0)

LFS_SAFE=
  Artifacts are .txt/.ps1/.tsv only (no .csv/.json/.bin/.zip) so push avoids LFS payload.

DO_NOT=
  Set PROMOTE=1
  Invent PASS / earn band weights without independent receipts
  Inherit RC4/4DE0/35C22 SHA credit onto this package
  Flip B6 earned while HOST_NOT_INDEPENDENT
