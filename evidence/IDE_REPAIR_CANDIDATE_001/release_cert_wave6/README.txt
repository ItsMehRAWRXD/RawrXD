RELEASE_CERT_WAVE6=97_TO_100
PROMOTE=0
CERTIFIED=0

CONTENTS=
  STATUS.txt
  WEIGHTED_ACCEPTANCE_LEDGER.txt   <- converted from LAYERS/ISSUE57/WORKSTREAMS; all EARNED=0
  SHA_LEDGER_TEMPLATE.txt
  CLEAN_MACHINE_CHECKLIST.txt
  Verify-PackageIntegrity.ps1
  Invoke-CleanMachineSmoke.ps1
  INDEPENDENT_VERIFIER_GAPS.txt
  README.txt

LFS_SAFE=
  Artifacts are .txt/.ps1 only (no .csv/.json/.bin/.zip) so push avoids LFS payload.

DO_NOT=
  Set PROMOTE=1
  Invent PASS / earn band weights without receipts
  Inherit RC4/4DE0/35C22 SHA credit onto this package
