# Push progression evidence without LFS uploads (quota exhausted on origin).
$ErrorActionPreference = 'Stop'
Set-Location F:\rawrxd
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$branch = "progression/finish25-323a38a0-evidence"
$files = @(
  'evidence/PROGRESSION_FINISH25_001/CANCEL/REQUEST_A_SURVIVAL_RESULT_20261108-202351.txt',
  'evidence/PROGRESSION_FINISH25_001/CANCEL/REQUEST_A_SURVIVAL_RUNLOG_20261108-202351.txt',
  'evidence/PROGRESSION_FINISH25_001/CANCEL/logs/dump_header_28836.txt',
  'evidence/PROGRESSION_FINISH25_001/CANCEL/harness_request_a_survival_progression.ps1',
  'evidence/PROGRESSION_FINISH25_001/DISPOSITION_323A38A0.md',
  'evidence/PROGRESSION_FINISH25_001/ASSESS_323A38A0.md',
  'evidence/PROGRESSION_FINISH25_001/BINARY_HASH.txt',
  'evidence/PROGRESSION_FINISH25_001/DISPOSITION.md',
  'evidence/PROGRESSION_FINISH25_001/DISPOSITION_55BE19B7.md',
  'evidence/PROGRESSION_FINISH25_001/EDITOR/TASK07.md',
  'evidence/PROGRESSION_FINISH25_001/EDITOR/TASK08.md',
  'evidence/PROGRESSION_FINISH25_001/EDITOR/TASK10.md',
  'evidence/PROGRESSION_FINISH25_001/EDITOR/RETEST_T17_T07_T08_T10_SUMMARY.md',
  'evidence/PROGRESSION_FINISH25_001/EDITOR/RUNLOG_T17_T07_T08_T10.txt',
  'evidence/PROGRESSION_FINISH25_001/EDITOR/BUFFER_SYNC/RECEIPT.md',
  'evidence/POST_E59D_CANDIDATE_001/NEXT_ACTION.md',
  'evidence/POST_E59D_CANDIDATE_001/COMPLETENESS_ESTIMATE_2026_11_08.md',
  'evidence/POST_E59D_CANDIDATE_001/CONTROLLING_BASELINE_55BE19B7.md',
  'src/win32app/Win32IDE_lifecycle.cpp',
  'src/win32app/Win32IDE_FileOps.cpp',
  'src/win32app/Win32IDE.cpp',
  'src/win32app/Win32IDE.h'
)

# Preserve current branch
$prev = (git rev-parse --abbrev-ref HEAD).Trim()
Write-Output "PREV=$prev"

# Orphan commit containing only the authoritative local tip + receipts
git checkout --orphan $branch
git reset
git add -- $files
$status = git diff --cached --name-only
Write-Output "STAGED:"
$status
if (-not $status) { throw 'Nothing staged' }

git -c user.email='noreply@rawrxd.local' -c user.name='RawrXD Progression' commit -m @"
evidence(progression): publish 323A38A0 Request A crash receipt + tip sources

Local-authority package for crash analysis. PROMOTE=0 CERTIFIED=0 REQUEST_A_SURVIVES=0.
Orphan branch avoids LFS history. Controlling seal 55BE19B7 untouched.
"@

$env:GIT_LFS_SKIP_PUSH = '1'
git push -u origin "HEAD:refs/heads/$branch"
Write-Output "PUSH_EXIT=$LASTEXITCODE"
git rev-parse HEAD
Write-Output "BRANCH=$branch"
# Return to prior branch without carrying orphan index
git checkout -f $prev
Write-Output "RESTORED=$prev DONE=$stamp"
