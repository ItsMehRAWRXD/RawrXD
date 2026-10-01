$ErrorActionPreference = 'Stop'
Set-Location F:\~dev\rawrxd
$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\00b_diag.log'

'=== ORIGIN / UPSTREAM ===' | Out-File $Logs
'HEAD=' + (git rev-parse HEAD)                  | Out-File $Logs -Append
'origin/model-correctness=' + (git rev-parse origin/model-correctness) | Out-File $Logs -Append
'@{u}=' + (git rev-parse '@{u}' 2>$null)        | Out-File $Logs -Append

$porcelain = git status --porcelain
$porcelain | Out-File $Logs -Append

$M = ($porcelain | Select-String -Pattern '^ M ').Count
$D = ($porcelain | Select-String -Pattern '^ D ').Count
$R = ($porcelain | Select-String -Pattern '^R  ').Count
$Q = ($porcelain | Select-String -Pattern '^\?\?').Count
$Qm = ($porcelain | Select-String -Pattern '^ M ').Count

'COUNT_M_worktree=' + $M | Out-File $Logs -Append
'COUNT_D_worktree=' + $D | Out-File $Logs -Append
'COUNT_R_worktree=' + $R | Out-File $Logs -Append
'COUNT_??_worktree=' + $Q | Out-File $Logs -Append

$untracked = git ls-files --others --exclude-standard
$underSrc = @($untracked | Where-Object { $_ -like 'src/*' })
'COUNT_untracked_under_src=' + $underSrc.Count | Out-File $Logs -Append

Append ('PIN_HEAD=' + ($(if ((git rev-parse HEAD) -eq 'a078e3b87be6b22ed1fa6fce6a20bfdd980e4441') { 'STILL_PINNED' } else { 'MOVED' })))
Append ('WORKTREE=' + ($(if ($porcelain.Count -eq 0) { 'CLEAN' } else { 'DIRTY' })))

'=== CONCURRENT WRITER INDICATORS ===' | Append
Append ('WL=' + (@($untracked | Where-Object { $_ -like '*WriterLeaseAuthority*' }).Count))
Append ('SW=' + (@($untracked | Where-Object { $_ -like 'src/authority/*' }).Count))
Append ('AC=' + (@($untracked | Where-Object { $_ -like 'src/agent/*' }).Count))
Append ('RA=' + (@($untracked | Where-Object { $_ -like '*ReceiptAuthority*' -or $_ -like '*ImmutableReceiptAuthority*' }).Count))
Append ('PS_TOOLS=' + (@($untracked | Where-Object { $_ -like 'tools/*.ps1' }).Count))
Append ('RECEIPTS_DIRS=' + (@($untracked | Where-Object { $_ -like 'receipts/RAWRXD_*' }).Count))

'=== MODIFIED (worktree) under src/ ===' | Append
foreach ($l in $porcelain) {
    if ($l -like ' M src/*') { Append $l }
}

'log=' + $Logs
