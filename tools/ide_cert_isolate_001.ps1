<#
Isolation experiment for the IDE runtime-cert hang.

Three observed states, no controlled variable between them:
  A  no Deep2Engine change, no S12 cert edit   -> receipt in 24s        MEASURED
  C  Deep2Engine change + S12 cert edit         -> no receipt, hangs    MEASURED (twice,
                                                                 variable point)
  B  Deep2Engine change, NO S12 cert edit      -> ???                  THIS EXPERIMENT

B isolates the two candidate causes. The S12 edit is this session's own, so reverting it
temporarily is legitimate. The Deep2Engine.cpp change belongs to another lane and is NOT
touched: B still contains it, which is exactly what makes the comparison valid.

Restore is guaranteed by a finally block: the S12 edit is re-applied whatever happens.
#>

$ps1 = 'F:\~dev\rawrxd\src\win32app\Win32IDE_RuntimeCert.cpp'
$Exe = 'F:\~dev\build_ide_probe\bin\RawrXD-Win32IDE.exe'
$Vcv = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$Rec = 'F:\dev_ide_cert_B\ide_runtime_cert_receipt.txt'
$Ws  = 'F:\~dev\build_ide_probe\bin\ide_cert_workspace'

$FIXED = 'const bool ok = grew && undoWorked && routed && routedRedo && (afterRedo == typed);'
$ORIG  = 'const bool ok = grew && routed && routedRedo;'

function Say($m) { Write-Information $m -InformationAction Continue }

function RunCert([int]$maxWaitSec) {
    New-Item -ItemType Directory -Path 'F:\dev_ide_cert_B' -Force | Out-Null
    Remove-Item $Rec -Force -ErrorAction SilentlyContinue
    if (Test-Path $Ws) { Remove-Item "$Ws\*" -Recurse -Force -ErrorAction SilentlyContinue }
    $p = Start-Process -FilePath $Exe -PassThru -WindowStyle Normal `
         -WorkingDirectory 'F:\dev_ide_cert_B' `
         -ArgumentList @('--ide-runtime-cert','--ide-cert-receipt',$Rec)
    $got = $false
    for ($i = 0; $i -lt $maxWaitSec; $i++) {
        Start-Sleep -Seconds 2
        if ($p.HasExited) { Say "  process exited code=$($p.ExitCode)"; break }
        if (Test-Path $Rec) { $got = $true; Say "  receipt after $(2*($i+1))s"; break }
    }
    if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(20000) | Out-Null }
    Say "  RECEIPT=$got"
    return $got
}

try {
    Say "HASH_BEFORE=$((Get-FileHash $Exe -Algorithm SHA256).Hash)"

    # ---- B: revert ONLY this session's S12 edit -------------------------
    $t = Get-Content $ps1 -Raw
    if ($t -notmatch [regex]::Escape($FIXED)) { Say 'ABORT: fixed S12 line not found'; exit 2 }
    Set-Content -Path $ps1 -Value ($t -replace [regex]::Escape($FIXED), $ORIG) -NoNewline
    Say 'REVERTED_S12_EDIT=YES (Deep2Engine.cpp change left untouched)'

    $rc = Start-Process cmd.exe -ArgumentList '/c',
        "call `"$Vcv`" >nul 2>&1 && ninja -C F:\~dev\build_ide_probe RawrXD-Win32IDE" `
        -RedirectStandardOutput 'F:\~dev\audit_tombstone_001\build_B.log' `
        -NoNewWindow -PassThru -Wait
    Say "BUILD_B_EXIT=$($rc.ExitCode)"
    Say "HASH_B=$((Get-FileHash $Exe -Algorithm SHA256).Hash)"

    Say ''
    Say '--- B: Deep2Engine change present, S12 cert edit REVERTED ---'
    $b = RunCert 90

    if ($b) { Say ''; Say 'B_RESULT=RECEIPT_WRITTEN  -> S12 EDIT IS IMPLICATED'; }
    else    { Say ''; Say 'B_RESULT=NO_RECEIPT      -> the Deep2Engine change is implicated, not the S12 edit'; }
} finally {
    # ---- always restore the S12 edit ------------------------------------
    $t2 = Get-Content $ps1 -Raw
    if ($t2 -notmatch [regex]::Escape($FIXED)) {
        Set-Content -Path $ps1 -Value ($t2 -replace [regex]::Escape($ORIG), $FIXED) -NoNewline
    }
    Say ''
    Say 'RESTORED_S12_EDIT=YES'
    $rc2 = Start-Process cmd.exe -ArgumentList '/c',
        "call `"$Vcv`" >nul 2>&1 && ninja -C F:\~dev\build_ide_probe RawrXD-Win32IDE" `
        -RedirectStandardOutput 'F:\~dev\audit_tombstone_001\build_restore.log' `
        -NoNewWindow -PassThru -Wait
    Say "REBUILD_AFTER_RESTORE_EXIT=$($rc2.ExitCode)"
    Say "HASH_RESTORED=$((Get-FileHash $Exe -Algorithm SHA256).Hash)"
}
