<#
Repeat-trial harness for the IDE runtime-cert hang.

Reason this exists: a single A/B gave "S12 EDIT IS IMPLICATED", but the edit is a boolean
expression evaluated after every side-effecting call, so it has no mechanism to block.
With n=2 hangs and n=2 successes the correlation is not evidence. This runs repeated
trials of ONE binary to measure the hang RATE. A hang rate strictly between 0 and 1
exonerates the edit and establishes nondeterminism.

Each trial: fresh receipt path, workspace cleared, one PID, bounded wait, kill that PID.
#>

param([int]$Trials = 5, [int]$WaitSec = 75)

$Exe = 'F:\~dev\build_ide_probe\bin\RawrXD-Win32IDE.exe'
$Ws  = 'F:\~dev\build_ide_probe\bin\ide_cert_workspace'
$Base= 'F:\dev_ide_repeat'

function Say($m) { Write-Information $m -InformationAction Continue }

$hash = (Get-FileHash $Exe -Algorithm SHA256).Hash
Say "EXE_SHA256=$hash"
Say "TRIALS=$Trials  WAIT_SECONDS=$WaitSec"
Say ''

$ok = 0; $hang = 0; $rows = @()

for ($t = 1; $t -le $Trials; $t++) {
    $dir = Join-Path $Base "t$t"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $rec = Join-Path $dir 'ide_runtime_cert_receipt.txt'
    Remove-Item $rec -Force -ErrorAction SilentlyContinue
    if (Test-Path $Ws) { Remove-Item "$Ws\*" -Recurse -Force -ErrorAction SilentlyContinue }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $Exe -PassThru -WindowStyle Normal -WorkingDirectory $dir `
         -ArgumentList @('--ide-runtime-cert','--ide-cert-receipt',$rec)
    $got = $false; $secs = 0; $s12 = ''
    for ($i = 0; $i -lt $WaitSec; $i++) {
        Start-Sleep -Seconds 1
        $secs = $i + 1
        if ($p.HasExited) { break }
        if (Test-Path $rec) { $got = $true; break }
    }
    if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(20000) | Out-Null }

    if ($got) {
        $ok++
        $line = Select-String -Path $rec -Pattern 'S12_UNDO_REDO' -ErrorAction SilentlyContinue
        if ($line) {
            $m = [regex]::Match($line.Line, 'S12_UNDO_REDO=(\w+)')
            $s12 = if ($m.Success) { $m.Groups[1].Value } else { '?' }
        }
        $verdict = (Select-String -Path $rec -Pattern '^IDE_RUNTIME_CERT=' | Select-Object -First 1)
        $v = if ($verdict) { ($verdict.Line -split '=')[1] } else { '?' }
        Say ("trial {0}: RECEIPT in {1,3}s   S12={2}   OVERALL={3}" -f $t,$secs,$s12,$v)
    } else {
        $hang++
        $doc = if (Test-Path "$Ws\cert_doc.txt") { (Get-Item "$Ws\cert_doc.txt").Length } else { -1 }
        Say ("trial {0}: NO RECEIPT after {1}s (killed)   workspace_doc_bytes={2}" -f $t,$secs,$doc)
    }
    $rows += [pscustomobject]@{ trial=$t; receipt=$got; secs=$secs; s12=$s12 }
    Start-Sleep -Seconds 3
}

Say ''
Say "RECEIPT_WRITTEN=$ok   NO_RECEIPT=$hang   TOTAL=$Trials"
$rate = if ($Trials -gt 0) { [math]::Round(100.0*$hang/$Trials,1) } else { 0 }
Say "HANG_RATE_PERCENT=$rate"
if ($hang -eq 0)      { Say 'VERDICT=DETERMINISTIC_NO_HANG_ON_THIS_BINARY' }
elseif ($ok -eq 0)    { Say 'VERDICT=DETERMINISTIC_HANG_ON_THIS_BINARY' }
else                  { Say 'VERDICT=NONDETERMINISTIC  <-- a single A/B run cannot attribute a cause' }
