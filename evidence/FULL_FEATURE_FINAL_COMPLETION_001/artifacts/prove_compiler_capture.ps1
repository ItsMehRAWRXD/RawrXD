# Bounded proof: cl under pipes + VS_UNICODE_OUTPUT scrub. PROMOTE=0. Not a tip promote.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
$Fixture = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$Work = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures'
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$Receipt = Join-Path $OutDir 'COMPILER_CAPTURE_ISOLATED_RECEIPT.txt'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Run-ClCapture([string]$tag, [bool]$scrub) {
  $stdout = Join-Path $OutDir ("_cl_" + $tag + "_stdout.txt")
  $stderr = Join-Path $OutDir ("_cl_" + $tag + "_stderr.txt")
  Remove-Item $stdout,$stderr -Force -EA SilentlyContinue
  $inner = "echo [RAWRXD_PROBLEMS_FIXTURE_START] && cd /d $Work && call `"$Vcvars`" >nul && "
  if ($scrub) {
    $inner += "set VS_UNICODE_OUTPUT=&& set VC_CLEAR=&& "
  } else {
    # Poison: inherited-style IDE unicode output channel (invalid handle → hang/stall)
    $inner += "set VS_UNICODE_OUTPUT=42&& "
  }
  $inner += "cl /nologo /c /W4 /EHsc /FS `"$Fixture`" 2>&1 & echo [RAWRXD_PROBLEMS_FIXTURE_RESULT] DONE"
  $p = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/s','/c', $inner) `
    -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $ok = $p.WaitForExit(90000)
  $disposition = if (-not $ok) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue; 'timeout' }
                 elseif ($p.ExitCode -eq 0) { 'success' } else { 'failure' }
  $outText = if (Test-Path $stdout) { Get-Content $stdout -Raw } else { '' }
  $errText = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { '' }
  $combined = "$outText$errText"
  $hasStart = $combined -match 'RAWRXD_PROBLEMS_FIXTURE_START'
  $hasResult = $combined -match 'RAWRXD_PROBLEMS_FIXTURE_RESULT'
  $hasDiag = $combined -match 'error C\d+'
  [pscustomobject]@{
    TAG=$tag; SCRUB=$scrub; DISPOSITION=$disposition; EXIT=($(if($ok){$p.ExitCode}else{259}))
    HAS_START=$hasStart; HAS_RESULT=$hasResult; HAS_DIAG=$hasDiag
    OUT_LEN=$combined.Length; STDOUT=$stdout; STDERR=$stderr
  }
}

$poison = Run-ClCapture 'poison' $false
$scrubbed = Run-ClCapture 'scrub' $true

@"
COMPILER_CAPTURE_ISOLATED=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CONTROLLING_TIP=CC79
CANDIDATE_NOT_PROMOTED=1
PROMOTE=0
CERTIFIED=0
POISON_VS_UNICODE_OUTPUT disposition=$($poison.DISPOSITION) exit=$($poison.EXIT) start=$($poison.HAS_START) result=$($poison.HAS_RESULT) diag=$($poison.HAS_DIAG) out_len=$($poison.OUT_LEN)
SCRUB_VS_UNICODE_OUTPUT disposition=$($scrubbed.DISPOSITION) exit=$($scrubbed.EXIT) start=$($scrubbed.HAS_START) result=$($scrubbed.HAS_RESULT) diag=$($scrubbed.HAS_DIAG) out_len=$($scrubbed.OUT_LEN)
ROOT_CAUSE_HYPOTHESIS=VS_UNICODE_OUTPUT inherited/poison stalls cl after /nologo filename; scrub + /FS + 2>&1 required for pipe capture
COMPILER_EXECUTION=$(if($scrubbed.HAS_RESULT){'VERIFIED'}else{'NOT_VERIFIED'})
COMPILER_OUTPUT_CAPTURE=$(if($scrubbed.HAS_DIAG){'VERIFIED'}else{'NOT_VERIFIED'})
DIAGNOSTIC_FEED=$(if($scrubbed.HAS_DIAG){'LINES_PRESENT'}else{'NOT_VERIFIED'})
"@ | Set-Content -LiteralPath $Receipt -Encoding UTF8

Write-Host (Get-Content $Receipt -Raw)
if (-not $scrubbed.HAS_DIAG) { exit 2 }
exit 0
