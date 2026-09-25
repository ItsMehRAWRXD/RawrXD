param(
  [string]$BuildRoot = "F:\~dev\rawrxd\win32ide_strict\build_v4",
  [int[]]$Prefixes = @(0,1,3,7,15,27)
)
$ErrorActionPreference = "Stop"
$exe = Join-Path $BuildRoot "Release\RawrXD-Win32IDE.exe"
if (!(Test-Path $exe)) { throw "Executable not found: $exe" }
$outDir = Join-Path $BuildRoot "finite_prefix_diag"
New-Item -ItemType Directory -Force $outDir | Out-Null

$env:RAWRXD_GPU_FORWARD="1"
$env:DEEP2_RESIDENT_FIRST="1"
$env:DEEP2_DISABLE_VULKAN="0"
$env:DEEP2_GPU_FINITE_TRACE="1"

$rows=@()
foreach($pfx in $Prefixes){
  $env:DEEP2_GPU_TRACE_PREFIX_HI="$pfx"
  $err=Join-Path $outDir ("prefix_{0:D2}_stderr.txt" -f $pfx)
  $out=Join-Path $outDir ("prefix_{0:D2}_stdout.txt" -f $pfx)
  Write-Host "=== PREFIX $pfx ==="
  $p=Start-Process -FilePath $exe -ArgumentList "--headless","--autorun=inference" `
      -WorkingDirectory $BuildRoot -Wait -PassThru -NoNewWindow `
      -RedirectStandardError $err -RedirectStandardOutput $out
  $m=Select-String -Path $err -Pattern "GPU_FINITE_WITNESS" | Select-Object -First 1
  if(!$m){
    $rows += [pscustomobject]@{PrefixHi=$pfx;ExitCode=$p.ExitCode;Status="NO_WITNESS";Witness="";Stderr=$err}
    break
  }
  $line=$m.Line
  $nan=if($line -match 'nan=(\d+)'){[int64]$Matches[1]}else{-1}
  $inf=if($line -match 'inf=(\d+)'){[int64]$Matches[1]}else{-1}
  $finite=if($line -match 'finite=(\d+)'){[int64]$Matches[1]}else{-1}
  $status=if($nan -eq 0 -and $inf -eq 0 -and $finite -gt 0){"FINITE"}else{"NONFINITE"}
  $rows += [pscustomobject]@{PrefixHi=$pfx;ExitCode=$p.ExitCode;Status=$status;Witness=$line;Stderr=$err}
  Write-Host "$status :: $line"
  if($status -eq "NONFINITE"){ break }
}
$csv=Join-Path $outDir "finite_prefix_summary.csv"
$rows | Export-Csv -NoTypeInformation $csv
$rows | Format-Table -AutoSize
Write-Host "SUMMARY_CSV=$csv"
Write-Host "If first bad coarse prefix=N and previous finite=P, rerun with -Prefixes ((P+1)..N)."
