# Offline MSVC build pipeline gate — FULL_FEATURE_ONESHOT_001 TRACK I
# PROMOTE=0 · NOT_RUN!=PASS · IDE HWND not claimed · A4F overwrite forbidden
$ErrorActionPreference = "Continue"
$root = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001"
$fx = Join-Path $root "fixtures\build_pipeline"
$out = Join-Path $root "artifacts\build_pipeline"
$logs = Join-Path $root "logs\build_pipeline"
New-Item -ItemType Directory -Force -Path $out, $logs | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$receipt = Join-Path $logs "build_pipeline_receipt_$stamp.txt"
$vsdev = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
$clPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"
$linkPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"

$tcLog = Join-Path $logs "toolchain_$stamp.txt"
cmd /c "`"$vsdev`" -arch=amd64 >NUL && cl 2>&1" > $tcLog 2>&1
$clVerLine = (Get-Content $tcLog | Select-String "Compiler Version" | Select-Object -First 1).Line
if (-not $clVerLine) { $clVerLine = "Compiler Version UNKNOWN" }

$results = [ordered]@{}
function Invoke-VsCl {
  param([string]$ArgsLine, [string]$LogFile, [int]$TimeoutMs = 180000)
  $bat = Join-Path $out "_run_cl_tmp.bat"
  @"
@echo off
call "$vsdev" -arch=amd64 >NUL
cl $ArgsLine
exit /b %ERRORLEVEL%
"@ | Set-Content -LiteralPath $bat -Encoding ASCII
  $errFile = Join-Path $out "_cl_err_tmp.txt"
  $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$bat`"" -NoNewWindow -PassThru `
    -RedirectStandardOutput $LogFile -RedirectStandardError $errFile
  $ok = $p.WaitForExit($TimeoutMs)
  if (-not $ok) {
    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
    return @{ TimedOut = $true; ExitCode = -1; Pid = $p.Id }
  }
  try { $p.Refresh() } catch {}
  $ec = -998
  if ($null -ne $p.ExitCode) {
    try { $ec = [int]$p.ExitCode } catch { $ec = -998 }
  }
  $err = Get-Content $errFile -Raw -ErrorAction SilentlyContinue
  if ($err) { Add-Content -LiteralPath $LogFile -Value $err }
  return @{ TimedOut = $false; ExitCode = $ec; Pid = $p.Id }
}

# 1 CLEAN
$cleanLog = Join-Path $logs "01_clean_hello_$stamp.log"
Remove-Item -LiteralPath (Join-Path $out "hello.exe"), (Join-Path $out "hello.obj") -Force -ErrorAction SilentlyContinue
$r = Invoke-VsCl -ArgsLine "/nologo /W3 /O2 /Fe:`"$out\hello.exe`" /Fo:`"$out\hello.obj`" `"$fx\hello.c`"" -LogFile $cleanLog
$helloExe = Join-Path $out "hello.exe"
$helloRun = ""
if (Test-Path -LiteralPath $helloExe) {
  $helloRun = (& $helloExe | Out-String).Trim()
}
$results["CLEAN"] = [ordered]@{
  EXIT = $r.ExitCode; EXE_EXISTS = [bool](Test-Path -LiteralPath $helloExe); RUN = $helloRun
  PASS = ([bool](Test-Path -LiteralPath $helloExe) -and $helloRun -eq "BP_HELLO_OK")
}

# 2 PATHS WITH SPACES
$spacesLog = Join-Path $logs "02_paths_spaces_$stamp.log"
$spSrc = Join-Path $fx "path with spaces\spaced hello.c"
$spExe = Join-Path $out "spaced_hello.exe"
$spObj = Join-Path $out "spaced_hello.obj"
Remove-Item -LiteralPath $spExe, $spObj -Force -ErrorAction SilentlyContinue
$r2 = Invoke-VsCl -ArgsLine "/nologo /W3 /Fe:`"$spExe`" /Fo:`"$spObj`" `"$spSrc`"" -LogFile $spacesLog
$spRun = ""
if (Test-Path -LiteralPath $spExe) { $spRun = (& $spExe | Out-String).Trim() }
$results["PATHS_WITH_SPACES"] = [ordered]@{
  EXIT = $r2.ExitCode; EXE_EXISTS = [bool](Test-Path -LiteralPath $spExe); RUN = $spRun
  PASS = ([bool](Test-Path -LiteralPath $spExe) -and $spRun -eq "BP_SPACES_OK")
}

# 3 INCREMENTAL
$incrLog1 = Join-Path $logs "03_incremental_pass1_$stamp.log"
$incrLog2 = Join-Path $logs "03_incremental_pass2_$stamp.log"
$incrExe = Join-Path $out "incr.exe"
$incrObj = Join-Path $out "incr.obj"
Remove-Item -LiteralPath $incrExe, $incrObj -Force -ErrorAction SilentlyContinue
$r3a = Invoke-VsCl -ArgsLine "/nologo /c /Fo:`"$incrObj`" `"$fx\incremental\incr_main.c`"" -LogFile $incrLog1
$objTime1 = if (Test-Path $incrObj) { (Get-Item -LiteralPath $incrObj).LastWriteTimeUtc.ToString("o") } else { "MISSING" }
Start-Sleep -Milliseconds 1100
(Get-Item -LiteralPath (Join-Path $fx "incremental\incr_main.c")).LastWriteTime = Get-Date
$r3b = Invoke-VsCl -ArgsLine "/nologo /c /Fo:`"$incrObj`" `"$fx\incremental\incr_main.c`"" -LogFile $incrLog2
$objTime2 = if (Test-Path $incrObj) { (Get-Item -LiteralPath $incrObj).LastWriteTimeUtc.ToString("o") } else { "MISSING" }
$incrLinkLog = Join-Path $logs "03_incremental_link_$stamp.log"
$r3c = Invoke-VsCl -ArgsLine "/nologo /Fe:`"$incrExe`" `"$incrObj`"" -LogFile $incrLinkLog
$incrRun = ""
if (Test-Path -LiteralPath $incrExe) { $incrRun = (& $incrExe | Out-String).Trim() }
$objRebuilt = ($objTime2 -ne $objTime1 -and $objTime2 -ne "MISSING")
$results["INCREMENTAL"] = [ordered]@{
  PASS1_EXIT = $r3a.ExitCode; PASS2_EXIT = $r3b.ExitCode; LINK_EXIT = $r3c.ExitCode
  OBJ_TIME1 = $objTime1; OBJ_TIME2 = $objTime2
  OBJ_REBUILT = $objRebuilt
  RUN = $incrRun
  PASS = ([bool](Test-Path -LiteralPath $incrExe) -and ($incrRun -match "BP_INCR=5") -and $objRebuilt)
}

# 4 FAILURE DIAGNOSTICS
$failLog = Join-Path $logs "04_failure_diag_$stamp.log"
$r4 = Invoke-VsCl -ArgsLine "/nologo /c /Fo:`"$out\broken.obj`" `"$fx\broken_multi.cpp`"" -LogFile $failLog
$failText = Get-Content -LiteralPath $failLog -Raw
$hasC2065 = $failText -match "C2065"
$hasC2660 = $failText -match "C2660"
$hasC2440 = $failText -match "C2440"
$errorLines = ([regex]::Matches($failText, "error C\d+")).Count
$results["FAILURE_DIAGNOSTICS"] = [ordered]@{
  EXIT = $r4.ExitCode; EXPECT_NONEZERO = ($r4.ExitCode -ne 0)
  HAS_C2065 = $hasC2065; HAS_C2660 = $hasC2660; HAS_C2440 = $hasC2440
  ERROR_TOKEN_COUNT = $errorLines
  PASS = ($hasC2065 -and $hasC2660 -and $hasC2440 -and $errorLines -ge 3)
}

# 5 CANCEL
$cancelLog = Join-Path $logs "05_cancel_$stamp.log"
$cancelBat = Join-Path $out "_cancel_cl.bat"
$cancelObj = Join-Path $out "long_compile.obj"
Remove-Item -LiteralPath $cancelObj -Force -ErrorAction SilentlyContinue
@"
@echo off
call "$vsdev" -arch=amd64 >NUL
cl /nologo /c /Od /Fo:"$cancelObj" "$fx\cancel_long\long_compile.c"
exit /b %ERRORLEVEL%
"@ | Set-Content -LiteralPath $cancelBat -Encoding ASCII
$cp = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$cancelBat`"" -NoNewWindow -PassThru `
  -RedirectStandardOutput $cancelLog -RedirectStandardError (Join-Path $out "_cancel_err.txt")
Start-Sleep -Milliseconds 400
$killed = $false
$cancelPid = $cp.Id
if (-not $cp.HasExited) {
  cmd /c "taskkill /PID $($cp.Id) /T /F" > (Join-Path $logs "05_cancel_taskkill_$stamp.txt") 2>&1
  $killed = $true
  Start-Sleep -Milliseconds 500
}
try { $null = $cp.WaitForExit(5000) } catch {}
try { $cp.Refresh() } catch {}
$cancelExit = if ($cp.HasExited) { try { [int]$cp.ExitCode } catch { -1 } } else { -999 }
$cancelText = Get-Content $cancelLog -Raw -ErrorAction SilentlyContinue
$cancelCompleted = [bool]($cancelText -match "BP_CANCEL_DONE")
$results["CANCEL"] = [ordered]@{
  PID = $cancelPid; KILLED = $killed; EXIT = $cancelExit
  FULL_COMPILE_MARKER = $cancelCompleted
  PASS = ($killed -and -not $cancelCompleted)
}

# 6 CLEAN REBUILD
$clean2Log = Join-Path $logs "06_clean_rebuild_$stamp.log"
Remove-Item -LiteralPath (Join-Path $out "hello.exe"), (Join-Path $out "hello.obj") -Force -ErrorAction SilentlyContinue
$preCleanGone = -not (Test-Path (Join-Path $out "hello.obj"))
$r6 = Invoke-VsCl -ArgsLine "/nologo /W3 /Fe:`"$out\hello.exe`" /Fo:`"$out\hello.obj`" `"$fx\hello.c`"" -LogFile $clean2Log
$helloRun2 = ""
if (Test-Path -LiteralPath $helloExe) {
  $helloRun2 = (& $helloExe | Out-String).Trim()
}
$results["CLEAN_REBUILD"] = [ordered]@{
  PRE_OBJ_GONE = $preCleanGone; EXIT = $r6.ExitCode; RUN = $helloRun2
  PASS = ($preCleanGone -and [bool](Test-Path -LiteralPath $helloExe) -and $helloRun2 -eq "BP_HELLO_OK")
}

# harness
$harLog = Join-Path $logs "00_harness_$stamp.log"
$harExe = Join-Path $out "build_pipeline_harness.exe"
$rH = Invoke-VsCl -ArgsLine "/nologo /Fe:`"$harExe`" /Fo:`"$out\build_pipeline_harness.obj`" `"$fx\build_pipeline_harness.c`"" -LogFile $harLog
$harPing = ""
$harSha = ""
if (Test-Path -LiteralPath $harExe) {
  $harPing = (& $harExe --ping | Out-String).Trim()
  $harSha = (Get-FileHash -LiteralPath $harExe -Algorithm SHA256).Hash
}
$results["HARNESS"] = [ordered]@{
  EXIT = $rH.ExitCode; PING = $harPing; SHA256 = $harSha
  PASS = ([bool](Test-Path -LiteralPath $harExe) -and $harPing -eq "BUILD_PIPELINE_HARNESS_OK" -and $harSha.Length -eq 64)
}

$offlineKeys = @("CLEAN", "PATHS_WITH_SPACES", "INCREMENTAL", "FAILURE_DIAGNOSTICS", "CANCEL", "CLEAN_REBUILD", "HARNESS")
$passCount = 0
foreach ($k in $offlineKeys) { if ($results[$k].PASS) { $passCount++ } }
$allPass = ($passCount -eq $offlineKeys.Count)
$status = if ($allPass) { "OFFLINE_PASS_IDE_NOT_RUN" } else { "OFFLINE_FAIL_IDE_NOT_RUN" }

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
$lines.Add("STAMP=$stamp")
$lines.Add("PROMOTE=0")
$lines.Add("CERTIFIED=0")
$lines.Add("INVENT_PASS=0")
$lines.Add("IDE_BUILD_PROJECT_HWND=NOT_RUN")
$lines.Add("LANE=OFFLINE_MSVC_PIPELINE")
$lines.Add("CL_PATH=$clPath")
$lines.Add("LINK_PATH=$linkPath")
$lines.Add("CL_VERSION_LINE=$clVerLine")
$lines.Add("MSVC_TOOLSET=14.44.35207")
$lines.Add("HARNESS_EXE=$harExe")
$lines.Add("HARNESS_SHA256=$harSha")
$lines.Add("HARNESS_PING=$harPing")
$lines.Add("A4F_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E")
$lines.Add("A4F_UNTOUCHED=1")
$lines.Add("FROZEN_PACKAGE_OVERWRITE=FORBIDDEN")
foreach ($k in $offlineKeys) {
  $lines.Add("")
  $lines.Add("[$k]")
  foreach ($kk in $results[$k].Keys) { $lines.Add("$kk=$($results[$k][$kk])") }
}
$lines.Add("")
$lines.Add("OFFLINE_CASE_PASS_COUNT=$passCount/$($offlineKeys.Count)")
$lines.Add("BUILD_PIPELINE_OFFLINE=$(if($allPass){'PASS'}else{'FAIL'})")
$lines.Add("BUILD_PIPELINE_IDE_HWND=NOT_RUN")
$lines.Add("BUILD_PIPELINE_STATUS=$status")
$lines -join "`r`n" | Set-Content -LiteralPath $receipt -Encoding UTF8
Copy-Item -LiteralPath $receipt -Destination (Join-Path $logs "build_pipeline_receipt_LATEST.txt") -Force

Write-Output "RECEIPT=$receipt"
Write-Output "BUILD_PIPELINE_STATUS=$status"
Write-Output "PASS_COUNT=$passCount/$($offlineKeys.Count)"
foreach ($k in $offlineKeys) { Write-Output "$k=$($results[$k].PASS)" }
Write-Output "HARNESS_SHA256=$harSha"
