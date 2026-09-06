$ErrorActionPreference = 'Continue'
$root = 'F:\~dev\rawrxd'
$trace = "$env:TEMP\P1PRA_E2E_TRACE.txt"
$rerun = "$root\evidence\P1_PRODUCT_RUNTIME_AUTHORITY_002\E2E_RERUN_POST_SEND_FIX.log"
if (-not (Test-Path $rerun)) { $rerun = "$root\E2E_RERUN_POST_SEND_FIX.log" }

Write-Host '=== PATTERN SCAN rerun+trace ==='
Select-String $rerun,$trace -Pattern 'load|loaded|model|resolve|hwnd|send|retry|user_prompt|generation|P1PRA|error|fail' -CaseSensitive:$false -ErrorAction SilentlyContinue | Select Path,LineNumber,Line

Write-Host "`n=== RUN.log TAIL ==="
$runObj = Get-ChildItem $root -Recurse -Filter RUN.log -File -ErrorAction SilentlyContinue | Sort LastWriteTime -Descending | Select -First 1
$run = $runObj.FullName
Write-Host "RUN=$run"
Get-Content $run -Tail 120 -ErrorAction SilentlyContinue

Write-Host "`n=== SEND BOUNDARY CHECK ==="
Select-String $run -Pattern 'phase=user_prompt|user_prompt|handleCommandSend|COMMAND_SEND|Send' -CaseSensitive:$false -ErrorAction SilentlyContinue

Write-Host "`n=== AUTHORITY PROGRESSION ==="
Select-String $run,$trace -Pattern 'P1PRA_FINALIZE|P1PRA_CALLBACK|PRODUCT_INFERENCE|generation|inference|completion' -CaseSensitive:$false -ErrorAction SilentlyContinue

Write-Host "`n=== IDE PROCESS ==="
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Select Id,StartTime,MainWindowHandle,MainWindowTitle

Write-Host "`n=== LIVE RAWRXD HWNDs ==="
Add-Type 'using System;using System.Runtime.InteropServices;public class W{[DllImport("user32.dll")]public static extern bool EnumWindows(EnumWindowsProc p,IntPtr l);public delegate bool EnumWindowsProc(IntPtr h,IntPtr l);[DllImport("user32.dll")]public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);}'
[W]::EnumWindows({ param($h,$l) $p=0; [void][W]::GetWindowThreadProcessId($h,[ref]$p); $proc = Get-Process -Id $p -ErrorAction SilentlyContinue; if ($proc -and $proc.ProcessName -like 'RawrXD*') { "PID=$p HWND=0x$($h.ToInt64().ToString('X'))" }; $true }, [IntPtr]::Zero)

Write-Host "`n=== SEND CONTROL IDS (sample) ==="
Get-ChildItem "$root\src" -Recurse -File -Include '*.cpp','*.hpp','*.h','*.rc' -ErrorAction SilentlyContinue | Select-String 'IDC_CMD_SEND|12502|handleCommandSend|WM_COMMAND' | Select-Object -First 40 Path,LineNumber,Line

Write-Host "`n=== handleCommandSend CALLERS ==="
Get-ChildItem "$root\src" -Recurse -File -Include '*.cpp','*.hpp' -ErrorAction SilentlyContinue | Select-String 'handleCommandSend\s*\(' | Select Path,LineNumber,Line

Write-Host "`n=== user_prompt PUBLICATION ==="
Get-ChildItem "$root\src" -Recurse -File -Include '*.cpp','*.hpp','*.asm' -ErrorAction SilentlyContinue | Select-String 'user_prompt|phase=startup|appendRunLog' | Select Path,LineNumber,Line

Write-Host "`n=== AUTOMATION SEND MECHANISM ==="
Select-String $rerun -Pattern 'retry|Send|click|WM_COMMAND|BM_CLICK|PostMessage|SendMessage|HWND|composer|main=' -CaseSensitive:$false -ErrorAction SilentlyContinue

Write-Host "`n=== GATE VERDICT ==="
if (Select-String $run 'phase=user_prompt' -Quiet -ErrorAction SilentlyContinue) { 'SEND_BOUNDARY=PASS' } else { 'SEND_BOUNDARY=FAIL' }
if (Select-String $run,$trace 'P1PRA_FINALIZE=0' -Quiet -ErrorAction SilentlyContinue) { 'FINALIZE=PASS' } else { 'FINALIZE=FAIL' }
if (Get-ChildItem $root,$env:TEMP -Recurse -Filter E2E.log -File -ErrorAction SilentlyContinue) { 'E2E_LOG=PASS' } else { 'E2E_LOG=FAIL' }

Write-Host "`n=== EVIDENCE BUNDLE ==="
Write-Host '===RERUN==='
Get-Content $rerun -Tail 150 -ErrorAction SilentlyContinue
Write-Host '===TRACE==='
Get-Content $trace -Tail 150 -ErrorAction SilentlyContinue
Write-Host '===RUN==='
Get-Content $run -Tail 150 -ErrorAction SilentlyContinue
Write-Host '===E2E==='
Get-ChildItem $root,$env:TEMP -Recurse -Filter E2E.log -File -ErrorAction SilentlyContinue | Select LastWriteTime,Length,FullName
