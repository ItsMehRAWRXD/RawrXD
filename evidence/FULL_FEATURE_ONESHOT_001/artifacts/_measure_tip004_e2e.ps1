# Measure tip_final_004 full-feature candidate. PROMOTE=0. Never touch A4F.
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$Pkg = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package'
$Tip = Join-Path $Pkg 'tip_final_004\RawrXD-Win32IDE-Native-Ext.exe'
$A4F = Join-Path $Pkg 'RawrXD-Win32IDE-Native.exe'
$OutDir = Join-Path $Root 'artifacts'
$LogDir = Join-Path $Root 'logs'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Receipt = Join-Path $OutDir "TIP004_MEASURE_$Stamp.txt"
$HwndLog = Join-Path $OutDir "tip004_hwnd_panels_$Stamp.txt"
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$s) { $lines.Add($s); Write-Host $s }

L "MEASURE_START=$Stamp"
L "PROMOTE=0"
L "CERTIFIED=0"
L "PRODUCT_PASS=0"

$tipHash = (Get-FileHash -Algorithm SHA256 $Tip).Hash.ToUpperInvariant()
$a4fHash = (Get-FileHash -Algorithm SHA256 $A4F).Hash.ToUpperInvariant()
$chat002 = Join-Path $Pkg 'tip_chat_ctrl_enter_002\RawrXD-Win32IDE-Native-Ext.exe'
$chatHash = (Get-FileHash -Algorithm SHA256 $chat002).Hash.ToUpperInvariant()
L "TIP_FINAL_004_SHA256=$tipHash"
L "TIP_CHAT_002_SHA256=$chatHash"
L "A4F_LIVE_SHA256=$a4fHash"
L "A4F_EXPECTED=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E"
L "FROZEN_A4F_UNTOUCHED=$([int]($a4fHash -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))"
L "CHAT002_MATCH_2CB03699=$([int]($chatHash -eq '2CB036995C8F8D371BCACEA575CE3E4BECEA0CBE792BAA67508C702A79AA0DF7'))"

$bytes = [IO.File]::ReadAllBytes($Tip)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
L "TIP_HAS_CreatePseudoConsole=$([int]$ascii.Contains('CreatePseudoConsole'))"
L "TIP_HAS_os26300_capture=$([int]$ascii.Contains('os26300_capture'))"
L "TIP_HAS_GhostText=$([int]$ascii.Contains('GhostText'))"

Get-Process -Name 'RawrXD-Win32IDE-Native-Ext','RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue |
  ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {} }
Start-Sleep -Milliseconds 400

$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$conptyBat = Join-Path $LogDir '_run_conpty_capture_tip004.bat'
$conptyOut = Join-Path $LogDir 'conpty_capture_tip004.txt'
@"
@echo off
call "$vcvars" >nul
cd /d "$Root"
if not exist bin mkdir bin
cl /nologo /EHsc /O2 /I F:\rawrxd\src\win32app /Fe:bin\terminal_conpty_capture_tip004.exe harness\terminal_conpty_capture.cpp F:\rawrxd\src\win32app\Win32TerminalManager.cpp /link /nologo > logs\conpty_tip004_build.log 2>&1
if errorlevel 1 exit /b 1
bin\terminal_conpty_capture_tip004.exe > logs\conpty_capture_tip004_stdout.txt 2>&1
exit /b %ERRORLEVEL%
"@ | Set-Content -Path $conptyBat -Encoding ASCII

cmd /c "`"$conptyBat`""
$capRc = $LASTEXITCODE
L "CONPTY_HARNESS_RC=$capRc"
$runCap = Join-Path $LogDir 'conpty_capture_run.txt'
if (Test-Path $runCap) {
  Copy-Item $runCap $conptyOut -Force
  Get-Content $conptyOut | ForEach-Object { L "CONPTY_LINE=$_" }
  $capText = Get-Content $conptyOut -Raw
  $termPass = ($capText -match 'TERMINAL_CAPTURE=PASS') -and ($capText -match 'CAPTURE_HAS_MARK=1') -and ($capText -match 'TRANSPORT=2')
  L "TERMINAL_CAPTURE_ON_TIP004_SOURCE=$([string]$(if($termPass){'PASS'}else{'FAIL'}))"
} else {
  L "TERMINAL_CAPTURE_ON_TIP004_SOURCE=FAIL"
  L "CONPTY_RECEIPT_MISSING=1"
}
L "TERMINAL_ATTRIBUTED_TIP_SHA=$tipHash"
L "NOTE=ConPTY harness links Win32TerminalManager.cpp used by tip_final_004 build; tip binary contains CreatePseudoConsole+os26300_capture"

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class PanelHwnd {
  public delegate bool EnumProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static string Text(IntPtr h){ var sb=new StringBuilder(512); GetWindowTextW(h,sb,sb.Capacity); return sb.ToString(); }
  public static string Cls(IntPtr h){ var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity); return sb.ToString(); }
}
"@

$ud = Join-Path $OutDir ("tip004_ud_" + $Stamp)
New-Item -ItemType Directory -Force -Path $ud | Out-Null
$p = Start-Process -FilePath $Tip -ArgumentList @("--user-data-dir=$ud") -PassThru -WindowStyle Normal
L "TIP_PID=$($p.Id)"
$deadline = (Get-Date).AddSeconds(25)
$main = [IntPtr]::Zero
$script:foundMain = [IntPtr]::Zero
while ((Get-Date) -lt $deadline -and $main -eq [IntPtr]::Zero) {
  Start-Sleep -Milliseconds 400
  [PanelHwnd]::EnumWindows({
    param([IntPtr]$h, [IntPtr]$lp)
    $pidOut = 0
    [void][PanelHwnd]::GetWindowThreadProcessId($h, [ref]$pidOut)
    if ($pidOut -eq $p.Id -and [PanelHwnd]::IsWindowVisible($h)) {
      $t = [PanelHwnd]::Text($h)
      if ($t -match 'RawrXD|Win32IDE|IDE') { $script:foundMain = $h }
    }
    return $true
  }, [IntPtr]::Zero)
  if ($script:foundMain -ne [IntPtr]::Zero) { $main = $script:foundMain }
}
L "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"

$hits = New-Object System.Collections.Generic.List[string]
$all = New-Object System.Collections.Generic.List[string]
$script:walkStack = New-Object System.Collections.Generic.Stack[IntPtr]
if ($main -ne [IntPtr]::Zero) {
  $script:walkStack.Push($main)
  while ($script:walkStack.Count -gt 0) {
    $h = $script:walkStack.Pop()
    $t = [PanelHwnd]::Text($h)
    $c = [PanelHwnd]::Cls($h)
    $vis = [PanelHwnd]::IsWindowVisible($h)
    if ($t -or $c) { $all.Add(("0x{0:X}|vis={1}|cls={2}|txt={3}" -f $h.ToInt64(), [int]$vis, $c, $t)) }
    foreach ($needle in @('Output','Problems','Debug','Terminal','Build')) {
      if (($t -match $needle) -or ($c -match $needle)) {
        $hits.Add(("HIT_{0}=0x{1:X}|cls={2}|txt={3}" -f $needle.ToUpperInvariant(), $h.ToInt64(), $c, $t))
      }
    }
    [PanelHwnd]::EnumChildWindows($h, {
      param([IntPtr]$ch, [IntPtr]$lp)
      $script:walkStack.Push($ch)
      return $true
    }, [IntPtr]::Zero) | Out-Null
  }
}
$hits | ForEach-Object { L $_ }
$all | Set-Content -Path $HwndLog -Encoding UTF8
L "HWND_ENUM_COUNT=$($all.Count)"
L "HWND_HIT_COUNT=$($hits.Count)"

$hasOut = [int](($hits | Where-Object { $_ -match '^HIT_OUTPUT=' }).Count -gt 0)
$hasProb = [int](($hits | Where-Object { $_ -match '^HIT_PROBLEMS=' }).Count -gt 0)
$hasDbg = [int](($hits | Where-Object { $_ -match '^HIT_DEBUG=' }).Count -gt 0)
$hasTerm = [int](($hits | Where-Object { $_ -match '^HIT_TERMINAL=' }).Count -gt 0)
$hasBuild = [int](($hits | Where-Object { $_ -match '^HIT_BUILD=' }).Count -gt 0)
L "HWND_OUTPUT_PRESENT=$hasOut"
L "HWND_PROBLEMS_PRESENT=$hasProb"
L "HWND_DEBUG_PRESENT=$hasDbg"
L "HWND_TERMINAL_PRESENT=$hasTerm"
L "HWND_BUILD_PRESENT=$hasBuild"
L "OUTPUT_PANEL=NOT_RUN"
L "PROBLEMS_PANEL=NOT_RUN"
L "DEBUG_CONSOLE=NOT_RUN"
L "FOUR_PANEL_INTEGRATION=NOT_VERIFIED"
L "IDE_BUILD_PROJECT_HWND=NOT_RUN"
L "NOTE_HWND=Presence flags only; no E2E channel/functional PASS invented"

try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Milliseconds 500
Get-Process -Id $p.Id -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

$bp = Join-Path $Root 'harness\run_build_pipeline_gate.ps1'
if (Test-Path $bp) {
  try {
    $bpOut = & powershell -NoProfile -ExecutionPolicy Bypass -File $bp 2>&1 | Out-String
    $bpOut.Trim().Split("`n") | Select-Object -First 40 | ForEach-Object { L ("BUILDPIPE=" + $_.TrimEnd()) }
  } catch {
    L "BUILD_PIPELINE_EXCEPTION=$($_.Exception.Message)"
  }
} else {
  L "BUILD_PIPELINE=HARNESS_ABSENT"
}

L "MEASURE_END=$(Get-Date -Format o)"
$lines | Set-Content -Path $Receipt -Encoding UTF8
Write-Host "RECEIPT=$Receipt"
Write-Host "HWND_LOG=$HwndLog"
