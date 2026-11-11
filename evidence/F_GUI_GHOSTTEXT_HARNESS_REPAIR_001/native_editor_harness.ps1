[CmdletBinding()]
param(
    [string]$Exe = 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe',
    [string]$Fixture = 'F:\rawrxd\evidence\F_GUI_GHOSTTEXT_HARNESS_REPAIR_001\fixture.cpp',
    [int]$TimeoutSeconds = 20,
    [switch]$Run
)

$ErrorActionPreference = 'Stop'
$expectedHash = '70E6B1700F8EDF7A3770F63A5B89565AB05798CAB4B8DFC784200153B786F9DA'

Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class NativeEditorHarness {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string ClassName(IntPtr h) { var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
}
'@

if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "Missing production executable: $Exe" }
if ((Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Production binary hash mismatch; refusing to run.' }
if (-not $Run) { Write-Output 'STATIC_ONLY=1'; Write-Output 'RUN_SKIPPED=1'; exit 0 }

# Ownership/isolation gate: classify exact candidate paths separately, but keep
# the stronger safety rule that every same-product native IDE blocks launch while
# shared mutable logs/configuration/Ollama state remain unproven.
$candidatePath = [IO.Path]::GetFullPath($Exe)
$candidatePath = [IO.Path]::GetFullPath((Get-Item -LiteralPath $candidatePath).FullName)
$inventory = @(Get-CimInstance Win32_Process -Filter "Name='rawrxd-win32ide-native.exe'" | ForEach-Object {
    $path = if ($_.ExecutablePath) { [IO.Path]::GetFullPath($_.ExecutablePath) } else { '' }
    [pscustomobject]@{ Pid = [int]$_.ProcessId; Path = $path; ExactCandidate = ($path -ieq $candidatePath); ParentPid = [int]$_.ParentProcessId; Creation = $_.CreationDate }
})
if ($inventory.Count -ne 0) {
    $summary = ($inventory | ForEach-Object { "PID=$($_.Pid) ExactCandidate=$($_.ExactCandidate) Path=$($_.Path)" }) -join '; '
    throw "Isolation gate failed; native IDE process(es) present: $summary"
}

$fixtureDir = Split-Path -Parent $Fixture
New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null
Set-Content -LiteralPath $Fixture -Value "int main() {`r`n    return 0;`r`n}`r`n" -NoNewline
$proc = Start-Process -FilePath $Exe -WorkingDirectory (Split-Path $Exe) -PassThru
$ownedPid = $proc.Id
$ownedStart = $proc.StartTime
try {
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline -and -not $proc.HasExited) {
    $proc.Refresh(); if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { break }; Start-Sleep -Milliseconds 100
  }
  if ($proc.HasExited) { throw "IDE exited during startup: $($proc.ExitCode)" }
  $root = $proc.MainWindowHandle
  if ($root -eq [IntPtr]::Zero) { throw 'No main window HWND became available.' }
  $editor = [IntPtr]::Zero
  [NativeEditorHarness]::EnumChildWindows($root, { param($h,$p)
    # IDC_EDITOR is 1001 in Win32IDE_CommandIDs.h. RichEdit20A is the
    # runtime class created by RICHEDIT_CLASSA in this production binary.
    if ([NativeEditorHarness]::ClassName($h) -eq 'RichEdit20A' -and [NativeEditorHarness]::GetDlgCtrlID($h) -eq 1001 -and [NativeEditorHarness]::IsWindowVisible($h) -and [NativeEditorHarness]::IsWindowEnabled($h)) { $script:editor = $h; return $false }
    return $true
  }, [IntPtr]::Zero) | Out-Null
  if ($editor -eq [IntPtr]::Zero) { throw 'Visible enabled RICHEDIT editor HWND not found.' }
  [NativeEditorHarness]::SetForegroundWindow($root) | Out-Null
  $guiThread = [uint32]0; [NativeEditorHarness]::GetWindowThreadProcessId($root, [ref]$guiThread) | Out-Null
  $myThread = [NativeEditorHarness]::GetCurrentThreadId()
  $attached = $false
  if ($guiThread -ne $myThread) { $attached = [NativeEditorHarness]::AttachThreadInput($myThread, $guiThread, $true) }
  try { [NativeEditorHarness]::SetFocus($editor) | Out-Null; Start-Sleep -Milliseconds 100; if ([NativeEditorHarness]::GetFocus() -ne $editor) { throw 'Editor focus verification failed.' } }
  finally { if ($attached) { [NativeEditorHarness]::AttachThreadInput($myThread, $guiThread, $false) | Out-Null } }
  $rect = New-Object NativeEditorHarness+RECT
  if (-not [NativeEditorHarness]::GetClientRect($editor, [ref]$rect) -or $rect.R -le 0 -or $rect.B -le 0) { throw 'Editor geometry verification failed.' }
  [pscustomobject]@{ ROOT_HWND=$root; EDITOR_HWND=$editor; CLASS='RichEdit50W'; WIDTH=$rect.R; HEIGHT=$rect.B; FOCUS_VERIFIED=$true } | ConvertTo-Json
}
finally {
  $owned = Get-CimInstance Win32_Process -Filter "ProcessId=$ownedPid" -ErrorAction SilentlyContinue
  $ownedPath = if ($owned -and $owned.ExecutablePath) { [IO.Path]::GetFullPath($owned.ExecutablePath) } else { '' }
  if ($proc -and -not $proc.HasExited -and $owned -and $ownedPath -ieq $candidatePath) { $proc.CloseMainWindow() | Out-Null; if (-not $proc.WaitForExit(5000)) { Write-Warning 'Graceful close did not complete; bounded cleanup required.'; Stop-Process -Id $ownedPid -Force } }
}
