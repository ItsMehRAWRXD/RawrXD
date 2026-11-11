#Requires -Version 5.1
param(
  [ValidateSet('BM_CLICK','WM_COMMAND_BN_CLICKED')]
  [string]$ClickMode = 'BM_CLICK',
  [int]$ArmSeconds = 25,
  [switch]$DualSetEdit
)
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL'
$Logs = Join-Path $OutDir 'logs'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Tag = $ClickMode
$Log = Join-Path $OutDir ("PHASE1_T03_{0}_RUNLOG_{1}.txt" -f $Tag, $Stamp)
$ResultPath = Join-Path $Logs ("phase1_t03_{0}_result_{1}.json" -f $Tag.ToLower(), $Stamp)
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Output $line
}
$cs = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Phase1T03Iso2 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_SETTEXT = 0x000C;
  public const uint BM_CLICK = 0x00F5;
  public static void ClickBm(IntPtr btn) {
    if (btn != IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
  }
  public static void ClickWmCommand(IntPtr parent, IntPtr btn, int id) {
    IntPtr wp = (IntPtr)((0 << 16) | (id & 0xFFFF));
    SendMessageW(parent, WM_COMMAND, wp, btn);
  }
  public static int SetEditWmOnly(IntPtr edit, string text) {
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p);
    Marshal.FreeHGlobal(p);
    return GetWindowTextLengthW(edit);
  }
  public static int SetEditDual(IntPtr edit, string text) {
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p);
    Marshal.FreeHGlobal(p);
    SetWindowTextW(edit, text);
    return GetWindowTextLengthW(edit);
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == "RawrXD_IDE_Window") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => {
      if (GetWindowLongW(h, -12) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null
$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog ("CLICK_MODE={0} DUAL_SETEDIT={1}" -f $ClickMode, [int]$DualSetEdit.IsPresent)
WLog ("SHA_PRE={0}" -f $sha)
if ($sha -ne $ExpectSha) { WLog 'SHA_DRIFT'; exit 3 }
Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe; $psi.WorkingDirectory = (Split-Path $CandExe); $psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog ("PID={0}" -f $proc.Id)
$main = [IntPtr]::Zero
$dl = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { WLog ("EXIT_EARLY {0}" -f $proc.ExitCode); break }
  $main = [Phase1T03Iso2]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [Phase1T03Iso2]::IsWindowVisible($main) -and
      [Phase1T03Iso2]::FindChildById($main, 1204) -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 300
}
[void][Phase1T03Iso2]::ShowWindow($main, 9)
[void][Phase1T03Iso2]::SetForegroundWindow($main)
WLog ("HWND=0x{0:X}" -f $main.ToInt64())
$inputHwnd = [Phase1T03Iso2]::FindChildById($main, 1202)
$send = [Phase1T03Iso2]::FindChildById($main, 1204)
$combo = [Phase1T03Iso2]::FindChildById($main, 1206)
$cnt = [Phase1T03Iso2]::SendMessageW($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
for ($i = 0; $i -lt $cnt; $i++) {
  $tlen = [Phase1T03Iso2]::SendMessageW($combo, 0x0149, [IntPtr]$i, [IntPtr]::Zero).ToInt32()
  if ($tlen -le 0) { continue }
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(($tlen + 2) * 2)
  try {
    [void][Phase1T03Iso2]::SendMessageW($combo, 0x0148, [IntPtr]$i, $buf)
    $item = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
  if ($item -like '*gemma3:4b*') {
    [void][Phase1T03Iso2]::SendMessageW($combo, 0x014E, [IntPtr]$i, [IntPtr]::Zero)
    WLog ("MODEL={0}" -f $item); break
  }
}
Start-Sleep -Milliseconds 500
$prompt = 'Write a very long detailed essay of at least 2000 words about Windows kernel scheduling.'
if ($DualSetEdit) {
  $setLen = [Phase1T03Iso2]::SetEditDual($inputHwnd, $prompt)
  WLog ("SETEDIT_MODE=DUAL SETEDIT_LEN={0}" -f $setLen)
} else {
  $setLen = [Phase1T03Iso2]::SetEditWmOnly($inputHwnd, $prompt)
  WLog ("SETEDIT_MODE=WM_SETTEXT_ONLY SETEDIT_LEN={0}" -f $setLen)
}
Start-Sleep -Milliseconds 200
if ($ClickMode -eq 'BM_CLICK') {
  [Phase1T03Iso2]::ClickBm($send)
  WLog 'REQUEST_A_SUBMITTED_BM_CLICK'
} else {
  [Phase1T03Iso2]::ClickWmCommand($main, $send, 1204)
  WLog 'REQUEST_A_SUBMITTED_WM_COMMAND_BN_CLICKED'
}
$crash = 0; $exitCode = $null
$armDl = (Get-Date).AddSeconds($ArmSeconds)
while ((Get-Date) -lt $armDl) {
  if ($proc.HasExited) {
    $crash = 1; $exitCode = $proc.ExitCode
    WLog ("CRASH exit={0} hex=0x{1:X8}" -f $exitCode, [uint32]$exitCode)
    break
  }
  Start-Sleep -Milliseconds 250
}
if (-not $proc.HasExited) {
  WLog ("NO_CRASH_{0}S" -f $ArmSeconds)
  try { $proc.Kill() } catch {}
  Start-Sleep 1
}
$shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog ("SHA_POST={0}" -f $shaPost)
$dumpCopy = $null
$crashDir = 'C:\Users\Garrett\AppData\Local\RawrXD\crashes'
if ($crash -eq 1 -and (Test-Path -LiteralPath $crashDir)) {
  $newest = Get-ChildItem -LiteralPath $crashDir -Filter 'rawrxd-*.dmp' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($newest) {
    $dumpCopy = Join-Path $Logs $newest.Name
    if (-not (Test-Path -LiteralPath $dumpCopy)) {
      Copy-Item -LiteralPath $newest.FullName -Destination $dumpCopy -Force
    }
    WLog ("DUMP_COPY={0}" -f $dumpCopy)
  }
}
$result = [ordered]@{
  CLICK_MODE = $ClickMode
  DUAL_SETEDIT = [int]$DualSetEdit.IsPresent
  CRASH = $crash
  EXIT_CODE = "$exitCode"
  ARM_SECONDS = $ArmSeconds
  CERT_EXE_SHA_BEFORE = $sha
  CERT_EXE_SHA_AFTER = $shaPost
  SHA_MATCH = [int]($sha -eq $shaPost -and $sha -eq $ExpectSha)
  SETEDIT_LEN = $setLen
  DUMP = $dumpCopy
  PRODUCT_DEFECT = 'NOT_PROVEN'
  REBUILD = 'HELD'
  PROMOTE = 0
  STAMP = $Stamp
  LOG = $Log
}
$result | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
WLog ("RESULT_JSON={0}" -f $ResultPath)
if ($crash -eq 1) { exit 1 } else { exit 0 }
