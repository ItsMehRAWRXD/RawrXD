#Requires -Version 5.1
# T14 Model routing: explicit qwen3:8b then switch to gemma3:4b. PROMOTE=0 no rebuild.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\MODEL_ROUTE'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$OllamaLog = Join-Path $CandDir 'ollama_debug.log'
$LogFile = Join-Path $OutDir 'RUNLOG.txt'
$ModelA = 'qwen3:8b'
$ModelB = 'gemma3:4b'
$PromptA = 'Reply with exactly one short sentence containing the marker ROUTE_A_QWEN3 and nothing else.'
$PromptB = 'Reply with exactly one short sentence containing the marker ROUTE_B_GEMMA3 and nothing else.'

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $LogFile -Value $line
  Write-Output $line
}
Set-Content -LiteralPath $LogFile -Value ''
WLog 'T14 MODEL_ROUTE START PROMOTE=0'

$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class ModelRouteUi {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public const uint WM_COMMAND = 0x0111; public const uint WM_SETTEXT = 0x000C; public const uint BM_CLICK = 0x00F5;
  public const int GWL_ID = -12; public const int BN_CLICKED = 0;
  public static void ClickChild(IntPtr parent, IntPtr btn, int id) {
    if (btn != IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    IntPtr wp = (IntPtr)((BN_CLICKED << 16) | (id & 0xFFFF));
    SendMessageW(parent, WM_COMMAND, wp, btn); PostMessageW(parent, WM_COMMAND, wp, btn);
  }
  public static int SetEdit(IntPtr edit, string text) {
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p); Marshal.FreeHGlobal(p);
    SetWindowTextW(edit, text); return GetWindowTextLengthW(edit);
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p); if (p != pid) return true;
      var cls = new StringBuilder(256); GetClassNameW(h, cls, 256);
      if (cls.ToString() == "RawrXD_IDE_Window") { found = h; return false; } return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => { if (GetWindowLongW(h, GWL_ID) == id) { found = h; return false; } return true; }, IntPtr.Zero);
    return found;
  }
  public static string Text(IntPtr h) {
    int len = SendMessageW(h, 0x000E, IntPtr.Zero, IntPtr.Zero).ToInt32();
    if (len <= 0) len = GetWindowTextLengthW(h); if (len <= 0) return "";
    IntPtr buf = Marshal.AllocHGlobal((len + 2) * 2);
    try { SendMessageW(h, 0x000D, (IntPtr)(len + 1), buf); return Marshal.PtrToStringUni(buf) ?? ""; }
    finally { Marshal.FreeHGlobal(buf); }
  }
  public static string SelectModel(IntPtr main, IntPtr combo, string needle) {
    int cnt = SendMessageW(combo, 0x0146, IntPtr.Zero, IntPtr.Zero).ToInt32();
    for (int i = 0; i < cnt; i++) {
      int tlen = SendMessageW(combo, 0x0149, (IntPtr)i, IntPtr.Zero).ToInt32();
      if (tlen <= 0) continue;
      IntPtr buf = Marshal.AllocHGlobal((tlen + 2) * 2);
      try {
        SendMessageW(combo, 0x0148, (IntPtr)i, buf);
        string item = Marshal.PtrToStringUni(buf) ?? "";
        if (item.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
          SendMessageW(combo, 0x014E, (IntPtr)i, IntPtr.Zero);
          IntPtr wp = (IntPtr)((1206 & 0xFFFF) | (1 << 16));
          PostMessageW(main, WM_COMMAND, wp, combo);
          return item;
        }
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return "";
  }
  public static string DumpModels(IntPtr combo) {
    var sb = new StringBuilder();
    int cnt = SendMessageW(combo, 0x0146, IntPtr.Zero, IntPtr.Zero).ToInt32();
    for (int i = 0; i < cnt; i++) {
      int tlen = SendMessageW(combo, 0x0149, (IntPtr)i, IntPtr.Zero).ToInt32();
      if (tlen <= 0) continue;
      IntPtr buf = Marshal.AllocHGlobal((tlen + 2) * 2);
      try {
        SendMessageW(combo, 0x0148, (IntPtr)i, buf);
        string item = Marshal.PtrToStringUni(buf) ?? "";
        sb.AppendLine(i + "|" + item);
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return sb.ToString();
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
$size = (Get-Item $CandExe).Length
WLog "PRE_HASH sha=$sha size=$size"
if ($sha -ne $ExpectSha) { WLog 'HASH_MISMATCH'; exit 3 }

Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe; $psi.WorkingDirectory = $CandDir; $psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCH pid=$($proc.Id)"

$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main = [ModelRouteUi]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [ModelRouteUi]::IsWindowVisible($main)) {
    if ([ModelRouteUi]::FindChildById($main, 1202) -ne [IntPtr]::Zero) { break }
  }
  Start-Sleep -Milliseconds 300
}
if ($main -eq [IntPtr]::Zero) { WLog 'MAIN_TIMEOUT'; exit 4 }
[void][ModelRouteUi]::ShowWindow($main, 9)
[void][ModelRouteUi]::SetForegroundWindow($main)
WLog ("HWND=0x{0:X}" -f $main.ToInt64())

$inputEdit = [ModelRouteUi]::FindChildById($main, 1202)
$outputEdit = [ModelRouteUi]::FindChildById($main, 1203)
$btnSend = [ModelRouteUi]::FindChildById($main, 1204)
$combo = [ModelRouteUi]::FindChildById($main, 1206)
$btnClear = [ModelRouteUi]::FindChildById($main, 1205)
$sidebar = [ModelRouteUi]::FindChildById($main, 1200)
if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }

$models = [ModelRouteUi]::DumpModels($combo)
Set-Content -LiteralPath (Join-Path $OutDir 'model_combo_rows.txt') -Value $models -Encoding utf8
WLog 'COMBO_ROWS_WRITTEN'

function Read-OllamaDelta([int64]$offset) {
  if (-not (Test-Path $OllamaLog)) { return '' }
  $fs = [IO.File]::Open($OllamaLog, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $fs.Position = [Math]::Min($offset, $fs.Length)
    $sr = New-Object IO.StreamReader($fs)
    return $sr.ReadToEnd()
  } finally { $fs.Close() }
}

function Invoke-ChatTurn([string]$modelNeedle, [string]$prompt, [string]$marker, [string]$tag) {
  $sel = [ModelRouteUi]::SelectModel($main, $combo, $modelNeedle)
  WLog "$tag MODEL_UI='$sel'"
  if (-not $sel) { return @{ ok=0; model=''; marker=0; ui=''; selected='' } }
  Start-Sleep -Milliseconds 400
  if ($btnClear -ne [IntPtr]::Zero) {
    [ModelRouteUi]::ClickChild($sidebar, $btnClear, 1205)
    Start-Sleep -Milliseconds 250
  }
  $before = [ModelRouteUi]::Text($outputEdit)
  $off = if (Test-Path $OllamaLog) { (Get-Item $OllamaLog).Length } else { 0 }
  [void][ModelRouteUi]::SetEdit($inputEdit, $prompt)
  [ModelRouteUi]::ClickChild($sidebar, $btnSend, 1204)
  WLog "$tag PROMPT_SUBMITTED"
  $gotMarker = 0; $modelId = 'NONE'; $ui = ''; $done = 0
  $dl = (Get-Date).AddSeconds(240)
  while ((Get-Date) -lt $dl) {
    if ($proc.HasExited) { WLog "$tag CRASH exit=$($proc.ExitCode)"; break }
    $delta = Read-OllamaDelta $off
    if ($delta) {
      $mm = [regex]::Matches($delta, 'MODEL=([^\s]+)')
      if ($mm.Count -gt 0) { $modelId = $mm[$mm.Count-1].Groups[1].Value }
      if ($delta -match 'DONE_REASON=stop') { $done = 1 }
    }
    $ui = [ModelRouteUi]::Text($outputEdit)
    if ($ui -and $ui.Length -gt $before.Length -and $ui -match [regex]::Escape($marker)) {
      $gotMarker = 1
      break
    }
    if ($done -eq 1) {
      Start-Sleep -Milliseconds 800
      $ui = [ModelRouteUi]::Text($outputEdit)
      if ($ui -match [regex]::Escape($marker)) { $gotMarker = 1 }
      break
    }
    Start-Sleep -Milliseconds 250
  }
  Set-Content -LiteralPath (Join-Path $OutDir ("RESPONSE_{0}.txt" -f $tag)) -Value $ui -Encoding utf8
  $deltaAll = Read-OllamaDelta $off
  Set-Content -LiteralPath (Join-Path $OutDir ("ollama_delta_{0}.txt" -f $tag)) -Value $deltaAll -Encoding utf8
  $ok = 0
  if ($modelId -match [regex]::Escape($modelNeedle) -and ($gotMarker -eq 1 -or ($ui.Length -gt $before.Length))) { $ok = 1 }
  if ($modelId -notmatch [regex]::Escape($modelNeedle)) { $ok = 0 }
  WLog "$tag BACKEND_MODEL=$modelId UI_MARKER=$gotMarker UI_LEN=$($ui.Length) OK=$ok"
  return @{ ok=$ok; model=$modelId; marker=$gotMarker; ui=$ui; selected=$sel }
}

$a = Invoke-ChatTurn $ModelA $PromptA 'ROUTE_A_QWEN3' 'A'
$b = Invoke-ChatTurn $ModelB $PromptB 'ROUTE_B_GEMMA3' 'B'

$routeA = if ($a.ok -eq 1 -and $a.model -match 'qwen3:8b') { 'PASS' } else { 'FAIL' }
$routeB = if ($b.ok -eq 1 -and $b.model -match 'gemma3:4b') { 'PASS' } else { 'FAIL' }
$switch = if ($routeA -eq 'PASS' -and $routeB -eq 'PASS' -and $a.model -ne $b.model) { 'PASS' } else { 'FAIL' }
$overall = if ($switch -eq 'PASS') { 'PASS' } else { 'FAIL' }

$postSha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
$alive = -not $proc.HasExited
if ($alive) { try { $proc.Kill() } catch {} }

$receipt = @"
# T14 MODEL_ROUTE RECEIPT

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
GATE=FINISH_25_T14
CERT_EXE=$CandExe
CERT_EXE_SHA=$ExpectSha
SHA_PRE=$sha
SHA_POST=$postSha
SHA_MATCH=$([int]($sha -eq $ExpectSha -and $postSha -eq $ExpectSha))
MODEL_A_TARGET=$ModelA
MODEL_A_UI=$($a.selected)
MODEL_A_BACKEND=$($a.model)
MODEL_A_MARKER=$($a.marker)
ROUTE_QWEN3_8B=$routeA
MODEL_B_TARGET=$ModelB
MODEL_B_UI=$($b.selected)
MODEL_B_BACKEND=$($b.model)
MODEL_B_MARKER=$($b.marker)
ROUTE_SWITCH=$routeB
MODEL_SWITCH=$switch
RESULT=$overall
PROCESS_ALIVE_AT_END=$([int]$alive)
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
NOTE=Chat Send path only (not Request-A Cancel). Fail-closed on backend MODEL= identity.
"@
Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT.md') -Value $receipt -Encoding utf8
Copy-Item (Join-Path $OutDir 'RECEIPT.md') 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\PHASE3\T14_MODEL_ROUTE_RECEIPT.md' -Force
WLog "RESULT=$overall SWITCH=$switch"
Write-Output "T14_RESULT=$overall"
if ($overall -ne 'PASS') { exit 1 }
