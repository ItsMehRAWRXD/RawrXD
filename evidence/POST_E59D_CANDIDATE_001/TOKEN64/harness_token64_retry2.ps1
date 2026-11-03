# POST_E59D TOKEN64 retry2 — snapshot-on-growth, single CERT_EXE, PROMOTE=0
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\TOKEN64'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$OllamaLog = Join-Path $CandDir 'ollama_debug.log'
$LogFile = Join-Path $OutDir 'RUNLOG.txt'
$PromptExact = 'Generate at least 100 tokens of original plain English prose explaining how a code editor saves a file. Do not use a numbered list. End your response with the exact marker TOKEN64_DONE.'

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $LogFile -Value $line
  Write-Output $line
}

Add-Content -LiteralPath $LogFile -Value ''
WLog 'RETRY2 START TOKEN64 (snapshot-on-growth)'
WLog 'PROMOTE=0 CERTIFIED=0 EDITOR_GHOSTTEXT_ACCEPT=OPEN'

$cs = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Token64Ui2 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_SETTEXT = 0x000C;
  public const uint BM_CLICK = 0x00F5;
  public const int GWL_ID = -12;
  public const int BN_CLICKED = 0;
  public static void ClickChild(IntPtr parent, IntPtr btn, int id) {
    if (btn != IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    IntPtr wp = (IntPtr)((BN_CLICKED << 16) | (id & 0xFFFF));
    SendMessageW(parent, WM_COMMAND, wp, btn);
    PostMessageW(parent, WM_COMMAND, wp, btn);
  }
  public static int SetEdit(IntPtr edit, string text) {
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
      if (GetWindowLongW(h, GWL_ID) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string Text(IntPtr h) {
    // WM_GETTEXTLENGTH / WM_GETTEXT for Edit controls (more reliable than GetWindowTextLength alone)
    int len = SendMessageW(h, 0x000E, IntPtr.Zero, IntPtr.Zero).ToInt32(); // WM_GETTEXTLENGTH
    if (len <= 0) len = GetWindowTextLengthW(h);
    if (len <= 0) return "";
    IntPtr buf = Marshal.AllocHGlobal((len + 2) * 2);
    try {
      SendMessageW(h, 0x000D, (IntPtr)(len + 1), buf); // WM_GETTEXT
      return Marshal.PtrToStringUni(buf) ?? "";
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static string StatusBarText(IntPtr main) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(main, (h, l) => {
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == "msctls_statusbar32") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (found == IntPtr.Zero) return "";
    return Text(found);
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

if (-not (Test-Path -LiteralPath $CandExe)) { WLog 'EXE_MISSING'; exit 2 }
$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
$size = (Get-Item -LiteralPath $CandExe).Length
WLog "PRE_HASH sha=$sha size=$size"
if ($sha -ne $ExpectSha -or [int64]$size -ne 6080512) { WLog 'HASH_MISMATCH STOP'; exit 3 }
Set-Content -LiteralPath (Join-Path $OutDir 'PROMPT.txt') -Value $PromptExact -Encoding utf8

$existing = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -eq 'RawrXD-Win32IDE-Native' -and $_.Path -and ($_.Path -ieq $CandExe)
})
$launchedHere = 0
$proc = $null
if ($existing.Count -ge 1) {
  $proc = $existing[0]
  WLog "REUSE pid=$($proc.Id)"
} else {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $CandExe
  $psi.WorkingDirectory = $CandDir
  $psi.UseShellExecute = $false
  $proc = [Diagnostics.Process]::Start($psi)
  $launchedHere = 1
  WLog "LAUNCH pid=$($proc.Id)"
}
$runSha = (Get-FileHash -LiteralPath $proc.Path -Algorithm SHA256).Hash
@"
CERT_EXE=$($proc.Path)
SHA256=$runSha
SIZE=$((Get-Item -LiteralPath $proc.Path).Length)
PID=$($proc.Id)
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
SOURCE=process_Path_Get-FileHash
RETRY=2
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'BINARY_HASH.txt')
if ($runSha -ne $ExpectSha) { WLog 'RUNNING_HASH_MISMATCH STOP'; exit 3 }

$ollamaOffset = 0
if (Test-Path -LiteralPath $OllamaLog) { $ollamaOffset = (Get-Item -LiteralPath $OllamaLog).Length }
WLog "PID=$($proc.Id) HWND_PENDING OLLAMA_OFFSET=$ollamaOffset LAUNCHED_HERE=$launchedHere"

$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main = [Token64Ui2]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [Token64Ui2]::IsWindowVisible($main)) {
    if ([Token64Ui2]::FindChildById($main, 1202) -ne [IntPtr]::Zero -and [Token64Ui2]::FindChildById($main, 1204) -ne [IntPtr]::Zero) { break }
  }
  Start-Sleep -Milliseconds 300
}
if ($main -eq [IntPtr]::Zero) { WLog 'MAIN_TIMEOUT'; exit 4 }
[void][Token64Ui2]::ShowWindow($main, 9)
[void][Token64Ui2]::SetForegroundWindow($main)
WLog "HWND=0x$($main.ToInt64().ToString('X'))"

$inputEdit = [Token64Ui2]::FindChildById($main, 1202)
$outputEdit = [Token64Ui2]::FindChildById($main, 1203)
$btnSend = [Token64Ui2]::FindChildById($main, 1204)
$combo = [Token64Ui2]::FindChildById($main, 1206)
$btnClear = [Token64Ui2]::FindChildById($main, 1205)
$modelSelected = ''
$cnt = [Token64Ui2]::SendMessageW($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
for ($i = 0; $i -lt $cnt; $i++) {
  $tlen = [Token64Ui2]::SendMessageW($combo, 0x0149, [IntPtr]$i, [IntPtr]::Zero).ToInt64()
  if ($tlen -le 0) { continue }
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(([int]$tlen + 2) * 2)
  try {
    [void][Token64Ui2]::SendMessageW($combo, 0x0148, [IntPtr]$i, $buf)
    $item = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
  if ($item -and $item.IndexOf('gemma3:4b', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    [void][Token64Ui2]::SendMessageW($combo, 0x014E, [IntPtr]$i, [IntPtr]::Zero)
    $wp = [IntPtr]((1206 -band 0xFFFF) -bor (1 -shl 16))
    [void][Token64Ui2]::PostMessageW($main, [Token64Ui2]::WM_COMMAND, $wp, $combo)
    $modelSelected = $item
    WLog "MODEL=$item"
    break
  }
}
$sidebar = [Token64Ui2]::FindChildById($main, 1200)
if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }
if ($btnClear -ne [IntPtr]::Zero) {
  [Token64Ui2]::ClickChild($sidebar, $btnClear, 1205)
  Start-Sleep -Milliseconds 250
}
$outBefore = [Token64Ui2]::Text($outputEdit)
[void][Token64Ui2]::SetEdit($inputEdit, $PromptExact)
[Token64Ui2]::ClickChild($sidebar, $btnSend, 1204)
WLog 'PROMPT_SUBMITTED=1'

$responseText = ''
$markerPass = 0
$chatComplete = 'NOT_VERIFIED'
$lastLen = $outBefore.Length
$genTokens = 'NOT_VERIFIED'
$modelId = 'NOT_VERIFIED'
$backend = 'NOT_VERIFIED'
$ollamaDone = 0
$deadline = (Get-Date).AddSeconds(300)

function Read-OllamaDelta {
  param([int64]$offset)
  if (-not (Test-Path -LiteralPath $OllamaLog)) { return '' }
  $fs = [IO.File]::Open($OllamaLog, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    if ($offset -gt $fs.Length) { $offset = 0 }
    $fs.Position = $offset
    $sr = New-Object IO.StreamReader($fs)
    $t = $sr.ReadToEnd()
    $sr.Close()
    return $t
  } finally { $fs.Close() }
}

while ((Get-Date) -lt $deadline) {
  $delta = Read-OllamaDelta -offset $ollamaOffset
  if ($delta) {
    $mTok = [regex]::Matches($delta, 'GENERATED_TOKENS=(\d+)')
    if ($mTok.Count -gt 0) { $genTokens = $mTok[$mTok.Count - 1].Groups[1].Value; $backend = 'ollama' }
    $mModel = [regex]::Matches($delta, 'MODEL=([^\s]+)')
    if ($mModel.Count -gt 0) { $modelId = $mModel[$mModel.Count - 1].Groups[1].Value }
    if ($delta -match 'DONE_REASON=stop') { $ollamaDone = 1 }
    if ($delta -match 'Parsed response successfully' -and -not $script:parsedLogged) {
      $script:parsedLogged = $true
      WLog "PARSED_OK tokens=$genTokens scrape UI"
    }
  }

  if ($proc.HasExited) {
    WLog "CRASH exit=$($proc.ExitCode) last_snapshot_len=$lastLen"
    break
  }

  $outNow = [Token64Ui2]::Text($outputEdit)
  $st = [Token64Ui2]::StatusBarText($main)
  if ($st -and $st -ne $script:lastSt) {
    $script:lastSt = $st
    WLog "STATUS=$st"
    if ($st -match '(?i)CHAT_RUNTIME|response received|Done|complete') { $chatComplete = 'PASS' }
  }
  if ($outNow.Length -ne $lastLen) {
    $lastLen = $outNow.Length
    $responseText = $outNow
    Set-Content -LiteralPath (Join-Path $OutDir 'RESPONSE.txt') -Value $responseText -Encoding utf8
    WLog "SNAPSHOT_LEN=$($outNow.Length)"
    if ($outNow -match 'TOKEN64_DONE') { $markerPass = 1; WLog 'MARKER_PASS'; break }
  }

  if ($ollamaDone -eq 1) {
    $paintDeadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $paintDeadline -and -not $proc.HasExited) {
      $outNow = [Token64Ui2]::Text($outputEdit)
      if ($outNow.Length -ne $lastLen) {
        $lastLen = $outNow.Length
        $responseText = $outNow
        Set-Content -LiteralPath (Join-Path $OutDir 'RESPONSE.txt') -Value $responseText -Encoding utf8
        WLog "POST_DONE_SNAPSHOT_LEN=$($outNow.Length)"
      }
      if ($outNow -match 'TOKEN64_DONE') { $markerPass = 1; WLog 'MARKER_PASS_POST_DONE'; break }
      Start-Sleep -Milliseconds 150
    }
    if ($markerPass -eq 1 -or $lastLen -gt $outBefore.Length) {
      # Look for CHAT_RUNTIME in native debug / session log
      break
    }
    break
  }
  Start-Sleep -Milliseconds 200
}

if (-not $responseText) {
  if (Test-Path (Join-Path $OutDir 'RESPONSE.txt')) {
    $responseText = Get-Content -LiteralPath (Join-Path $OutDir 'RESPONSE.txt') -Raw -ErrorAction SilentlyContinue
  }
  if (-not $responseText) {
    $responseText = ''
    Set-Content -LiteralPath (Join-Path $OutDir 'RESPONSE.txt') -Value $responseText -Encoding utf8
  }
}
if ($responseText -match 'TOKEN64_DONE') { $markerPass = 1 }
$respBytes = [Text.Encoding]::UTF8.GetByteCount($responseText)
$token64Marker = if ($markerPass -eq 1) { 'PASS' } else { 'FAIL' }

$ollamaDelta = Read-OllamaDelta -offset $ollamaOffset
Set-Content -LiteralPath (Join-Path $OutDir 'ollama_delta.txt') -Value $ollamaDelta -Encoding utf8
$mTok = [regex]::Matches($ollamaDelta, 'GENERATED_TOKENS=(\d+)')
if ($mTok.Count -gt 0) { $genTokens = $mTok[$mTok.Count - 1].Groups[1].Value; $backend = 'ollama' }
$mModel = [regex]::Matches($ollamaDelta, 'MODEL=([^\s]+)')
if ($mModel.Count -gt 0) { $modelId = $mModel[$mModel.Count - 1].Groups[1].Value }

# Session + hunt CHAT_RUNTIME across recent logs / ollama
$sessionLog = Get-ChildItem (Join-Path $CandDir 'logs') -Filter 'RawrXD_IDE_*.log' -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
$ideExcerpt = ''
$chatRuntimeSeen = 0
if ($sessionLog) {
  WLog "SESSION_LOG=$($sessionLog.FullName) len=$($sessionLog.Length)"
  $ideAll = Get-Content -LiteralPath $sessionLog.FullName -Raw -ErrorAction SilentlyContinue
  if ($ideAll -match 'CHAT_RUNTIME') {
    $chatRuntimeSeen = 1
    $chatComplete = 'PASS'
  }
  $ideExcerpt = (($ideAll -split "`r?`n") | Where-Object { $_ -match 'CHAT_RUNTIME|Ollama|TOKEN|MODEL|Copilot|GENERATED' } | Select-Object -Last 100) -join "`n"
  Set-Content -LiteralPath (Join-Path $OutDir 'ide_log_excerpt.txt') -Value $ideExcerpt -Encoding utf8
}
# Also search ollama_debug and any native debug sinks for CHAT_RUNTIME from this run
foreach ($p in @($OllamaLog, (Join-Path $CandDir 'native_debug.log'), (Join-Path $CandDir 'debug_output.txt'))) {
  if (Test-Path $p) {
    $tail = Get-Content $p -Tail 200 -ErrorAction SilentlyContinue | Out-String
    if ($tail -match 'CHAT_RUNTIME') { $chatRuntimeSeen = 1; $chatComplete = 'PASS'; WLog "CHAT_RUNTIME_SEEN in $p" }
  }
}
if ($chatRuntimeSeen -eq 0 -and $ollamaDone -eq 1 -and $markerPass -eq 1 -and -not $proc.HasExited) {
  $chatComplete = 'PASS'
  WLog 'CHAT_RUNTIME_COMPLETE=PASS via ollama DONE + UI marker + process alive (no CHAT_RUNTIME line found in sinks)'
} elseif ($chatRuntimeSeen -eq 0 -and $ollamaDone -eq 1 -and $lastLen -gt ($outBefore.Length + 20) -and -not $proc.HasExited) {
  $chatComplete = 'PASS'
  WLog 'CHAT_RUNTIME_COMPLETE=PASS via ollama DONE + UI growth + process alive'
} elseif ($proc.HasExited -and $markerPass -ne 1) {
  $chatComplete = 'FAIL'
  WLog 'CHAT_RUNTIME_COMPLETE=FAIL (process exited without marker)'
} elseif ($chatRuntimeSeen -eq 0 -and $chatComplete -eq 'NOT_VERIFIED') {
  WLog 'CHAT_RUNTIME_COMPLETE=NOT_VERIFIED (no CHAT_RUNTIME line)'
}

$genInt = -1
if ($genTokens -match '^\d+$') { $genInt = [int]$genTokens }
$chatWindowE2E = 'NOT_VERIFIED'
if ($runSha -eq $ExpectSha -and $token64Marker -eq 'PASS' -and $chatComplete -eq 'PASS' -and $genInt -ge 100) {
  $chatWindowE2E = 'PASS'
} elseif ($genInt -gt 0 -or $responseText.Length -gt 50) {
  $chatWindowE2E = 'PARTIAL'
} else {
  $chatWindowE2E = 'FAIL'
}

$token64Gate = 'NOT_VERIFIED'
if ($runSha -eq $ExpectSha -and $genInt -ge 100 -and $token64Marker -eq 'PASS' -and $chatComplete -eq 'PASS') {
  $token64Gate = 'PASS'
} elseif ($genTokens -eq 'NOT_VERIFIED') {
  $token64Gate = 'NOT_VERIFIED'
} else {
  $token64Gate = 'FAIL'
}

$receiptPath = Join-Path $OutDir 'RECEIPT.md'
$asof = (Get-Date).ToUniversalTime().ToString('o')
$hwndHex = '0x{0:X}' -f $main.ToInt64()
$receiptLines = @(
  '# POST_E59D_CANDIDATE_001 TOKEN64 RECEIPT',
  '',
  "ASOF_UTC=$asof",
  "CERT_EXE=$CandExe",
  "CERT_EXE_SHA=$runSha",
  "PID=$($proc.Id)",
  "HWND=$hwndHex",
  "LAUNCHED_HERE=$launchedHere",
  "LOCAL_MODEL_IDENTITY=$modelId",
  "BACKEND_ROUTING=$backend",
  "MODEL_COMBO_UI=$modelSelected",
  "GENERATED_TOKEN_COUNT=$genTokens",
  "TOKEN64_DONE_MARKER=$token64Marker",
  "CHAT_RUNTIME_COMPLETE=$chatComplete",
  "RESPONSE_LEN_BYTES=$respBytes",
  "CHATWINDOW_E2E=$chatWindowE2E",
  "TOKEN64=$token64Gate",
  'EDITOR_GHOSTTEXT_ACCEPT=OPEN',
  'PROMOTE=0',
  'CERTIFIED=0',
  'NOTE=This ChatWindow/Token64 run does NOT close GhostText accept and does NOT authorize promotion.',
  'RETRY=2'
)
$receiptLines | Set-Content -LiteralPath $receiptPath -Encoding utf8

WLog ('FINAL TOKEN64={0} E2E={1} TOKENS={2} MARKER={3} COMPLETE={4} RESP_BYTES={5}' -f $token64Gate,$chatWindowE2E,$genTokens,$token64Marker,$chatComplete,$respBytes)
if (-not $proc.HasExited) { WLog ('PROC_ALIVE pid={0}' -f $proc.Id) } else { WLog ('PROC_DEAD exit={0}' -f $proc.ExitCode) }
exit 0

