# POST_E59D TOKEN64 ChatWindow diagnostic — fail-closed, PROMOTE=0 CERTIFIED=0
# Reuses single live CERT_EXE if path+SHA match; else launches one instance.
# Does NOT close EDITOR.GHOSTTEXT_ACCEPT. Does NOT reopen E59D search.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\TOKEN64'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$ExpectSize = 6080512
$OllamaLog = Join-Path $CandDir 'ollama_debug.log'
$LogFile = Join-Path $OutDir 'RUNLOG.txt'
$PromptExact = 'Generate at least 100 tokens of original plain English prose explaining how a code editor saves a file. Do not use a numbered list. End your response with the exact marker TOKEN64_DONE.'

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $LogFile -Value $line
  Write-Output $line
}

Set-Content -LiteralPath $LogFile -Value ''
WLog 'START POST_E59D TOKEN64 ChatWindow diagnostic'
WLog 'PROMOTE=0 CERTIFIED=0 EDITOR_GHOSTTEXT_ACCEPT=OPEN'

if (-not (Test-Path -LiteralPath $CandExe)) {
  WLog "EXE_MISSING FAIL_CLOSED path=$CandExe"
  exit 2
}
$fi = Get-Item -LiteralPath $CandExe
$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog "PRE_HASH sha=$sha size=$($fi.Length) expect_sha=$ExpectSha expect_size=$ExpectSize"
@"
CERT_EXE=$CandExe
SHA256=$sha
SIZE=$($fi.Length)
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'BINARY_HASH.txt')
if ($sha -ne $ExpectSha -or [int64]$fi.Length -ne [int64]$ExpectSize) {
  WLog 'HASH_MISMATCH STOP'
  'HASH_MISMATCH' | Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT.md')
  exit 3
}
Set-Content -LiteralPath (Join-Path $OutDir 'PROMPT.txt') -Value $PromptExact -Encoding utf8

$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Token64Ui {
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
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
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
  public const int SW_RESTORE = 9;
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
    int len = GetWindowTextLengthW(h);
    var b = new StringBuilder(Math.Max(4096, len + 1));
    GetWindowTextW(h, b, b.Capacity);
    return b.ToString();
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

# Prefer existing single CERT_EXE instance with matching path; do not kill other work.
$launchedHere = 0
$proc = $null
$existing = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -like 'RawrXD-Win32IDE-Native*' -and $_.Path -and ($_.Path -ieq $CandExe)
})
if ($existing.Count -ge 1) {
  $proc = $existing[0]
  WLog "REUSE_EXISTING pid=$($proc.Id) path=$($proc.Path) count=$($existing.Count)"
} else {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $CandExe
  $psi.WorkingDirectory = $CandDir
  $psi.UseShellExecute = $false
  $proc = [Diagnostics.Process]::Start($psi)
  $launchedHere = 1
  WLog "LAUNCHED_SINGLE pid=$($proc.Id) path=$CandExe"
}
WLog "PID=$($proc.Id) FULL_PATH=$($proc.Path)"
$runSha = (Get-FileHash -LiteralPath $proc.Path -Algorithm SHA256).Hash
WLog "RUNNING_EXE_SHA=$runSha"
@"
CERT_EXE=$($proc.Path)
SHA256=$runSha
SIZE=$((Get-Item -LiteralPath $proc.Path).Length)
PID=$($proc.Id)
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
SOURCE=process_Path_Get-FileHash
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'BINARY_HASH.txt')
if ($runSha -ne $ExpectSha) {
  WLog 'HASH_MISMATCH on running path STOP'
  exit 3
}

# Mark ollama log offset before prompt
$ollamaOffset = 0
if (Test-Path -LiteralPath $OllamaLog) {
  $ollamaOffset = (Get-Item -LiteralPath $OllamaLog).Length
}
WLog "OLLAMA_LOG_OFFSET=$ollamaOffset path=$OllamaLog"

$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "EXIT_EARLY code=$($proc.ExitCode)"; break }
  $main = [Token64Ui]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [Token64Ui]::IsWindowVisible($main)) {
    $inputProbe = [Token64Ui]::FindChildById($main, 1202)
    $sendProbe = [Token64Ui]::FindChildById($main, 1204)
    if ($inputProbe -ne [IntPtr]::Zero -and $sendProbe -ne [IntPtr]::Zero) { break }
  }
  Start-Sleep -Milliseconds 400
}
if ($main -eq [IntPtr]::Zero) {
  WLog 'MAIN_WINDOW_TIMEOUT FAIL_CLOSED'
  exit 4
}
[void][Token64Ui]::ShowWindow($main, [Token64Ui]::SW_RESTORE)
[void][Token64Ui]::SetForegroundWindow($main)
WLog "MAIN_HWND=0x$($main.ToInt64().ToString('X'))"

$inputEdit = [Token64Ui]::FindChildById($main, 1202)
$outputEdit = [Token64Ui]::FindChildById($main, 1203)
$btnSend = [Token64Ui]::FindChildById($main, 1204)
$combo = [Token64Ui]::FindChildById($main, 1206)
$btnClear = [Token64Ui]::FindChildById($main, 1205)
WLog "CTRL input=$([int64]$inputEdit) output=$([int64]$outputEdit) send=$([int64]$btnSend) combo=$([int64]$combo)"

$modelSelected = ''
if ($combo -ne [IntPtr]::Zero) {
  $cnt = [Token64Ui]::SendMessageW($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
  WLog "MODEL_COMBO_COUNT=$cnt"
  $prefer = @('gemma3:4b','qwen2.5-coder:1.5b-base','qwen2.5-coder','llama3.2:3b','n4-tiny-oracle')
  for ($i=0; $i -lt $cnt; $i++) {
    $tlen = [Token64Ui]::SendMessageW($combo, 0x0149, [IntPtr]$i, [IntPtr]::Zero).ToInt64()
    if ($tlen -le 0) { continue }
    $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(([int]$tlen+2)*2)
    try {
      [void][Token64Ui]::SendMessageW($combo, 0x0148, [IntPtr]$i, $buf)
      $item = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
    foreach ($patt in $prefer) {
      if ($item -and $item.IndexOf($patt, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        [void][Token64Ui]::SendMessageW($combo, 0x014E, [IntPtr]$i, [IntPtr]::Zero)
        $wp = [IntPtr]((1206 -band 0xFFFF) -bor (1 -shl 16))
        [void][Token64Ui]::PostMessageW($main, [Token64Ui]::WM_COMMAND, $wp, $combo)
        $modelSelected = $item
        WLog "MODEL_SELECT idx=$i text='$item'"
        break
      }
    }
    if ($modelSelected) { break }
  }
  if (-not $modelSelected -and $cnt -gt 0) {
    [void][Token64Ui]::SendMessageW($combo, 0x014E, [IntPtr]0, [IntPtr]::Zero)
    $modelSelected = 'COMBO_INDEX_0'
    WLog 'MODEL_SELECT=COMBO_INDEX_0_FALLBACK'
  }
}

# Clear output pane if possible so capture is clean
if ($btnClear -ne [IntPtr]::Zero) {
  $sidebar = [Token64Ui]::FindChildById($main, 1200)
  if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }
  [Token64Ui]::ClickChild($sidebar, $btnClear, 1205)
  Start-Sleep -Milliseconds 300
}

$outBefore = [Token64Ui]::Text($outputEdit)
$lenSet = [Token64Ui]::SetEdit($inputEdit, $PromptExact)
WLog "INPUT_SET_LEN=$lenSet verify='$([Token64Ui]::Text($inputEdit).Substring(0,[Math]::Min(80,[Token64Ui]::Text($inputEdit).Length)))...'"
$sidebar = [Token64Ui]::FindChildById($main, 1200)
if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }
[Token64Ui]::ClickChild($sidebar, $btnSend, 1204)
WLog 'PROMPT_SUBMITTED=1'
$submitUtc = (Get-Date).ToUniversalTime().ToString('o')

$responseText = ''
$markerPass = 0
$chatComplete = 'NOT_VERIFIED'
$statusTrail = New-Object System.Collections.Generic.List[string]
$deadline = (Get-Date).AddSeconds(300)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) {
    WLog "CRASH_DURING_GEN exit=$($proc.ExitCode)"
    $chatComplete = 'FAIL'
    break
  }
  $st = [Token64Ui]::StatusBarText($main)
  $outNow = [Token64Ui]::Text($outputEdit)
  if ($st -and ($statusTrail.Count -eq 0 -or $statusTrail[$statusTrail.Count-1] -ne $st)) {
    $statusTrail.Add($st)
    WLog "STATUS=$st"
  }
  if ($outNow.Length -gt $outBefore.Length + 20) {
    $responseText = $outNow
    if ($outNow -match 'TOKEN64_DONE') {
      $markerPass = 1
      WLog "MARKER_SEEN output_len=$($outNow.Length)"
      # allow brief settle for GENERATED_TOKENS log line
      Start-Sleep -Seconds 2
      break
    }
  }
  if ($st -match '(?i)response received|Done|complete|CHAT_RUNTIME') {
    $chatComplete = 'PASS'
  }
  if ($st -match '(?i)error:|cannot connect|winhttp|select a model|No model') {
    WLog "STATUS_FAIL=$st"
    $responseText = $outNow
    break
  }
  Start-Sleep -Milliseconds 500
}

if (-not $responseText) { $responseText = [Token64Ui]::Text($outputEdit) }
Set-Content -LiteralPath (Join-Path $OutDir 'RESPONSE.txt') -Value $responseText -Encoding utf8
$respBytes = [Text.Encoding]::UTF8.GetByteCount($responseText)
WLog "RESPONSE_LEN_BYTES=$respBytes MARKER=$markerPass"

# Parse ollama_debug delta for GENERATED_TOKENS / model / route
$genTokens = 'NOT_VERIFIED'
$modelId = 'NOT_VERIFIED'
$backend = 'NOT_VERIFIED'
$ollamaDelta = ''
if (Test-Path -LiteralPath $OllamaLog) {
  $fs = [IO.File]::Open($OllamaLog, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    if ($ollamaOffset -gt $fs.Length) { $ollamaOffset = 0 }
    $fs.Position = $ollamaOffset
    $sr = New-Object IO.StreamReader($fs)
    $ollamaDelta = $sr.ReadToEnd()
    $sr.Close()
  } finally { $fs.Close() }
  Set-Content -LiteralPath (Join-Path $OutDir 'ollama_delta.txt') -Value $ollamaDelta -Encoding utf8
  $mTok = [regex]::Matches($ollamaDelta, 'GENERATED_TOKENS=(\d+)')
  if ($mTok.Count -gt 0) { $genTokens = $mTok[$mTok.Count-1].Groups[1].Value }
  $mModel = [regex]::Matches($ollamaDelta, "MODEL=([^\s]+)")
  if ($mModel.Count -gt 0) { $modelId = $mModel[$mModel.Count-1].Groups[1].Value }
  if ($ollamaDelta -match 'OLLAMA_|generateOllamaModel|localhost:11434') { $backend = 'ollama' }
  WLog "OLLAMA_DELTA_BYTES=$($ollamaDelta.Length) GENERATED_TOKEN_COUNT=$genTokens MODEL=$modelId BACKEND=$backend"
} else {
  WLog 'OLLAMA_LOG_MISSING'
}

# Session IDE log scrape
$sessionLog = Get-ChildItem (Join-Path $CandDir 'logs') -Filter 'RawrXD_IDE_*.log' -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
$ideLogExcerpt = ''
if ($sessionLog) {
  WLog "SESSION_LOG=$($sessionLog.FullName) len=$($sessionLog.Length)"
  try {
    $ideAll = Get-Content -LiteralPath $sessionLog.FullName -Raw -ErrorAction SilentlyContinue
    if ($ideAll) {
      $lines = $ideAll -split "`r?`n" | Where-Object { $_ -match 'CHAT_RUNTIME|GENERATED_TOKENS|Ollama|MODEL|TOKEN|Copilot|response' }
      $ideLogExcerpt = ($lines | Select-Object -Last 80) -join "`n"
      if ($ideAll -match 'CHAT_RUNTIME') { $chatComplete = 'PASS' }
    }
  } catch { WLog "SESSION_LOG_READ_ERR=$($_.Exception.Message)" }
  Set-Content -LiteralPath (Join-Path $OutDir 'ide_log_excerpt.txt') -Value $ideLogExcerpt -Encoding utf8
}

if ($markerPass -eq 1 -and $statusTrail -match '(?i)Done|response received|complete') {
  $chatComplete = 'PASS'
}
# Also treat ollama DONE_REASON=stop after our prompt as completion signal if UI grew
if ($chatComplete -eq 'NOT_VERIFIED' -and $ollamaDelta -match 'DONE_REASON=stop' -and $responseText.Length -gt ($outBefore.Length + 20)) {
  $chatComplete = 'PASS'
  WLog 'CHAT_RUNTIME_COMPLETE inferred from OLLAMA DONE_REASON=stop + UI growth (no CHAT_RUNTIME line in session log)'
}

$token64Marker = if ($markerPass -eq 1) { 'PASS' } else { 'FAIL' }
$genInt = -1
if ($genTokens -match '^\d+$') { $genInt = [int]$genTokens }

$chatWindowE2E = 'NOT_VERIFIED'
if ($runSha -eq $ExpectSha -and $token64Marker -eq 'PASS' -and $chatComplete -eq 'PASS' -and $genInt -ge 100) {
  $chatWindowE2E = 'PASS'
} elseif ($runSha -ne $ExpectSha) {
  $chatWindowE2E = 'FAIL'
} elseif ($token64Marker -eq 'FAIL' -and $genTokens -eq 'NOT_VERIFIED') {
  $chatWindowE2E = 'FAIL'
} elseif ($genTokens -eq 'NOT_VERIFIED' -or $genInt -lt 100 -or $chatComplete -ne 'PASS' -or $token64Marker -ne 'PASS') {
  if ($responseText.Length -gt 50 -or $genInt -gt 0) { $chatWindowE2E = 'PARTIAL' } else { $chatWindowE2E = 'NOT_VERIFIED' }
}

$token64Gate = 'NOT_VERIFIED'
if ($runSha -eq $ExpectSha -and $genInt -ge 100 -and $token64Marker -eq 'PASS' -and $chatComplete -eq 'PASS') {
  $token64Gate = 'PASS'
} elseif ($genTokens -eq 'NOT_VERIFIED') {
  $token64Gate = 'NOT_VERIFIED'
} elseif ($genInt -ge 0 -and $genInt -lt 100) {
  $token64Gate = 'FAIL'
} elseif ($token64Marker -eq 'FAIL') {
  $token64Gate = 'FAIL'
}

$receipt = @"
# POST_E59D_CANDIDATE_001 TOKEN64 RECEIPT

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CERT_EXE=$CandExe
CERT_EXE_SHA=$runSha
PID=$($proc.Id)
HWND=0x$($main.ToInt64().ToString('X'))
LAUNCHED_HERE=$launchedHere
SUBMIT_UTC=$submitUtc
LOCAL_MODEL_IDENTITY=$modelId
BACKEND_ROUTING=$backend
MODEL_COMBO_UI=$modelSelected
GENERATED_TOKEN_COUNT=$genTokens
TOKEN64_DONE_MARKER=$token64Marker
CHAT_RUNTIME_COMPLETE=$chatComplete
RESPONSE_LEN_BYTES=$respBytes
CHATWINDOW_E2E=$chatWindowE2E
TOKEN64=$token64Gate
EDITOR_GHOSTTEXT_ACCEPT=OPEN
PROMOTE=0
CERTIFIED=0
NOTE=This ChatWindow/Token64 run does NOT close GhostText accept and does NOT authorize promotion.
"@
Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT.md') -Value $receipt -Encoding utf8
WLog "TOKEN64=$token64Gate CHATWINDOW_E2E=$chatWindowE2E GENERATED_TOKEN_COUNT=$genTokens MARKER=$token64Marker CHAT_RUNTIME_COMPLETE=$chatComplete"
WLog 'END (process left running; no kill — GhostText worker coexistence)'
exit 0
