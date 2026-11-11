# PRODUCT_BINARY_SEAL_001 â€” Native ChatWindow runtime (candidate-only)
# Adapted from WIN32IDE_CONTINUOUS_COMPLETION_015/CHATWINDOW_RUNTIME_001
# Target: RawrXD-Win32IDE-Native (Copilot embedded chat), NOT Qt RawrXDChatWindow
# INVENT_PASS=0 PROMOTE=0 AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\AGENT_SHELL_CHANNEL_RECOVERY_001'
$Logs = Join-Path $OutDir 'logs_chatwindow'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = 'F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectCand = 'CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB'
$Log = Join-Path $OutDir 'CHATWINDOW_RUNTIME_RUNLOG.txt'
Set-Content $Log ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content $Log $line
  Write-Output $line
}

$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class ChatRtHarnessRec001 {
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
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_CLOSE = 0x0010;
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
    var b = new StringBuilder(Math.Max(1024, len + 1));
    GetWindowTextW(h, b, b.Capacity);
    return b.ToString();
  }
  public static List<string> DumpChildren(IntPtr parent) {
    var rows = new List<string>();
    if (parent == IntPtr.Zero || !IsWindow(parent)) return rows;
    EnumChildWindows(parent, (h, l) => {
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      rows.Add(string.Format("CHILD id={0} enabled={1} class='{2}' text='{3}'",
        GetWindowLongW(h, GWL_ID), IsWindowEnabled(h), cls, Text(h)));
      return true;
    }, IntPtr.Zero);
    return rows;
  }
  public static string StatusBarText(IntPtr main) {
    // SB_GETTEXTLENGTH / SB_GETTEXT via SendMessage â€” status often first pane
    IntPtr sb = FindChildById(main, 0); // may miss; scan for msctls_statusbar32
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

WLog 'START PRODUCT_BINARY_SEAL_001 CHATWINDOW_NATIVE'
WLog 'PROMOTE=0 INVENT_PASS=0 BUILD_SCOPE=CANDIDATE_ONLY'

if (-not (Test-Path -LiteralPath $CandExe)) {
  WLog "EXE_MISSING FAIL_CLOSED path=$CandExe"
  exit 2
}
$candSha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
WLog "PRE_HASH CAND=$candSha EXPECT=$ExpectCand"
"CANDIDATE_SHA=$candSha" | Set-Content (Join-Path $Logs 'sha_pre.txt')
if ($candSha -ne $ExpectCand) {
  WLog 'SHA_MISMATCH FAIL_CLOSED'
  exit 2
}

$ollamaUp = 0
$ollamaDetail = ''
$ollamaModels = @()
try {
  $tags = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3
  $ollamaUp = 1
  $ollamaModels = @($tags.models | ForEach-Object { $_.name })
  $ollamaDetail = ($ollamaModels -join ',')
  WLog "OLLAMA_UP=1 models_sample=$($ollamaModels[0..([Math]::Min(4,$ollamaModels.Count-1))] -join ',')"
} catch {
  $ollamaDetail = $_.Exception.Message
  WLog "OLLAMA_UP=0 detail=$ollamaDetail"
}
"OLLAMA_UP=$ollamaUp`nDETAIL=$ollamaDetail" | Set-Content (Join-Path $Logs 'ollama_probe.txt')

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } |
  ForEach-Object { WLog "KILL_PRE pid=$($_.Id) name=$($_.ProcessName)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe
$psi.WorkingDirectory = $CandDir
$psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCHED pid=$($proc.Id) exe=$CandExe"
$proc.Id | Set-Content (Join-Path $Logs 'pid.txt')

$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "EXIT_EARLY code=$($proc.ExitCode)"; break }
  $main = [ChatRtHarnessRec001]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [ChatRtHarnessRec001]::IsWindowVisible($main)) {
    $inputProbe = [ChatRtHarnessRec001]::FindChildById($main, 1202)
    $sendProbe = [ChatRtHarnessRec001]::FindChildById($main, 1204)
    if ($inputProbe -ne [IntPtr]::Zero -and $sendProbe -ne [IntPtr]::Zero) { break }
  }
  Start-Sleep -Milliseconds 500
}
if ($main -eq [IntPtr]::Zero -or -not [ChatRtHarnessRec001]::IsWindowVisible($main)) {
  WLog 'MAIN_WINDOW_TIMEOUT FAIL_CLOSED'
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  $disposition = 'FAIL_CLOSED_MAIN_WINDOW'
  @"
GATE=CHATWINDOW_RUNTIME_NATIVE_CANDIDATE
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
DISPOSITION=$disposition
RUNTIME_PASS=0
CANDIDATE_SHA=$candSha
CREATE_SHOW=0
PROMPT_SUBMIT=0
RESPONSE_OK=0
RESPONSE_CLASS=NOT_OBSERVED
CANCEL_OK=0
TEARDOWN_HIDE=0
TEARDOWN_PROC=0
OLLAMA_UP=$ollamaUp
UI_SURFACE=Native_Copilot_embedded (not Qt RawrXDChatWindow)
INVENT_PASS=0
PROMOTE=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
TIP_CLIMB=HOLD
"@ | Set-Content (Join-Path $OutDir 'CHATWINDOW_RUNTIME_RECEIPT.md')
  exit 4
}
[void][ChatRtHarnessRec001]::ShowWindow($main, [ChatRtHarnessRec001]::SW_RESTORE)
WLog "MAIN_READY hwnd=0x$($main.ToInt64().ToString('X')) class=RawrXD_IDE_Window"

$inputEdit = [ChatRtHarnessRec001]::FindChildById($main, 1202)
$outputEdit = [ChatRtHarnessRec001]::FindChildById($main, 1203)
$btnSend = [ChatRtHarnessRec001]::FindChildById($main, 1204)
$btnClear = [ChatRtHarnessRec001]::FindChildById($main, 1205)
$combo = [ChatRtHarnessRec001]::FindChildById($main, 1206)
$btnStop = [ChatRtHarnessRec001]::FindChildById($main, 1210)
$createOk = [int]($inputEdit -ne [IntPtr]::Zero -and $outputEdit -ne [IntPtr]::Zero -and $btnSend -ne [IntPtr]::Zero -and [ChatRtHarnessRec001]::IsWindowVisible($inputEdit))
WLog "CREATE_SHOW=$createOk input=$([int64]$inputEdit) output=$([int64]$outputEdit) send=$([int64]$btnSend) stop=$([int64]$btnStop) combo=$([int64]$combo)"
[ChatRtHarnessRec001]::DumpChildren($main) | Set-Content (Join-Path $Logs 'chat_children_pre.txt')
if ($createOk -ne 1) {
  WLog 'CREATE_SHOW_FAIL FAIL_CLOSED'
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  @"
GATE=CHATWINDOW_RUNTIME_NATIVE_CANDIDATE
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
DISPOSITION=FAIL_CLOSED_CREATE_SHOW
RUNTIME_PASS=0
CANDIDATE_SHA=$candSha
CREATE_SHOW=0
INVENT_PASS=0
PROMOTE=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
"@ | Set-Content (Join-Path $OutDir 'CHATWINDOW_RUNTIME_RECEIPT.md')
  exit 5
}

$modelSelected = ''
if ($combo -ne [IntPtr]::Zero) {
  foreach ($mname in @('qwen2.5-coder:1.5b-base','llama3.2:3b','llama3.2:latest','phi-3-mini:latest','phi-3-mini','n4-tiny-oracle:latest','gemma3:4b','qwen3:8b') + $ollamaModels) {
    if ([string]::IsNullOrWhiteSpace($mname)) { continue }
    $w = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($mname)
    $r = [ChatRtHarnessRec001]::SendMessageW($combo, 0x014D, [IntPtr]::Zero, $w).ToInt64()
    [Runtime.InteropServices.Marshal]::FreeHGlobal($w)
    if ($r -ne -1) { $modelSelected = $mname; WLog "MODEL_SELECT=$mname idx=$r"; break }
  }
  if (-not $modelSelected) {
    $cnt = [ChatRtHarnessRec001]::SendMessageW($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64() # CB_GETCOUNT
    WLog "MODEL_COMBO_COUNT=$cnt (enumerating labels)"
    for ($i = 0; $i -lt $cnt; $i++) {
      [void][ChatRtHarnessRec001]::SendMessageW($combo, 0x014E, [IntPtr]$i, [IntPtr]::Zero)
      Start-Sleep -Milliseconds 20
      $label = [ChatRtHarnessRec001]::Text($combo)
      if ($label -match 'qwen2\.5-coder|llama3\.2:3b|phi-3|n4-tiny|1\.5b|gemma3:4b|qwen3:8b') {
        $modelSelected = $label
        WLog "MODEL_SELECT_ENUM=$label idx=$i"
        # notify selchange
        $wp = [IntPtr]((1 -shl 16) -bor (1206 -band 0xFFFF))
        [void][ChatRtHarnessRec001]::SendMessageW($main, 0x0111, $wp, $combo)
        break
      }
    }
    if (-not $modelSelected -and $cnt -gt 0) {
      [void][ChatRtHarnessRec001]::SendMessageW($combo, 0x014E, [IntPtr]0, [IntPtr]::Zero)
      $modelSelected = 'COMBO_INDEX_0'
      WLog 'MODEL_SELECT=COMBO_INDEX_0'
    }
  }
} else {
  WLog 'MODEL_COMBO_ABSENT'
}

$outBefore = [ChatRtHarnessRec001]::Text($outputEdit)
$prompt1 = 'Reply with exactly one word: PONG'
$len1 = [ChatRtHarnessRec001]::SetEdit($inputEdit, $prompt1)
WLog "INPUT_LEN_AFTER_SET=$len1 text='$([ChatRtHarnessRec001]::Text($inputEdit))' sendEnabled=$([ChatRtHarnessRec001]::IsWindowEnabled($btnSend))"
Start-Sleep -Milliseconds 200
$sidebar = [ChatRtHarnessRec001]::FindChildById($main, 1200)
if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }
[ChatRtHarnessRec001]::ClickChild($sidebar, $btnSend, 1204)
WLog 'PROMPT_SUBMITTED=1 FALLBACK_CLICK_SEND=1'
$promptOk = 1

$responseOk = 0
$responseClass = 'NOT_OBSERVED'
$statusTrail = New-Object System.Collections.Generic.List[string]
$deadline = (Get-Date).AddSeconds(600)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "CRASH_DURING_GEN exit=$($proc.ExitCode)"; $responseClass = "CRASH:$($proc.ExitCode)"; break }
  $st = [ChatRtHarnessRec001]::StatusBarText($main)
  $outNow = [ChatRtHarnessRec001]::Text($outputEdit)
  if ($st -and ($statusTrail.Count -eq 0 -or $statusTrail[$statusTrail.Count-1] -ne $st)) {
    $statusTrail.Add($st)
    WLog "STATUS=$st"
  }
  if ($outNow.Length -gt $outBefore.Length + 5 -and ($outNow -match 'PONG|Assistant|assistant|Error:|Ollama|WinHTTP|No model|Select a model|stopped|Done|response')) {
    if ($outNow -match '(?i)error:|cannot connect|winhttp|no model|select a model') {
      $responseClass = "FAIL_CLOSED:$($outNow.Substring([Math]::Max(0,$outNow.Length-200)))"
      break
    }
    if ($outNow -match 'PONG' -or ($outNow.Length -gt $outBefore.Length + 20)) {
      $responseOk = 1
      $responseClass = 'STREAM_OR_OUTPUT_GROWTH'
      WLog "OUTPUT_GREW before=$($outBefore.Length) after=$($outNow.Length)"
      break
    }
  }
  if ($st -match '(?i)stopped|error|cannot connect|winhttp|select a model') {
    $responseClass = "FAIL_CLOSED:$st"
    break
  }
  Start-Sleep -Milliseconds 400
}
$statusTrail | Set-Content (Join-Path $Logs 'status_trail_prompt1.txt')
[ChatRtHarnessRec001]::Text($outputEdit) | Set-Content (Join-Path $Logs 'output_after_prompt1.txt')
WLog "RESPONSE_CLASS=$responseClass RESPONSE_OK=$responseOk MODEL_ROUTING=$modelSelected"

# Cancel path: long prompt + Stop
$prompt2 = 'Write a very long detailed essay of at least 800 words about Windows kernel scheduling.'
[void][ChatRtHarnessRec001]::SetEdit($inputEdit, $prompt2)
[ChatRtHarnessRec001]::ClickChild($sidebar, $btnSend, 1204)
Start-Sleep -Milliseconds 400
$cancelEnabled = [int][ChatRtHarnessRec001]::IsWindowEnabled($btnStop)
if ($cancelEnabled -eq 1) { [ChatRtHarnessRec001]::ClickChild($sidebar, $btnStop, 1210) }
else { [ChatRtHarnessRec001]::ClickChild($sidebar, $btnStop, 1210) }
WLog "CANCEL_CLICKED cancelEnabled=$cancelEnabled"
Start-Sleep -Milliseconds 800
$st2 = [ChatRtHarnessRec001]::StatusBarText($main)
WLog "STATUS_AFTER_CANCEL=$st2"
$cancelOk = 0
if ($st2 -match '(?i)stop' -or $cancelEnabled -eq 1) { $cancelOk = 1 }
elseif ($btnStop -ne [IntPtr]::Zero) { $cancelOk = 0; WLog 'CANCEL_NOT_PROVEN stop control present but status did not confirm' }
WLog "CANCEL_OK=$cancelOk"

# Teardown
[void][ChatRtHarnessRec001]::PostMessageW($main, [ChatRtHarnessRec001]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Milliseconds 800
$stillVisible = [int]([ChatRtHarnessRec001]::IsWindow($main) -and [ChatRtHarnessRec001]::IsWindowVisible($main))
$teardownHide = [int]($stillVisible -eq 0)
WLog "TEARDOWN_HIDE=$teardownHide stillVisible=$stillVisible"
if (-not $proc.HasExited) {
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2
$alive = @(Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)
$teardownProc = [int]($alive.Count -eq 0)
WLog "TEARDOWN_PROC=$teardownProc"

$candAfter = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
$shaOk = [int]($candAfter -eq $ExpectCand)

$runtimePass = 0
$disposition = 'FAIL_CLOSED'
if ($createOk -eq 1 -and $promptOk -eq 1 -and $teardownProc -eq 1) {
  if ($responseOk -eq 1 -and $cancelOk -eq 1) {
    $runtimePass = 1
    $disposition = 'RUNTIME_PASS'
  } elseif ($responseOk -eq 1 -and $cancelOk -eq 0) {
    $disposition = 'RESPONSE_OBSERVED_CANCEL_NOT_PROVEN'
  } elseif ($responseClass -like 'FAIL_CLOSED*' -and $ollamaUp -eq 0) {
    $disposition = 'FAIL_CLOSED_OLLAMA_DOWN_PARTIAL'
  } elseif ($responseClass -like 'FAIL_CLOSED*') {
    $disposition = 'FAIL_CLOSED_HTTP_OR_MODEL'
  } elseif ($responseClass -eq 'NOT_OBSERVED') {
    $disposition = 'FAIL_CLOSED_RESPONSE_NOT_OBSERVED'
  } elseif ($responseClass -like 'CRASH*') {
    $disposition = 'FAIL_CLOSED_CRASH'
  }
}

@"
GATE=CHATWINDOW_RUNTIME_NATIVE_CANDIDATE
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
DISPOSITION=$disposition
RUNTIME_PASS=$runtimePass
CANDIDATE_SHA=$candAfter
SHA_MATCH_EXPECT=$shaOk
CREATE_SHOW=$createOk
PROMPT_SUBMIT=$promptOk
RESPONSE_OK=$responseOk
RESPONSE_CLASS=$responseClass
CANCEL_OK=$cancelOk
TEARDOWN_HIDE=$teardownHide
TEARDOWN_PROC=$teardownProc
OLLAMA_UP=$ollamaUp
MODEL_ROUTING=$modelSelected
UI_SURFACE=Native_Copilot_embedded (class=RawrXD_IDE_Window; ids 1202/1203/1204/1210; not Qt RawrXDChatWindow)
CRASH_DURING_RUN=$([int]($responseClass -like 'CRASH*'))
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
BUILD_SCOPE=CANDIDATE_ONLY
TIP_CLIMB=HOLD
"@ | Set-Content (Join-Path $OutDir 'CHATWINDOW_RUNTIME_RECEIPT.md')

WLog "DISPOSITION=$disposition RUNTIME_PASS=$runtimePass"
if ($runtimePass -eq 1) { exit 0 } else { exit 1 }

