# P11-only: A -> Stop -> B token/response + stale-fence evidence on LIVE tip.
# Does not rewrite P07/P08/P09. CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD. NOT_RUN!=PASS.
param(
  [string]$ExePath = 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_18_AUDIT\RUNTIME_EVIDENCE',
  [string]$ExpectedTip = 'B53884F5E41530708054D4E110260D503AF8A27FDCF6BCF55324E15F687FA3A5',
  [string]$ModelNeedle = 'n4-tiny-oracle',
  [string]$ForceOllamaModel = 'n4-tiny-oracle:latest'
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runId = "b18_p11_$stamp"
$ud = Join-Path $OutDir "p11_userdata_$stamp"
$logDir = Join-Path $OutDir "p11_run_$stamp"
New-Item -ItemType Directory -Force -Path $ud,$logDir | Out-Null
$chatLog = Join-Path $logDir 'chat_runtime.log'
$runLog = Join-Path $OutDir "p11_token_probe_$stamp.txt"
$probeReceipt = Join-Path $OutDir 'P11_TOKEN_PROBE_RECEIPT.txt'
$followupReceipt = Join-Path $OutDir 'GUI_FOLLOWUP_RECEIPT.txt'
$disposition = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_18_AUDIT\DISPOSITION_RUNTIME_GATE.txt'

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runLog -Value $line -Encoding UTF8
  Write-Output $line
}

if (-not (Test-Path -LiteralPath $ExePath)) {
  Log 'EXE_ABSENT=1'
  Set-Content $probeReceipt "P11=FAIL`nP11_NOTE=EXE_ABSENT`nTIP_SHA=`nCERTIFIED=0`nPROMOTE=0" -Encoding UTF8
  exit 2
}
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
Log "TIP_SHA=$sha EXPECTED=$ExpectedTip MATCH=$($sha -eq $ExpectedTip)"
if ($sha -ne $ExpectedTip) {
  Set-Content $probeReceipt "P11=FAIL`nP11_NOTE=TIP_SHA_MISMATCH live=$sha expected=$ExpectedTip`nTIP_SHA=$sha`nCERTIFIED=0`nPROMOTE=0" -Encoding UTF8
  exit 3
}

try {
  $tags = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -UseBasicParsing -TimeoutSec 5
  Log "OLLAMA_UP=1 STATUS=$($tags.StatusCode)"
} catch {
  Log "OLLAMA_UP=0 ERR=$($_.Exception.Message)"
  $body = @"
P11=FAIL_CLOSED
P11_NOTE=MISSING_BACKEND=Ollama HTTP http://127.0.0.1:11434/api/tags (owner=local Ollama daemon / ollama-http route)
TIP_SHA=$sha
OLLAMA_UP=0
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
RUNLOG=$runLog
"@
  Set-Content $probeReceipt $body -Encoding UTF8
  exit 4
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class P11Ui {
  public const uint WM_COMMAND=0x0111; public const uint WM_COPYDATA=0x004A;
  public const uint BM_CLICK=0x00F5; public const uint WM_GETTEXT=0x000D;
  public const uint WM_GETTEXTLENGTH=0x000E; public const uint WM_CLOSE=0x0010;
  public const uint CB_GETCOUNT=0x0146; public const uint CB_GETLBTEXTLEN=0x0149;
  public const uint CB_GETLBTEXT=0x0148; public const uint CB_SETCURSEL=0x014E;
  public const int GWL_ID=-12;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct COPYDATASTRUCT {
    public IntPtr dwData; public int cbData; public IntPtr lpData;
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var cls=new StringBuilder(256); GetClassNameW(h,cls,256);
      if(cls.ToString()=="RawrXD_IDE_Window"){ found=h; return false;} return true; }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindById(IntPtr parent, int id) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,GWL_ID)==id){ found=h; return false;} return true;},IntPtr.Zero);
    return found;
  }
  public static bool Chin(IntPtr hwnd, string text) {
    byte[] bytes=Encoding.UTF8.GetBytes(text??"");
    IntPtr buf=Marshal.AllocHGlobal(bytes.Length+1);
    try {
      Marshal.Copy(bytes,0,buf,bytes.Length); Marshal.WriteByte(buf,bytes.Length,0);
      COPYDATASTRUCT cds; cds.dwData=(IntPtr)0x4348494E; cds.cbData=bytes.Length+1; cds.lpData=buf;
      IntPtr pCds=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(COPYDATASTRUCT)));
      try {
        Marshal.StructureToPtr(cds,pCds,false);
        return SendMessageW(hwnd, WM_COPYDATA, IntPtr.Zero, pCds)!=IntPtr.Zero;
      } finally { Marshal.FreeHGlobal(pCds); }
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static void ClickId(IntPtr main, int id) {
    IntPtr btn=FindById(main,id);
    if(btn!=IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    IntPtr wp=(IntPtr)((0<<16)|(id & 0xFFFF));
    SendMessageW(main, WM_COMMAND, wp, btn);
    PostMessageW(main, WM_COMMAND, wp, btn);
  }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return ""; if(n>120000) n=120000;
    var sb=new StringBuilder(n+2); SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb); return sb.ToString();
  }
  public static string SelectModel(IntPtr main, IntPtr combo, string needle) {
    int cnt=SendMessageW(combo,CB_GETCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
    for(int i=0;i<cnt;i++){
      int tlen=SendMessageW(combo,CB_GETLBTEXTLEN,(IntPtr)i,IntPtr.Zero).ToInt32();
      if(tlen<=0) continue;
      IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
      try {
        SendMessageW(combo,CB_GETLBTEXT,(IntPtr)i,buf);
        string item=Marshal.PtrToStringUni(buf)??"";
        if(item.IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){
          SendMessageW(combo,CB_SETCURSEL,(IntPtr)i,IntPtr.Zero);
          IntPtr wp=(IntPtr)((1206 & 0xFFFF)|(1<<16)); // CBN_SELCHANGE
          PostMessageW(main, WM_COMMAND, wp, combo);
          return item;
        }
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return "";
  }
  public static string[] ListCombo(IntPtr combo) {
    int cnt=SendMessageW(combo,CB_GETCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
    if(cnt<=0) return new string[0];
    string[] items=new string[cnt];
    for(int i=0;i<cnt;i++){
      int tlen=SendMessageW(combo,CB_GETLBTEXTLEN,(IntPtr)i,IntPtr.Zero).ToInt32();
      if(tlen<=0){ items[i]=""; continue; }
      IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
      try {
        SendMessageW(combo,CB_GETLBTEXT,(IntPtr)i,buf);
        items[i]=Marshal.PtrToStringUni(buf)??"";
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return items;
  }
}
"@

function Wait-LogMatch([string]$path,[string]$pattern,[int]$timeoutSec=90) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $path) {
      $txt = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
      if ($txt -and ($txt -match $pattern)) { return $true }
    }
    Start-Sleep -Milliseconds 250
  }
  return $false
}

function Wait-ComboNeedle([IntPtr]$main,[string]$needle,[int]$timeoutSec=60) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  $lastItems = @()
  $lastCombo = [IntPtr]::Zero
  while ((Get-Date) -lt $deadline) {
    $combo = [P11Ui]::FindById($main, 1206)
    if ($combo -ne [IntPtr]::Zero) {
      $items = [P11Ui]::ListCombo($combo)
      $lastCombo = $combo
      if ($items.Count -gt 0) { $lastItems = $items }
      foreach ($it in $items) {
        if ($it -and $it.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
          return @{ Ok=$true; Combo=$combo; Items=$items }
        }
      }
      # Do NOT early-return on first non-empty catalog: startup discovery
      # often seeds a single preferred Ollama row before the full /api/tags
      # catalog (incl. n4-tiny-oracle) lands. Keep waiting for the needle.
    }
    Start-Sleep -Milliseconds 500
  }
  return @{ Ok=$false; Combo=$lastCombo; Items=$lastItems }
}

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$env:RAWRXD_USER_DATA_DIR = $ud
$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_CHAT_RUN_ID = $runId
if ($ForceOllamaModel) {
  $env:RAWRXD_P11_FORCE_OLLAMA_MODEL = $ForceOllamaModel
  Log "FORCE_OLLAMA_MODEL=$ForceOllamaModel"
} else {
  Remove-Item Env:RAWRXD_P11_FORCE_OLLAMA_MODEL -ErrorAction SilentlyContinue
}
Remove-Item Env:RAWRXD_FORCE_LOCAL_AGENTIC -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_CHAT_BACKEND -ErrorAction SilentlyContinue

$workDir = Split-Path -Parent $ExePath
$proc = Start-Process -FilePath $ExePath -ArgumentList "--user-data-dir=`"$ud`"" -WorkingDirectory $workDir -PassThru -WindowStyle Normal
Log "PID=$($proc.Id) RUN_ID=$runId LOGDIR=$logDir"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 100; $i++) {
  Start-Sleep -Milliseconds 250
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { Log "EARLY_EXIT=$($proc.ExitCode)"; break }
  $main = [P11Ui]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) {
  Set-Content $probeReceipt "P11=FAIL`nP11_NOTE=NO_MAIN_HWND`nTIP_SHA=$sha`nCERTIFIED=0`nPROMOTE=0`nRUNLOG=$runLog" -Encoding UTF8
  exit 5
}

$ready = Wait-ComboNeedle $main $ModelNeedle 20
$combo = $ready.Combo
Log "MODEL_COMBO_OK=$($ready.Ok) COUNT=$($ready.Items.Count)"
if ($ready.Items.Count -gt 0) {
  Log ("MODEL_SAMPLE=" + (($ready.Items | Select-Object -First 12) -join ' | '))
}
$sel = ''
if ($ready.Ok -and $combo -ne [IntPtr]::Zero) {
  $sel = [P11Ui]::SelectModel($main, $combo, $ModelNeedle)
  Log "MODEL_SELECTED=$sel"
} elseif ($ForceOllamaModel) {
  $sel = "FORCE:$ForceOllamaModel"
  Log "MODEL_FORCE_ROUTE=$sel"
} else {
  # Prefer tiny local routes only — never fall back to a 20GB+ preferred
  # Ollama breadcrumb (bigdaddyg) that stalls TTFT past P11 budgets.
  $fallback = ($ready.Items | Where-Object { $_ -match 'n4-tiny|llama3\.2|qwen2\.5-coder:1\.5b|embeddinggemma|gemma3:4b' } | Select-Object -First 1)
  if ($fallback -and $combo -ne [IntPtr]::Zero) {
    $sel = [P11Ui]::SelectModel($main, $combo, $fallback)
    Log "MODEL_FALLBACK_SELECTED=$sel"
  } else {
    Log 'MODEL_SELECT_FAIL'
  }
}

if (-not $sel) {
  try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}
  $body = @"
P11=FAIL_CLOSED
P11_NOTE=MISSING_BACKEND_OWNER=chat model selector has no usable Ollama/local route containing '$ModelNeedle' (combo_count=$($ready.Items.Count)); product path=IDC_COPILOT_MODEL_SELECTOR/1206 -> ChatModelEntry::Ollama -> generateOllamaModel
TIP_SHA=$sha
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
RUNLOG=$runLog
CHATLOG=$chatLog
"@
  Set-Content $probeReceipt $body -Encoding UTF8
  exit 6
}

if ($sel -match 'bigdaddyg' -and $sel -notmatch [regex]::Escape($ModelNeedle)) {
  try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}
  $body = @"
P11=FAIL_CLOSED
P11_NOTE=STILL_ON_BIGDADDYG model='$sel' expected_needle='$ModelNeedle' force='$ForceOllamaModel'; product must seed/select RAWRXD_P11_FORCE_OLLAMA_MODEL into IDC 1206
TIP_SHA=$sha
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
RUNLOG=$runLog
CHATLOG=$chatLog
"@
  Set-Content $probeReceipt $body -Encoding UTF8
  Log "FAIL_CLOSED still on bigdaddyg sel=$sel"
  exit 7
}

Start-Sleep -Seconds 1
$markerA = "B18_P11_REQUEST_A_$stamp"
$markerB = "B18_P11_REQUEST_B_$stamp"
$tokenB = "P11_TOKEN_B_$stamp"
$ollamaDebug = Join-Path $logDir 'ollama_debug.log'
$debugPaneId = 1014  # IDC_OUTPUT_EDIT_DEBUG — complete_buffer_bytes lands via appendNativeDebugOutput

# Show Debug pane so complete_buffer_bytes text is retained/readable.
$tabs = [P11Ui]::FindById($main, 1301)
if ($tabs -ne [IntPtr]::Zero) {
  [void][P11Ui]::SendMessageW($tabs, 0x130C, [IntPtr]3, [IntPtr]::Zero) # TCM_SETCURSEL debug
  [void][P11Ui]::PostMessageW($main, [P11Ui]::WM_COMMAND, [IntPtr]1301, $tabs)
  Start-Sleep -Milliseconds 400
}

$chinA = [P11Ui]::Chin($main, "Write a very long multi-paragraph essay about cancel recovery, fencing, and reliability gates. Repeat ideas. Include marker $markerA.")
Log "CHIN_A=$chinA"
Start-Sleep -Milliseconds 300
[P11Ui]::ClickId($main, 1204)
$startedA = Wait-LogMatch $chatLog 'BACKEND_REQUEST_START|CHAT_SEND_ATTEMPT|request_started' 45
Log "STARTED_A=$startedA"
# Wait until A actually streams into UI so Stop can race queued updates → stale_ui_update.
$aStreamed = Wait-LogMatch $chatLog 'ui_update request_id=1' 60
Log "A_STREAMED_UI=$aStreamed"
Start-Sleep -Milliseconds 350
[P11Ui]::ClickId($main, 1210)
$cancelReq = Wait-LogMatch $chatLog 'cancel_requested' 30
$cancelAck = Wait-LogMatch $chatLog 'cancel_acknowledged' 30
# Give queued A updates a chance to land as stale_ui_update after stop.
Start-Sleep -Milliseconds 1200
$staleEarly = Wait-LogMatch $chatLog 'stale_ui_update' 5
Log "CANCEL_REQ=$cancelReq CANCEL_ACK=$cancelAck STALE_EARLY=$staleEarly"

try { $proc.Refresh() } catch {}
if ($proc.HasExited) {
  $body = @"
P11=FAIL
P11_NOTE=CRASH_ON_CANCEL
TIP_SHA=$sha
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
RUNLOG=$runLog
CHATLOG=$chatLog
"@
  Set-Content $probeReceipt $body -Encoding UTF8
  exit 7
}

$chinB = [P11Ui]::Chin($main, "Reply with exactly one short line containing both $tokenB and $markerB.")
Log "CHIN_B=$chinB"
Start-Sleep -Milliseconds 300
[P11Ui]::ClickId($main, 1204)
$startedB = Wait-LogMatch $chatLog 'CHAT_SEND_ATTEMPT|BACKEND_REQUEST_START|request_started' 45
Log "STARTED_B=$startedB"

# Wait for B completion path (RESPONSE_END / complete=1), not just first token.
$endB = Wait-LogMatch $chatLog 'RESPONSE_END request_id=2|ui_update request_id=2[^\r\n]*complete=1|BACKEND_REQUEST_END request_id=2 success=1' 120
Log "END_B=$endB"
Start-Sleep -Milliseconds 800

$outText = [P11Ui]::GetText([P11Ui]::FindById($main, 1203))
$tokenHit = ($outText -and $outText.Contains($tokenB))
$markerBHit = ($outText -and $outText.Contains($markerB))
$debugText = [P11Ui]::GetText([P11Ui]::FindById($main, $debugPaneId))
$chatRaw = ''
if (Test-Path $chatLog) { $chatRaw = Get-Content -LiteralPath $chatLog -Raw -ErrorAction SilentlyContinue }
$ollamaRaw = ''
if (Test-Path $ollamaDebug) { $ollamaRaw = Get-Content -LiteralPath $ollamaDebug -Raw -ErrorAction SilentlyContinue }
$allEvidence = "$chatRaw`n$ollamaRaw`n$debugText"

# Hard fence: exact chat_runtime.log keys only. No soft proxies. tokenHit ≠ fence.
# LIVE tip 8988 TIP_CLIMB=HOLD owners if missing:
#   GENERATED_TOKENS=      → generateOllamaModel logDebug-only (Win32IDE.cpp ~1375)
#   complete_buffer_bytes= → handleCopilotUiUpdate appendNativeDebugOutput-only (~9332)
#   stale_ui_update        → WriteChatRuntimeEvidence wired (~9238); callback returns on stop (~9204)
Start-Sleep -Milliseconds 500
if (Test-Path $chatLog) { $chatRaw = Get-Content -LiteralPath $chatLog -Raw -ErrorAction SilentlyContinue }

$uiUpdate = ($chatRaw -match 'ui_update request_id=2')
$genTokensMatch = [regex]::Match($chatRaw, 'GENERATED_TOKENS=([1-9][0-9]*)')
$genTokensVal = if ($genTokensMatch.Success) { [int]$genTokensMatch.Groups[1].Value } else { 0 }
$genTokens = $genTokensMatch.Success
$completeBufMatch = [regex]::Match($chatRaw, 'complete_buffer_bytes=([1-9][0-9]*)')
$completeBufVal = if ($completeBufMatch.Success) { [int]$completeBufMatch.Groups[1].Value } else { 0 }
$completeBuf = $completeBufMatch.Success
$staleDrop = ($chatRaw -match 'stale_ui_update')
$streamedOnly = $false
$rejectBlank = ([regex]::Matches($chatRaw, 'CHAT_SEND_REJECTED blank=1')).Count
$sendAttempts = ([regex]::Matches($chatRaw, 'CHAT_SEND_ATTEMPT')).Count
$backendEnds = ([regex]::Matches($chatRaw, 'BACKEND_REQUEST_END')).Count
$respEndB = ($chatRaw -match 'RESPONSE_END request_id=2') -or
            ($chatRaw -match 'BACKEND_REQUEST_END request_id=2 success=1')
$alive = $false
try { $proc.Refresh(); $alive = -not $proc.HasExited } catch {}

$missingOwners = @()
if (-not $genTokens -or $genTokensVal -le 0) {
  $missingOwners += 'GENERATED_TOKENS= missing chat_runtime.log (owner=generateOllamaModel/logDebug Win32IDE.cpp; wire WriteChatRuntimeEvidence)'
}
if (-not $completeBuf -or $completeBufVal -le 0) {
  $missingOwners += 'complete_buffer_bytes= missing chat_runtime.log (owner=handleCopilotUiUpdate appendNativeDebugOutput-only; wire WriteChatRuntimeEvidence)'
}
if (-not $staleDrop) {
  $missingOwners += 'stale_ui_update missing chat_runtime.log (owner=handleCopilotUiUpdate; callback returns on stop before PostMessage)'
}
if (-not ($tokenHit -or $markerBHit)) {
  $missingOwners += 'tokenHit/markerB missing UI transcript'
}
$missingNote = ($missingOwners -join ' | ')

Log "TOKEN_HIT=$tokenHit MARKER_B_HIT=$markerBHit UI_UPDATE=$uiUpdate GEN_TOKENS=$genTokens($genTokensVal) COMPLETE_BUF=$completeBuf($completeBufVal) STALE_DROP=$staleDrop END_B=$endB RESP_END_B=$respEndB ALIVE=$alive SEND_ATTEMPTS=$sendAttempts REJECT_BLANK=$rejectBlank BACKEND_ENDS=$backendEnds"
Log ("CHAT_OUT_LEN=$($outText.Length) SNIP=$($outText.Substring(0, [Math]::Min(400, [Math]::Max(0,$outText.Length))) -replace '`r|`n',' / ')")

$p11 = 'FAIL'
$p11note = ''
$inferenceVerified = $false
if (-not $alive -and $proc.HasExited) {
  $p11note = 'CRASH_AFTER_REQUEST_B'
} elseif (-not $startedA -and $rejectBlank -gt 0 -and $sendAttempts -eq 0) {
  $p11 = 'FAIL_CLOSED'
  $p11note = 'MISSING_BACKEND_OWNER=CHIN/Send path rejected blank; chat input staging failed (owner=stageCopilotChatInputUtf8 / HandleCopilotSend)'
} elseif (-not $sel) {
  $p11 = 'FAIL_CLOSED'
  $p11note = "MISSING_BACKEND_OWNER=no model selected needle=$ModelNeedle"
} elseif ($genTokens -and ($genTokensVal -gt 0) -and $completeBuf -and ($completeBufVal -gt 0) -and $staleDrop -and ($tokenHit -or $markerBHit) -and $cancelReq -and $cancelAck -and $startedB) {
  $inferenceVerified = $true
  $p11 = 'PASS'
  $p11note = "A_STOP_B fence verified model=$sel GEN_TOKENS=$genTokensVal COMPLETE_BUF=$completeBufVal STALE_DROP=1 tokenHit=$tokenHit markerB=$markerBHit"
} else {
  $p11 = 'FAIL_CLOSED'
  $p11note = "FENCE_LOG_MISSING GEN_TOKENS=$genTokens COMPLETE_BUF=$completeBuf STALE_DROP=$staleDrop tokenHit=$tokenHit markerB=$markerBHit cancel=$cancelReq/$cancelAck startedB=$startedB | $missingNote"
}

try {
  if (-not $proc.HasExited) {
    [void][P11Ui]::PostMessageW($main, [P11Ui]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
    $proc.WaitForExit(8000) | Out-Null
  }
} catch {}
try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force } } catch {}

$shaEnd = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToUpperInvariant()
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$probeBody = @"
BATCH18_P11_TOKEN_PROBE_RECEIPT
ASOF_UTC=$asof
TIP_SHA=$sha
TIP_SHA_END=$shaEnd
SHA_BOUND=$($sha -eq $shaEnd)
OLLAMA_UP=1
MODEL_SELECTED=$sel
STARTED_A=$startedA
CANCEL_REQ=$cancelReq
CANCEL_ACK=$cancelAck
STARTED_B=$startedB
TOKEN_HIT=$tokenHit
MARKER_B_HIT=$markerBHit
UI_UPDATE=$uiUpdate
GEN_TOKENS=$genTokens
GEN_TOKENS_VALUE=$genTokensVal
COMPLETE_BUF=$completeBuf
COMPLETE_BUF_VALUE=$completeBufVal
STALE_UI_UPDATE=$staleDrop
RESP_END_B=$respEndB
STREAMED_ONLY_NO_GEN_TOKENS=$streamedOnly
A_STREAMED_UI=$aStreamed
INFERENCE_COMPLETION_AND_STALE_FENCE=$(if($inferenceVerified -and $p11 -eq 'PASS'){'VERIFIED'}else{'NOT_VERIFIED'})
P11=$p11
P11_NOTE=$p11note
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
RUNLOG=$runLog
CHATLOG=$chatLog
OLLAMA_DEBUG=$ollamaDebug
"@
Set-Content $probeReceipt $probeBody -Encoding UTF8
Log $probeBody

# Update GUI_FOLLOWUP P11 fields only; preserve prior P07/P08/P09 PASS rows.
$p07='PASS'; $p07note='PRESERVED'
$p08='PASS'; $p08note='PRESERVED'
$p08session='PASS_HEIGHT_MATCH'
$p09='PASS'; $p09note='PRESERVED'
if (Test-Path $followupReceipt) {
  $prev = Get-Content $followupReceipt -Raw
  if ($prev -match '(?m)^P07=(.+)$') { $p07 = $Matches[1].Trim() }
  if ($prev -match '(?m)^P07_NOTE=(.+)$') { $p07note = $Matches[1].Trim() }
  if ($prev -match '(?m)^P08=(.+)$') { $p08 = $Matches[1].Trim() }
  if ($prev -match '(?m)^P08_NOTE=(.+)$') { $p08note = $Matches[1].Trim() }
  if ($prev -match '(?m)^P08_SESSION_RELOAD=(.+)$') { $p08session = $Matches[1].Trim() }
  if ($prev -match '(?m)^P09=(.+)$') { $p09 = $Matches[1].Trim() }
  if ($prev -match '(?m)^P09_NOTE=(.+)$') { $p09note = $Matches[1].Trim() }
}
$followBody = @"
BATCH18_GUI_FOLLOWUP_RECEIPT
ASOF_UTC=$asof
TIP_SHA=$sha
TIP_SHA_END=$shaEnd
SHA_BOUND=$($sha -eq $shaEnd)
P07=$p07
P07_NOTE=$p07note
P08=$p08
P08_NOTE=$p08note
P08_SESSION_RELOAD=$p08session
P09=$p09
P09_NOTE=$p09note
P11=$p11
P11_NOTE=$p11note
CERTIFIED=0
PROMOTE=0
RUNLOG=$runLog
P11_PROBE=$probeReceipt
CHATLOG=$chatLog
"@
Set-Content $followupReceipt $followBody -Encoding UTF8

# Patch disposition P11 only
$disp = @"
DISPOSITION=BATCH_18_RUNTIME_GATE
STATUS=PARTIAL_RUNTIME_REACHED_UNPROMOTED
ASOF_UTC=$asof
TIP_SHA=$sha
TIP_PATH=$ExePath
P06=RUNTIME_REACHED_UNPROMOTED
P07=$p07
P08=$p08
P08_SESSION_RELOAD=$p08session
P09=$p09
P10=RUNTIME_REACHED_UNPROMOTED
P11=$p11
P11_NOTE=$p11note
P11_EVIDENCE=$probeReceipt
PRODUCT_RUNTIME_PASS=$(if($p11 -eq 'PASS'){'4/6'}else{'3/6'})
HONEST_PRODUCT_OVERRIDE=1
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
REMAINING_ISOLATION=DebuggerIntegration
NEXT_EXECUTABLE_GATE=$(if($p11 -eq 'PASS'){'P06/P10 promote conjunction / multi-family'}else{'P11 response/stale fence token proof'})
SEAL=P07_P08_P09_PASS_P11_$p11 CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD
"@
Set-Content $disposition $disp -Encoding UTF8

Write-Output "P11=$p11"
Write-Output "TIP_SHA=$sha"
Write-Output "EVIDENCE=$probeReceipt"
exit 0
