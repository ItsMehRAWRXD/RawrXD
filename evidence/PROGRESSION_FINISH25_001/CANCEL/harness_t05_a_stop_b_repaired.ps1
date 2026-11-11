#Requires -Version 5.1
# T05 Aâ†’Stopâ†’B on progression SHA 18FA04F9â€¦ â€” repaired harness (NO SB_GETTEXTW cross-proc)
# PROMOTE=0 CERTIFIED=0 NOT_RUN!=PASS  FINISH_25_PASS=19 controlling untouched
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL'
$Logs = Join-Path $OutDir 'logs'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe'
$ExpectSha = '71D1459754830B5987E2291CE2FA43E3A8B6900F27AC1997A8B4D9F7B523CE05'
$ExpectSize = 2594304
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir ("T05_A_STOP_B_RUNLOG_{0}.txt" -f $Stamp)
$Result = Join-Path $OutDir ("T05_A_STOP_B_RESULT_{0}.txt" -f $Stamp)
$CrashDir = Join-Path $env:LOCALAPPDATA 'RawrXD\crashes'
Set-Content $Log ''
function WLog($m){ $l='[{0}] {1}' -f (Get-Date -Format o),$m; Add-Content $Log $l; Write-Output $l }

$cs = @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class T05Repair {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public const uint WM_SETTEXT=0x000C; public const uint BM_CLICK=0x00F5; public const uint WM_COMMAND=0x0111; public const uint WM_CLOSE=0x0010;
  public static void ClickChild(IntPtr btn){ if(btn!=IntPtr.Zero) SendMessageW(btn,BM_CLICK,IntPtr.Zero,IntPtr.Zero); }
  public static int SetEditWmOnly(IntPtr edit,string text){
    IntPtr p=Marshal.StringToHGlobalUni(text); SendMessageW(edit,WM_SETTEXT,IntPtr.Zero,p); Marshal.FreeHGlobal(p);
    return SendMessageW(edit,0x000E,IntPtr.Zero,IntPtr.Zero).ToInt32();
  }
  public static IntPtr FindMain(uint pid){ IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var c=new StringBuilder(256); GetClassNameW(h,c,256); if(c.ToString()=="RawrXD_IDE_Window"){found=h;return false;} return true;},IntPtr.Zero); return found; }
  public static IntPtr FindId(IntPtr parent,int id){ IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,-12)==id){found=h;return false;} return true;},IntPtr.Zero); return found; }
  public static string Text(IntPtr h){
    int len=SendMessageW(h,0x000E,IntPtr.Zero,IntPtr.Zero).ToInt32();
    if(len<=0) return "";
    var buf=new StringBuilder(len+2);
    SendMessageW(h,0x000D,(IntPtr)(len+1),buf); return buf.ToString();
  }
  // NO SB_GETTEXTW / SB_GETTEXTLENGTHW â€” proven harness crash origin (COMCTL32+0xBD02)
  public static string StatusBarWmGetText(IntPtr main){
    IntPtr found=IntPtr.Zero; EnumChildWindows(main,(h,l)=>{ var c=new StringBuilder(256); GetClassNameW(h,c,256);
      if(c.ToString()=="msctls_statusbar32"){found=h;return false;} return true;},IntPtr.Zero);
    if(found==IntPtr.Zero) return ""; return Text(found);
  }
  public static List<string> ComboItems(IntPtr combo){ var rows=new List<string>(); if(combo==IntPtr.Zero) return rows;
    int cnt=SendMessageW(combo,0x0146,IntPtr.Zero,IntPtr.Zero).ToInt32();
    for(int i=0;i<cnt && i<200;i++){ int len=SendMessageW(combo,0x0149,(IntPtr)i,IntPtr.Zero).ToInt32(); if(len<0) continue;
      var b=new StringBuilder(len+2); SendMessageW(combo,0x0148,(IntPtr)i,b); rows.Add(b.ToString()); } return rows; }
  public static void SelectComboIndex(IntPtr parent,IntPtr combo,int index,int comboId){
    SendMessageW(combo,0x014E,(IntPtr)index,IntPtr.Zero);
    IntPtr wp=(IntPtr)((1<<16)|(comboId&0xFFFF)); PostMessageW(parent,WM_COMMAND,wp,combo);
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$reqA='NOT_RUN'; $stopOk='NOT_RUN'; $reqB='NOT_RUN'; $lateA='NOT_RUN'
$disposition='NOT_RUN'; $model=''; $corrId=''
$markerA = "T05_A_CORR_$([guid]::NewGuid().ToString('N').Substring(0,10))"
$markerB = "T05_B_PONG_$([guid]::NewGuid().ToString('N').Substring(0,8))"

$shaPre=(Get-FileHash $CandExe -Algorithm SHA256).Hash
$sz=(Get-Item $CandExe).Length
WLog "SHA_PRE=$shaPre SIZE=$sz EXPECT=$ExpectSha"
if($shaPre -ne $ExpectSha -or [int64]$sz -ne $ExpectSize){
  WLog 'SHA_DRIFT'
  @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
STAMP=$Stamp
T05=FAIL_CLOSED_SHA_DRIFT
SHA_PRE=$shaPre
EXPECT=$ExpectSha
PROMOTE=0
"@ | Set-Content $Result -Encoding UTF8
  exit 3
}

$beforeDumps=@()
if(Test-Path $CrashDir){ $beforeDumps=@(Get-ChildItem $CrashDir -Filter '*.dmp' | ForEach-Object FullName) }

try { $null=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3; WLog 'OLLAMA_UP=1' }
catch { WLog "OLLAMA_UP=0 $($_.Exception.Message)" }

$sessClr = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
if(Test-Path $sessClr){ Remove-Item $sessClr -Force -EA SilentlyContinue; WLog 'SESSION_CLEARED' }
Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object {
  WLog "KILL $($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

$psi=New-Object Diagnostics.ProcessStartInfo
$psi.FileName=$CandExe; $psi.WorkingDirectory=(Split-Path $CandExe); $psi.UseShellExecute=$false
$proc=[Diagnostics.Process]::Start($psi)
WLog "PID=$($proc.Id)"

$main=[IntPtr]::Zero
$dl=(Get-Date).AddSeconds(90)
while((Get-Date) -lt $dl){
  if($proc.HasExited){ WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main=[T05Repair]::FindMain([uint32]$proc.Id)
  if($main -ne [IntPtr]::Zero -and [T05Repair]::IsWindowVisible($main) -and [T05Repair]::FindId($main,1204) -ne [IntPtr]::Zero){ break }
  Start-Sleep -Milliseconds 300
}
if($main -eq [IntPtr]::Zero){
  @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
T05=FAIL_CLOSED_MAIN
PROMOTE=0
RUNLOG=$Log
"@ | Set-Content $Result -Encoding UTF8
  exit 4
}
[void][T05Repair]::ShowWindow($main,9)
[void][T05Repair]::SetForegroundWindow($main)
WLog ("HWND=0x{0:X}" -f $main.ToInt64())

$inputHwnd=[T05Repair]::FindId($main,1202)
$outputHwnd=[T05Repair]::FindId($main,1203)
$send=[T05Repair]::FindId($main,1204)
$combo=[T05Repair]::FindId($main,1206)
$stop=[T05Repair]::FindId($main,1210)
$rows=@()
$modelDl=(Get-Date).AddSeconds(90)
while((Get-Date) -lt $modelDl){
  if($proc.HasExited){ WLog "EXIT_DURING_MODEL_WAIT exit=$($proc.ExitCode)"; break }
  $rows=@([T05Repair]::ComboItems($combo))
  if($rows.Count -gt 0){ break }
  Start-Sleep -Milliseconds 500
}
WLog "MODEL_COUNT=$($rows.Count)"
$pick=-1
foreach($p in @('gemma3:4b','qwen2.5-coder:1.5b-base','llama3.2','nemotron-3-nano:4b')){
  for($i=0;$i -lt $rows.Count;$i++){ if($rows[$i] -like "*$p*"){ $pick=$i; $model=$rows[$i]; break } }
  if($pick -ge 0){ break }
}
if($pick -lt 0){
  for($i=0;$i -lt $rows.Count;$i++){
    if($rows[$i] -match '(?i)ollama' -and $rows[$i] -notmatch 'connecting'){ $pick=$i; $model=$rows[$i]; break }
  }
}
if($pick -lt 0){
  if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
  @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
T05=FAIL_CLOSED_NO_MODEL
PROMOTE=0
RUNLOG=$Log
"@ | Set-Content $Result -Encoding UTF8
  exit 5
}
[T05Repair]::SelectComboIndex($main,$combo,$pick,1206)
WLog "MODEL=$model"
Start-Sleep -Milliseconds 800

$corrId = "CORR_$Stamp"
$promptA = "Write a very long detailed essay of at least 2000 words about Windows kernel scheduling. Include exact tokens $markerA and request_id=$corrId somewhere in the essay."
$len=[T05Repair]::SetEditWmOnly($inputHwnd,$promptA)
WLog "SETEDIT_WM_ONLY len=$len HARNESS=NO_SB_GETTEXT_CROSSPROC CLEAR=0"
[T05Repair]::ClickChild($send)
WLog "REQUEST_A_SUBMITTED markerA=$markerA corr=$corrId"
Start-Sleep -Milliseconds 400

$armed=0; $crash=0; $exit=''
$armDl=(Get-Date).AddSeconds(45)
while((Get-Date) -lt $armDl){
  if($proc.HasExited){ $crash=1; $exit="$($proc.ExitCode)"; WLog "CRASH_ARM exit=$exit"; break }
  $stopEn=[int][T05Repair]::IsWindowEnabled($stop)
  if($stopEn -eq 1){
    $st=[T05Repair]::StatusBarWmGetText($main)
    $armed=1; $reqA='PASS'; WLog "REQUEST_A_ARMED stopEnabled=$stopEn status_wm='$st'"; break
  }
  Start-Sleep -Milliseconds 200
}
if($armed -ne 1){
  $reqA='FAIL'; $stopOk='FAIL'; $reqB='FAIL'; $lateA='FAIL'
  $disposition = if($crash -eq 1){'FAIL_CLOSED_CRASH_ON_REQUEST_A'} else {'FAIL_CLOSED_REQUEST_A_NOT_ARMED'}
  WLog $disposition
  if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
  $shaPost=(Get-FileHash $CandExe -Algorithm SHA256).Hash
  @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
STAMP=$Stamp
CANDIDATE_SHA=$shaPre
SHA_POST=$shaPost
SHA_MATCH=$([int]($shaPre -eq $ExpectSha -and $shaPost -eq $ExpectSha))
HARNESS=NO_CLEAR+WM_SETTEXT_ONLY+SINGLE_BM_CLICK+NO_SB_GETTEXT_CROSSPROC+ARM_STOP_ONLY
HARNESS_CROSSPROC_SB_GETTEXT=PROVEN_ORIGIN
CANCEL_PRODUCT_DEFECT=NOT_PROVEN
T05=$disposition
REQUEST_A=$reqA
STOP=$stopOk
REQUEST_B=$reqB
LATE_A=$lateA
CORR_ID=$corrId
MARKER_A=$markerA
MARKER_B=$markerB
MODEL=$model
CRASH=$crash
EXIT_CODE=$exit
PROMOTE=0
CERTIFIED=0
FINISH_25_PASS=19
RUNLOG=$Log
"@ | Set-Content $Result -Encoding UTF8
  exit 6
}

Start-Sleep -Milliseconds 1200
[T05Repair]::ClickChild($stop)
$stopAt=Get-Date
WLog 'STOP_CLICKED'
Start-Sleep -Milliseconds 500
$stStop=[T05Repair]::StatusBarWmGetText($main)
$stopEnAfter=[int][T05Repair]::IsWindowEnabled($stop)
WLog "STATUS_AFTER_STOP='$stStop' stopEnabled=$stopEnAfter"
$stStop | Set-Content (Join-Path $Logs ("t05_status_after_stop_{0}.txt" -f $Stamp))
if($stStop -match '(?i)stop|cancel' -or $stopEnAfter -eq 0){ $stopOk='PASS' } else { $stopOk='FAIL' }

$waitMs=[Math]::Max(0, 5000 - [int]((Get-Date)-$stopAt).TotalMilliseconds)
if($waitMs -gt 0){ Start-Sleep -Milliseconds $waitMs }

$outBeforeB=[T05Repair]::Text($outputHwnd)
$outBeforeB | Set-Content (Join-Path $Logs ("t05_output_before_b_{0}.txt" -f $Stamp)) -Encoding UTF8
$promptB="Reply with exactly one word: $markerB"
[void][T05Repair]::SetEditWmOnly($inputHwnd,$promptB)
[T05Repair]::ClickChild($send)
WLog "REQUEST_B_SUBMITTED markerB=$markerB"

$bOk=0; $busyReject=0
$bDeadline=(Get-Date).AddSeconds(120)
while((Get-Date) -lt $bDeadline){
  if($proc.HasExited){ WLog "CRASH_B exit=$($proc.ExitCode)"; break }
  $st=[T05Repair]::StatusBarWmGetText($main)
  $outNow=[T05Repair]::Text($outputHwnd)
  if($st -match '(?i)already running'){ $busyReject=1; WLog 'REQUEST_B_REJECTED_ALREADY_RUNNING'; break }
  if($outNow -match [regex]::Escape($markerB)){ $bOk=1; WLog "REQUEST_B_RENDERED outLen=$($outNow.Length)"; break }
  Start-Sleep -Milliseconds 300
}
$outFinal=[T05Repair]::Text($outputHwnd)
$outFinal | Set-Content (Join-Path $Logs ("t05_output_after_b_{0}.txt" -f $Stamp)) -Encoding UTF8
if($busyReject -eq 1){ $reqB='FAIL' } elseif($bOk -eq 1){ $reqB='PASS' } else { $reqB='FAIL' }

Start-Sleep -Seconds 3
$outLate=[T05Repair]::Text($outputHwnd)
$outLate | Set-Content (Join-Path $Logs ("t05_output_late_{0}.txt" -f $Stamp)) -Encoding UTF8
$hadABeforeB=($outBeforeB -match [regex]::Escape($markerA))
$hasALate=($outLate -match [regex]::Escape($markerA))
$hasB=($outLate -match [regex]::Escape($markerB))
$staleGrowth=0
if($hasALate -and -not $hadABeforeB -and $hasB){ $staleGrowth=1 }
if($hasB -and (-not $hasALate -or $hadABeforeB)){
  if(-not $hasALate){ $lateA='PASS' }
  elseif($hadABeforeB -and $hasB){ $lateA='PASS'; WLog 'LATE_A=PASS (A partial before B; B rendered)' }
  else { $lateA='FAIL' }
} elseif($staleGrowth -eq 1){
  $lateA='FAIL'; WLog 'LATE_A=FAIL (A marker appeared after B window â€” stale)'
} elseif($reqB -eq 'PASS'){
  $lateA='PASS'
} else {
  $lateA='FAIL'
}

$corrOk='FAIL'
if($reqA -eq 'PASS' -and $reqB -eq 'PASS' -and $hasB -and ($outLate -notmatch [regex]::Escape($corrId) -or $hadABeforeB -or -not $hasALate)){
  # B completed under distinct request; A corr id must not newly dominate post-B output
  $corrOk='PASS'
}
if($reqB -eq 'PASS' -and $lateA -eq 'PASS'){ $corrOk='PASS' }

if($reqA -eq 'PASS' -and $stopOk -eq 'PASS' -and $reqB -eq 'PASS' -and $lateA -eq 'PASS'){
  $disposition='PASS_CANCEL_A_STOP_B'
} else {
  $disposition="FAIL_CLOSED A=$reqA STOP=$stopOk B=$reqB LATE_A=$lateA CORR=$corrOk"
}
WLog "DISPOSITION=$disposition"

[void][T05Repair]::PostMessageW($main,[T05Repair]::WM_CLOSE,[IntPtr]::Zero,[IntPtr]::Zero)
Start-Sleep -Milliseconds 800
if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
Start-Sleep 1

$shaPost=(Get-FileHash $CandExe -Algorithm SHA256).Hash
$newDump=''
if(Test-Path $CrashDir){
  $newest=Get-ChildItem $CrashDir -Filter '*.dmp' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if($newest -and ($beforeDumps -notcontains $newest.FullName)){ $newDump=$newest.FullName }
}
if($shaPost -ne $ExpectSha){ $disposition='FAIL_CLOSED_SHA_DRIFT_POST' }

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
STAMP=$Stamp
CANDIDATE_SHA=$shaPre
SHA_POST=$shaPost
SHA_MATCH=$([int]($shaPre -eq $ExpectSha -and $shaPost -eq $ExpectSha))
HARNESS=NO_CLEAR+WM_SETTEXT_ONLY+SINGLE_BM_CLICK+NO_SB_GETTEXT_CROSSPROC+ARM_STOP_ONLY+WM_GETTEXT_STATUS
HARNESS_CROSSPROC_SB_GETTEXT=PROVEN_ORIGIN
CANCEL_PRODUCT_DEFECT=NOT_PROVEN
T05=$disposition
REQUEST_A=$reqA
STOP=$stopOk
REQUEST_B=$reqB
LATE_A_STALE_REJECT=$lateA
CORR_ID=$corrId
CORR_OK=$corrOk
MARKER_A=$markerA
MARKER_B=$markerB
MODEL=$model
NEW_DUMP=$newDump
PROMOTE=0
CERTIFIED=0
FINISH_25_PASS=19
CONTROLLING_SEAL_REWRITE=0
RUNLOG=$Log
"@ | Set-Content $Result -Encoding UTF8
WLog "RESULT=$Result DISPOSITION=$disposition"
if($disposition -eq 'PASS_CANCEL_A_STOP_B'){ exit 0 } else { exit 1 }



