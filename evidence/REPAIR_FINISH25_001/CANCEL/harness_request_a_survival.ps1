#Requires -Version 5.1
# REQUEST_A Cancel-path survival diagnostic Ã¢â‚¬â€ same SHA, no rebuild, no Stop/B
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\REPAIR_FINISH25_001\CANCEL'
$Logs = Join-Path $OutDir 'logs'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = 'F:\rawrxd\build_repair_finish25\bin\RawrXD-Win32IDE-Native.exe'
$ExpectSha = '4D35764A70A926DF4800A4BA41458E126DA82D74C9BD01B1624B61F51F36041C'
$ExpectSize = 2497024
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir ("REQUEST_A_SURVIVAL_RUNLOG_{0}.txt" -f $Stamp)
$Result = Join-Path $OutDir ("REQUEST_A_SURVIVAL_RESULT_{0}.txt" -f $Stamp)
$CrashDir = Join-Path $env:LOCALAPPDATA 'RawrXD\crashes'
Set-Content $Log ''
function WLog($m){ $l='[{0}] {1}' -f (Get-Date -Format o),$m; Add-Content $Log $l; Write-Output $l }

$cs = @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class ReqASurvive {
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
  public const uint WM_SETTEXT=0x000C; public const uint BM_CLICK=0x00F5; public const uint WM_COMMAND=0x0111;
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
  public static string StatusBarText(IntPtr main){
    IntPtr found=IntPtr.Zero; EnumChildWindows(main,(h,l)=>{ var c=new StringBuilder(256); GetClassNameW(h,c,256);
      if(c.ToString()=="msctls_statusbar32"){found=h;return false;} return true;},IntPtr.Zero);
    if(found==IntPtr.Zero) return "";
    int meta=SendMessageW(found,0x040C,IntPtr.Zero,IntPtr.Zero).ToInt32(); int len=meta&0xFFFF;
    if(len<=0) return ""; var buf=new StringBuilder(len+2); SendMessageW(found,0x040D,IntPtr.Zero,buf); return buf.ToString();
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

$shaPre=(Get-FileHash $CandExe -Algorithm SHA256).Hash
$sz=(Get-Item $CandExe).Length
WLog "SHA_PRE=$shaPre SIZE=$sz"
if($shaPre -ne $ExpectSha -or [int64]$sz -ne $ExpectSize){
  WLog 'SHA_DRIFT'
  Set-Content $Result "REQUEST_A_SURVIVES=0`nDISPOSITION=FAIL_CLOSED_SHA_DRIFT"
  exit 3
}

$beforeDumps=@()
if(Test-Path $CrashDir){ $beforeDumps=@(Get-ChildItem $CrashDir -Filter '*.dmp' | ForEach-Object FullName) }

try {
  $null=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3
  WLog 'OLLAMA_UP=1'
} catch {
  WLog "OLLAMA_UP=0 $($_.Exception.Message)"
}

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object {
  WLog "KILL $($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

$psi=New-Object Diagnostics.ProcessStartInfo
$psi.FileName=$CandExe
$psi.WorkingDirectory=(Split-Path $CandExe)
$psi.UseShellExecute=$false
$proc=[Diagnostics.Process]::Start($psi)
WLog "PID=$($proc.Id)"

$main=[IntPtr]::Zero
$dl=(Get-Date).AddSeconds(90)
while((Get-Date) -lt $dl){
  if($proc.HasExited){ WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main=[ReqASurvive]::FindMain([uint32]$proc.Id)
  if($main -ne [IntPtr]::Zero -and [ReqASurvive]::IsWindowVisible($main) -and [ReqASurvive]::FindId($main,1204) -ne [IntPtr]::Zero){ break }
  Start-Sleep -Milliseconds 300
}
if($main -eq [IntPtr]::Zero){
  WLog 'NO_MAIN'
  Set-Content $Result "REQUEST_A_SURVIVES=0`nDISPOSITION=FAIL_CLOSED_MAIN"
  exit 4
}
[void][ReqASurvive]::ShowWindow($main,9)
[void][ReqASurvive]::SetForegroundWindow($main)
WLog ("HWND=0x{0:X}" -f $main.ToInt64())

$inputHwnd=[ReqASurvive]::FindId($main,1202)
$send=[ReqASurvive]::FindId($main,1204)
$combo=[ReqASurvive]::FindId($main,1206)
$stop=[ReqASurvive]::FindId($main,1210)
Start-Sleep 3
$rows=@([ReqASurvive]::ComboItems($combo))
WLog "MODEL_COUNT=$($rows.Count)"
$pick=-1; $model=''
foreach($p in @('gemma3:4b','qwen2.5-coder:1.5b-base','llama3.2','nemotron-3-nano:4b')){
  for($i=0;$i -lt $rows.Count;$i++){
    if($rows[$i] -like "*$p*"){ $pick=$i; $model=$rows[$i]; break }
  }
  if($pick -ge 0){ break }
}
if($pick -lt 0){
  for($i=0;$i -lt $rows.Count;$i++){
    if($rows[$i] -match '(?i)ollama' -and $rows[$i] -notmatch 'connecting'){
      $pick=$i; $model=$rows[$i]; break
    }
  }
}
if($pick -lt 0){
  WLog 'NO_MODEL'
  if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  Set-Content $Result "REQUEST_A_SURVIVES=0`nDISPOSITION=FAIL_CLOSED_NO_MODEL"
  exit 5
}
[ReqASurvive]::SelectComboIndex($main,$combo,$pick,1206)
WLog "MODEL=$model"
Start-Sleep -Milliseconds 800

$marker='CANCEL_A_SURVIVAL_MARKER_F25_3B72'
$prompt="Write a very long detailed essay of at least 2000 words about Windows kernel scheduling. Include the exact marker $marker somewhere in the essay."
$len=[ReqASurvive]::SetEditWmOnly($inputHwnd,$prompt)
WLog "SETEDIT_WM_ONLY len=$len CLEAR=0 DUAL=0 CLICK=SINGLE_BM"
[ReqASurvive]::ClickChild($send)
WLog 'REQUEST_A_SUBMITTED'
Start-Sleep -Milliseconds 400

$crash=0; $exit=''; $armed=0; $survive=0
$armDl=(Get-Date).AddSeconds(45)
while((Get-Date) -lt $armDl){
  if($proc.HasExited){
    $crash=1; $exit="$($proc.ExitCode)"; WLog "CRASH_ARM exit=$exit"; break
  }
  $st=[ReqASurvive]::StatusBarText($main)
  $stopEn=[int][ReqASurvive]::IsWindowEnabled($stop)
  if($stopEn -eq 1 -or $st -match '(?i)warming|waiting|running|Ollama|already running|Inference|Generating|Streaming'){
    $armed=1; WLog "ARMED stopEnabled=$stopEn status='$st'"; break
  }
  Start-Sleep -Milliseconds 200
}

if($crash -eq 0 -and $armed -eq 1){
  $survDl=(Get-Date).AddSeconds(20)
  while((Get-Date) -lt $survDl){
    if($proc.HasExited){
      $crash=1; $exit="$($proc.ExitCode)"; WLog "CRASH_POST_ARM exit=$exit"; break
    }
    Start-Sleep -Milliseconds 250
  }
  if($crash -eq 0){ $survive=1; WLog 'REQUEST_A_SURVIVES=1' }
}

$shaPost=(Get-FileHash $CandExe -Algorithm SHA256).Hash
$newDump=''
if(Test-Path $CrashDir){
  $newest=Get-ChildItem $CrashDir -Filter '*.dmp' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if($newest -and ($beforeDumps -notcontains $newest.FullName)){
    $newDump=$newest.FullName; WLog "NEW_DUMP=$newDump"
  }
}

if(-not $proc.HasExited){
  WLog 'CLOSE_ALIVE'
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}

$disp='FAIL_CLOSED_CRASH_ON_REQUEST_A'
if($survive -eq 1){ $disp='REQUEST_A_SURVIVES_CANCEL_PATH' }
elseif($crash -eq 0 -and $armed -eq 0){ $disp='FAIL_CLOSED_A_NOT_ARMED_NO_CRASH' }

@(
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
  "STAMP=$Stamp"
  "CERT_EXE_SHA=$shaPre"
  "SHA_POST=$shaPost"
  "SHA_MATCH=$([int]($shaPre -eq $ExpectSha -and $shaPost -eq $ExpectSha))"
  "HARNESS=NO_CLEAR+WM_SETTEXT_ONLY+SINGLE_BM_CLICK"
  "MODEL=$model"
  "SETEDIT_LEN=$len"
  "REQUEST_A_SUBMITTED=1"
  "A_ARMED=$armed"
  "CRASH=$crash"
  "EXIT_CODE=$exit"
  "REQUEST_A_SURVIVES=$survive"
  "DISPOSITION=$disp"
  "NEW_DUMP=$newDump"
  "REBUILD=AUTHORIZED_RETEST
LINK_PROFILE=SLIM_WIN32IDE_DEEP2_OFF"
  "PROMOTE=0"
  "RUNLOG=$Log"
) | Set-Content $Result -Encoding UTF8
WLog "RESULT=$Result DISPOSITION=$disp SURVIVES=$survive"
if($survive -eq 1){ exit 0 } else { exit 1 }
