param([int]$MaxAttempts=8)
$ErrorActionPreference='Continue'
$base='F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006\T05_REQUEST_B_FAULTING_STACK_001'
$exe='F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$sha='0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E'
$cdb='C:\Users\Garrett\AppData\Local\Microsoft\WindowsApps\cdbX64.exe'
$dumpDir=Join-Path $base 'dumps'
New-Item -ItemType Directory -Force -Path $dumpDir,(Join-Path $base 'runs') | Out-Null
$hash=(Get-FileHash $exe -Algorithm SHA256).Hash
if($hash -ne $sha){ throw "SHA_MISMATCH actual=$hash" }

if(-not ('RawrXD_T05Fault' -as [type])){
  Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class RawrXD_T05Fault {
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  public const uint WM_SETTEXT=0x000C; public const uint BM_CLICK=0x00F5; public const uint WM_COMMAND=0x0111;
  public static IntPtr FindId(IntPtr parent, int id){
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,-12)==id){found=h;return false;} return true;},IntPtr.Zero);
    return found;
  }
  public static List<string> ComboItems(IntPtr combo){
    var rows=new List<string>(); if(combo==IntPtr.Zero) return rows;
    int cnt=SendMessageW(combo,0x0146,IntPtr.Zero,IntPtr.Zero).ToInt32();
    for(int i=0;i<cnt && i<300;i++){
      int len=SendMessageW(combo,0x0149,(IntPtr)i,IntPtr.Zero).ToInt32(); if(len<0) continue;
      var b=new StringBuilder(len+2); SendMessageW(combo,0x0148,(IntPtr)i,b); rows.Add(b.ToString());
    }
    return rows;
  }
  public static void SelectComboIndex(IntPtr parent, IntPtr combo, int index, int comboId){
    SendMessageW(combo,0x014E,(IntPtr)index,IntPtr.Zero);
    IntPtr wp=(IntPtr)((1<<16)|(comboId&0xFFFF));
    SendMessageW(parent,WM_COMMAND,wp,combo);
    wp=(IntPtr)((9<<16)|(comboId&0xFFFF));
    SendMessageW(parent,WM_COMMAND,wp,combo);
  }
  public static int SetEditWmOnly(IntPtr edit, string text){
    IntPtr p=Marshal.StringToHGlobalUni(text);
    try { SendMessageW(edit,WM_SETTEXT,IntPtr.Zero,p); }
    finally { Marshal.FreeHGlobal(p); }
    return SendMessageW(edit,0x000E,IntPtr.Zero,IntPtr.Zero).ToInt32();
  }
  public static void ClickChild(IntPtr btn){ if(btn!=IntPtr.Zero) SendMessageW(btn,BM_CLICK,IntPtr.Zero,IntPtr.Zero); }
  public static string Text(IntPtr h){
    int len=SendMessageW(h,0x000E,IntPtr.Zero,IntPtr.Zero).ToInt32();
    if(len<=0) return "";
    var buf=new StringBuilder(len+2);
    SendMessageW(h,0x000D,(IntPtr)(len+1),buf); return buf.ToString();
  }
}
'@
}

function Stop-AllNative {
  # REQUIRED: I026_EXTERNAL_KILL_CORRELATION_001 — forbid Name='RawrXD-Win32IDE-Native*'
  # (wildcard TerminateProcess sibling Tip Ext mid-Issue49). Path-scoped to this T05 $exe only.
  Get-CimInstance Win32_Process -Filter "Name = 'RawrXD-Win32IDE-Native.exe'" -EA SilentlyContinue |
    Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -ieq $exe) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  Get-Process -Name 'cdb*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

$marker='RAWRXD_CANCEL_RECOVERY_OK'
$gotStack=$false
for($attempt=1; $attempt -le $MaxAttempts; $attempt++){
  Stop-AllNative
  $runDir=Join-Path $base ("runs\attempt_{0:D2}" -f $attempt)
  New-Item -ItemType Directory -Force -Path $runDir | Out-Null
  $liveDump=Join-Path $dumpDir ("t05_request_b_attempt{0:D2}.dmp" -f $attempt)
  $cdbLog=Join-Path $runDir 'cdb.log'
  $cmds=@"
.logopen $cdbLog
.sympath srv*
sxe -c ".echo ===T05_EXCEPTION===; .exr -1; kL 50; lm m RawrXD*; .dump /ma $liveDump; .logclose; qd" av
sxe -c ".echo ===T05_EXCEPTION===; .exr -1; kL 50; lm m RawrXD*; .dump /ma $liveDump; .logclose; qd" eh
sxe -c ".echo ===T05_EXCEPTION===; .exr -1; kL 50; lm m RawrXD*; .dump /ma $liveDump; .logclose; qd" c0000409
sxe -c ".echo ===T05_EXCEPTION===; .exr -1; kL 50; lm m RawrXD*; .dump /ma $liveDump; .logclose; qd" c0000005
sxi ibp
g
"@
  $cmdFile=Join-Path $runDir 'cdb_cmds.txt'
  $cmds | Set-Content $cmdFile -Encoding ASCII

  $p=Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
  $pidNative=$p.Id
  Start-Sleep -Milliseconds 800
  if(-not (Get-Process -Id $pidNative -ErrorAction SilentlyContinue)){
    "ATTEMPT=$attempt EARLY_EXIT_BEFORE_ATTACH" | Tee-Object -FilePath (Join-Path $runDir 'status.txt')
    continue
  }
  $cdbProc=Start-Process -FilePath $cdb -ArgumentList @('-p',"$pidNative",'-cf',$cmdFile) -PassThru -WindowStyle Minimized
  "ATTEMPT=$attempt NATIVE_PID=$pidNative CDB_PID=$($cdbProc.Id)" | Tee-Object -FilePath (Join-Path $runDir 'status.txt')
  Start-Sleep -Seconds 2

  $receipt=[ordered]@{
    Gate='T05_FAULT_CAPTURE'; Attempt=$attempt; CandidateSHA256=$sha; PID=$pidNative
    CancelObserved=$false; SecondRequestSent=$false; SecondRequestRecovered=$false
    ProcessAlive=$false; StopFeedbackObserved=$false; MarkerExact=$false
    TranscriptDelta=$null; Error=$null; CdbPid=$cdbProc.Id; LiveDump=$liveDump
  }
  try {
    $proc=Get-Process -Id $pidNative -ErrorAction Stop
    $until=[DateTime]::UtcNow.AddSeconds(90)
    do {
      $proc.Refresh()
      if($proc.MainWindowHandle -ne [IntPtr]::Zero){
        $probe=[RawrXD_T05Fault]::FindId($proc.MainWindowHandle,1204)
        if($probe -ne [IntPtr]::Zero){ break }
      }
      Start-Sleep -Milliseconds 300
    } while([DateTime]::UtcNow -lt $until)
    if($proc.MainWindowHandle -eq [IntPtr]::Zero){ throw 'NO_MAIN_WINDOW' }
    $main=$proc.MainWindowHandle
    $combo=[RawrXD_T05Fault]::FindId($main,1206)
    $inputHwnd=[RawrXD_T05Fault]::FindId($main,1202)
    $outputHwnd=[RawrXD_T05Fault]::FindId($main,1203)
    $sendHwnd=[RawrXD_T05Fault]::FindId($main,1204)
    if($combo -eq [IntPtr]::Zero -or $inputHwnd -eq [IntPtr]::Zero -or $sendHwnd -eq [IntPtr]::Zero){ throw 'CONTROLS_MISSING' }

    $rows=@(); $hasGemma=$false
    $modelUntil=[DateTime]::UtcNow.AddSeconds(120)
    while([DateTime]::UtcNow -lt $modelUntil){
      $null=Get-Process -Id $pidNative -ErrorAction Stop
      $rows=@([RawrXD_T05Fault]::ComboItems($combo))
      foreach($r in $rows){ if($r -like '*gemma3:4b*'){ $hasGemma=$true; break } }
      if($hasGemma){ break }
      Start-Sleep -Milliseconds 500
    }
    if(-not $hasGemma){ throw 'gemma3:4b not discovered' }
    $pick=-1; $model=''
    foreach($pref in @('gemma3:4b','qwen2.5-coder:1.5b-base','nemotron-3-nano:4b','llama3.2','bigdaddyg-productivity-local')){
      for($i=0;$i -lt $rows.Count;$i++){
        if($rows[$i] -like "*$pref*"){ $pick=$i; $model=$rows[$i]; break }
      }
      if($pick -ge 0){ break }
    }
    if($pick -lt 0){ throw 'NO_USABLE_MODEL' }
    [RawrXD_T05Fault]::SelectComboIndex($main,$combo,$pick,1206)
    $receipt.Model=$model
    Start-Sleep -Milliseconds 800

    $promptA='Generate a very long detailed response about C++ build systems. Continue for many paragraphs and do not stop early.'
    $len=[RawrXD_T05Fault]::SetEditWmOnly($inputHwnd,$promptA)
    if($len -le 0){ throw 'PROMPT_A_SET_FAILED' }
    [RawrXD_T05Fault]::ClickChild($sendHwnd)

    $stopEnabled=$false
    for($i=0;$i -lt 90;$i++){
      Start-Sleep -Milliseconds 500
      $null=Get-Process -Id $pidNative -ErrorAction Stop
      $stopHwnd=[RawrXD_T05Fault]::FindId($main,1210)
      if($stopHwnd -ne [IntPtr]::Zero -and [RawrXD_T05Fault]::IsWindowEnabled($stopHwnd)){ $stopEnabled=$true; break }
    }
    if(-not $stopEnabled){ throw 'STOP_NEVER_ENABLED' }
    [RawrXD_T05Fault]::ClickChild($stopHwnd)
    $receipt.CancelObserved=$true
    Start-Sleep -Seconds 3

    $beforeB=''
    try { $beforeB=[RawrXD_T05Fault]::Text($outputHwnd) } catch { $beforeB='' }
    if($beforeB -match '\[stopped\]|generation cancelled'){ $receipt.StopFeedbackObserved=$true }

    $bPrompt="Reply exactly: $marker"
    $inputHwnd=[RawrXD_T05Fault]::FindId($main,1202)
    $sendHwnd=[RawrXD_T05Fault]::FindId($main,1204)
    $outputHwnd=[RawrXD_T05Fault]::FindId($main,1203)
    $blen=[RawrXD_T05Fault]::SetEditWmOnly($inputHwnd,$bPrompt)
    if($blen -le 0){ throw 'SET_TEXT_VERIFICATION_FAILED' }
    [RawrXD_T05Fault]::ClickChild($sendHwnd)
    $receipt.SecondRequestSent=$true

    $seen=$false; $delta=''
    for($i=0;$i -lt 90;$i++){
      Start-Sleep -Milliseconds 500
      try {
        $null=Get-Process -Id $pidNative -ErrorAction Stop
        $receipt.ProcessAlive=$true
        $outputHwnd=[RawrXD_T05Fault]::FindId($main,1203)
        $text=[RawrXD_T05Fault]::Text($outputHwnd)
        if($beforeB.Length -gt 0 -and $text.Length -ge $beforeB.Length){ $delta=$text.Substring($beforeB.Length) } else { $delta=$text }
        if($delta -match ("(?ms)^AI:.*{0}" -f [regex]::Escape($marker))){ $seen=$true; $receipt.MarkerExact=$true; break }
        if($text -match '\[stopped\]|generation cancelled'){ $receipt.StopFeedbackObserved=$true }
      } catch {
        $receipt.ProcessAlive=$false
        $receipt.Error=$_.Exception.Message
        break
      }
    }
    $receipt.TranscriptDelta=$delta
    $receipt.SecondRequestRecovered=$seen
    if(-not $receipt.Error){
      try { $null=Get-Process -Id $pidNative -ErrorAction Stop; $receipt.ProcessAlive=$true } catch {
        $receipt.ProcessAlive=$false
        if(-not $receipt.Error){ $receipt.Error=$_.Exception.Message }
      }
    }
  } catch {
    $receipt.Error=$_.Exception.Message
    try { $null=Get-Process -Id $pidNative -ErrorAction Stop; $receipt.ProcessAlive=$true } catch { $receipt.ProcessAlive=$false }
  }

  $receipt | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $runDir 'T05.receipt.json') -Encoding UTF8
  $receipt | ConvertTo-Json -Depth 6 | Out-Host

  if(-not $receipt.ProcessAlive -and $receipt.SecondRequestSent){
    for($w=0;$w -lt 30;$w++){
      if(Test-Path $liveDump){ break }
      if(Test-Path $cdbLog){
        $log=Get-Content $cdbLog -Raw -ErrorAction SilentlyContinue
        if($log -match 'T05_EXCEPTION|Child-SP'){ break }
      }
      Start-Sleep -Seconds 1
    }
    $werDumps=@(Get-ChildItem $dumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) })
    "CRASH_OBSERVED attempt=$attempt liveDumpExists=$(Test-Path $liveDump) werCount=$($werDumps.Count)" | Tee-Object -FilePath (Join-Path $runDir 'crash_note.txt')
    if((Test-Path $liveDump) -or $werDumps.Count -gt 0 -or ((Test-Path $cdbLog) -and (Select-String -Path $cdbLog -Pattern 'T05_EXCEPTION|Child-SP' -Quiet))){
      $gotStack=$true
      break
    }
  }
  Stop-AllNative
}

"GOT_STACK=$gotStack" | Set-Content (Join-Path $base 'LOOP_STATUS.txt') -Encoding UTF8
Get-ChildItem $dumpDir -ErrorAction SilentlyContinue | Format-Table Name,Length,LastWriteTime
if($gotStack){ exit 0 } else { exit 2 }
