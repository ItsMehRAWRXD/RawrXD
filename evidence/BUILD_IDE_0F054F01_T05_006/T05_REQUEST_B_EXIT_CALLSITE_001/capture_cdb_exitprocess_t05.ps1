param([int]$MaxAttempts = 10)
# Lean ExitProcess/RtlExitUserProcess BP capture for T05 Request-B-after-cancel.
# TRACE ONLY. Do not g past hit (bp command dumps stack then qd).
$ErrorActionPreference = 'Continue'
$base = 'F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006\T05_REQUEST_B_EXIT_CALLSITE_001'
$exe = 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$sha = '0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E'
$cdb = 'C:\Users\Garrett\AppData\Local\Microsoft\WindowsApps\cdbX64.exe'
$proven = 'F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006\T05_REQUEST_B_FAULTING_STACK_001\capture_exitcode_procdump_t05.ps1'
$dumpDir = Join-Path $base 'dumps'
$runsDir = Join-Path $base 'runs'
New-Item -ItemType Directory -Force -Path $dumpDir,$runsDir | Out-Null
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
if ($hash -ne $sha) { throw "SHA_MISMATCH actual=$hash" }

# Reuse proven UI driver types by dot-sourcing helper body is heavy; inline minimal copy.
if (-not ('RawrXD_T05ExitCap' -as [type])) {
  . {
    # Pull type definition by invoking a no-op path through proven script's type only —
    # fall back to local identical type name used by capture_exitcode_procdump_t05.ps1.
    $null = $proven
  }
}

# Prefer proven script type: run a tiny preamble that only defines the type.
if (-not ('RawrXD_T05ExitCap' -as [type])) {
  Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class RawrXD_T05ExitCap {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool b, int p);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr h, out uint c);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  public const uint PROCESS_QUERY_LIMITED_INFORMATION=0x1000;
  public const uint SYNCHRONIZE=0x00100000;
  public const uint STILL_ACTIVE=259;
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
}
'@
}

function Stop-All {
  # REQUIRED: I026_EXTERNAL_KILL_CORRELATION_001 — forbid Name='RawrXD-Win32IDE-Native*'
  # (wildcard TerminateProcess sibling Tip Ext mid-Issue49). Path-scoped to this T05 $exe only.
  Get-CimInstance Win32_Process -Filter "Name = 'RawrXD-Win32IDE-Native.exe'" -EA SilentlyContinue |
    Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -ieq $exe) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  Get-Process -Name 'cdb*','cdbX64*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep 1
}
function Get-Exit([IntPtr]$h){
  if($h -eq [IntPtr]::Zero){ return $null }
  [uint32]$c=0
  if(-not [RawrXD_T05ExitCap]::GetExitCodeProcess($h,[ref]$c)){ return $null }
  if($c -eq [RawrXD_T05ExitCap]::STILL_ACTIVE){ return $null }
  return [uint32]$c
}

$summary = New-Object System.Collections.Generic.List[string]
$gotStack=$false; $gotDeath=$false
for($attempt=1; $attempt -le $MaxAttempts; $attempt++){
  Stop-All
  $runDir = Join-Path $runsDir ("cdb_{0:D2}" -f $attempt)
  New-Item -ItemType Directory -Force -Path $runDir | Out-Null
  $cdbLog = Join-Path $runDir 'cdb.log'
  $cmdFile = Join-Path $runDir 'cdb_cmds.txt'
  $liveDump = (Join-Path $dumpDir ("t05_k32exit_{0:D2}.dmp" -f $attempt)).Replace('\','/')
  $hProc=[IntPtr]::Zero; $cdbProc=$null; $pidNative=0
  $rec=[ordered]@{Attempt=$attempt;PID=$null;Cancel=$false;SentB=$false;Alive=$true;ExitHex=$null;Hit='NONE';Stack=$false;Err=$null;Timeline=@()}
  try {
    @(
      ".logopen $cdbLog"
      '.sympath srv*'
      '.reload /f ntdll.dll'
      '.reload /f kernel32.dll'
      ("bp kernel32!ExitProcess `".echo ===HIT_K32_EXITPROCESS===; r rcx; kL 80; lm m RawrXD*; .dump /ma $liveDump; .logclose; qd`"")
      ("bp ntdll!RtlExitUserProcess `".echo ===HIT_RTL_EXITUSERPROCESS===; r rcx; kL 80; lm m RawrXD*; .dump /ma $liveDump; .logclose; qd`"")
      ("bp ucrtbase!exit `".echo ===HIT_UCRT_EXIT===; r rcx; kL 80; lm m RawrXD*; .dump /ma $liveDump; .logclose; qd`"")
      'sxd eh'
      'sxi ibp'
      'bl'
      'g'
    ) | Set-Content $cmdFile -Encoding ASCII

    $p = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
    $pidNative=$p.Id; $rec.PID=$pidNative
    $rec.Timeline += "SPAWNED $pidNative"
    Start-Sleep -Milliseconds 900
    if(-not (Get-Process -Id $pidNative -EA SilentlyContinue)){ throw 'EARLY_EXIT' }
    $cdbProc = Start-Process -FilePath $cdb -ArgumentList @('-p',"$pidNative",'-cf',$cmdFile) -PassThru -WindowStyle Minimized
    Start-Sleep 3
    $hProc = [RawrXD_T05ExitCap]::OpenProcess(0x1000 -bor 0x100000, $false, $pidNative)

    $proc = Get-Process -Id $pidNative -EA Stop
    $until=[DateTime]::UtcNow.AddSeconds(90)
    do {
      $proc.Refresh()
      if($proc.MainWindowHandle -ne 0 -and [RawrXD_T05ExitCap]::FindId($proc.MainWindowHandle,1204) -ne [IntPtr]::Zero){ break }
      if($null -ne (Get-Exit $hProc)){ throw 'EXIT_WINDOW_WAIT' }
      Start-Sleep -Milliseconds 300
    } while([DateTime]::UtcNow -lt $until)
    if($proc.MainWindowHandle -eq 0){ throw 'NO_MAIN' }
    $main=$proc.MainWindowHandle
    $combo=[RawrXD_T05ExitCap]::FindId($main,1206)
    $input=[RawrXD_T05ExitCap]::FindId($main,1202)
    $send=[RawrXD_T05ExitCap]::FindId($main,1204)
    $rows=@(); $ok=$false
    $mu=[DateTime]::UtcNow.AddSeconds(120)
    while([DateTime]::UtcNow -lt $mu){
      if($null -ne (Get-Exit $hProc)){ throw 'EXIT_MODEL_WAIT' }
      $rows=@([RawrXD_T05ExitCap]::ComboItems($combo))
      foreach($r in $rows){ if($r -like '*gemma3:4b*'){ $ok=$true; break } }
      if($ok){ break }
      Start-Sleep -Milliseconds 500
    }
    if(-not $ok){ throw 'NO_GEMMA' }
    $pick=-1; $model=''
    foreach($pref in @('gemma3:4b','qwen2.5-coder:1.5b-base','nemotron-3-nano:4b')){
      for($i=0;$i -lt $rows.Count;$i++){ if($rows[$i] -like "*$pref*"){ $pick=$i; $model=$rows[$i]; break } }
      if($pick -ge 0){ break }
    }
    [RawrXD_T05ExitCap]::SelectComboIndex($main,$combo,$pick,1206)
    Start-Sleep -Milliseconds 800
    [void][RawrXD_T05ExitCap]::SetEditWmOnly($input,'Generate a very long detailed response about C++ build systems. Continue for many paragraphs and do not stop early.')
    [RawrXD_T05ExitCap]::ClickChild($send)
    $rec.Timeline += 'REQUEST_A_SENT'
    $stopOk=$false
    for($i=0;$i -lt 90;$i++){
      Start-Sleep -Milliseconds 500
      if($null -ne (Get-Exit $hProc)){ throw 'EXIT_REQUEST_A' }
      $stop=[RawrXD_T05ExitCap]::FindId($main,1210)
      if($stop -ne [IntPtr]::Zero -and [RawrXD_T05ExitCap]::IsWindowEnabled($stop)){ $stopOk=$true; break }
    }
    if(-not $stopOk){ throw 'STOP_NEVER' }
    [RawrXD_T05ExitCap]::ClickChild([RawrXD_T05ExitCap]::FindId($main,1210))
    $rec.Cancel=$true; $rec.Timeline += 'CANCEL'
    Start-Sleep 3
    $input=[RawrXD_T05ExitCap]::FindId($main,1202)
    $send=[RawrXD_T05ExitCap]::FindId($main,1204)
    if([RawrXD_T05ExitCap]::SetEditWmOnly($input,'Reply exactly: RAWRXD_CANCEL_RECOVERY_OK') -le 0){ throw 'SET_TEXT_FAIL' }
    [RawrXD_T05ExitCap]::ClickChild($send)
    $rec.SentB=$true; $rec.Timeline += 'REQUEST_B_SENT'

    $hitPat='^===HIT_(K32_EXITPROCESS|RTL_EXITUSERPROCESS|UCRT_EXIT)===$'
    for($i=0;$i -lt 90;$i++){
      Start-Sleep -Milliseconds 500
      if((Test-Path $cdbLog) -and (Select-String -Path $cdbLog -Pattern $hitPat -Quiet)){ $rec.Timeline += 'CDB_HIT'; break }
      $ec=Get-Exit $hProc
      if($null -ne $ec){
        $rec.Alive=$false
        $rec.ExitHex=('0x{0:X8}' -f [uint32]$ec)
        $rec.Err='EXIT_REQUEST_B'
        $rec.Timeline += "EXIT $($rec.ExitHex)"
        break
      }
      if(-not (Get-Process -Id $pidNative -EA SilentlyContinue)){
        $ec2=Get-Exit $hProc; $rec.Alive=$false
        if($null -ne $ec2){ $rec.ExitHex=('0x{0:X8}' -f [uint32]$ec2) }
        $rec.Err='GONE'; break
      }
    }
  } catch {
    $rec.Err=$_.Exception.Message
    $ec=Get-Exit $hProc
    if($null -ne $ec){ $rec.Alive=$false; $rec.ExitHex=('0x{0:X8}' -f [uint32]$ec) }
    else { try{ $null=Get-Process -Id $pidNative -EA Stop } catch { $rec.Alive=$false } }
  }

  $cdbText=''; if(Test-Path $cdbLog){ $cdbText=Get-Content $cdbLog -Raw -EA SilentlyContinue }
  if($cdbText -match '(?m)^===HIT_K32_EXITPROCESS===$'){ $rec.Hit='K32_EXITPROCESS' }
  elseif($cdbText -match '(?m)^===HIT_RTL_EXITUSERPROCESS===$'){ $rec.Hit='RTL_EXITUSERPROCESS' }
  elseif($cdbText -match '(?m)^===HIT_UCRT_EXIT===$'){ $rec.Hit='UCRT_EXIT' }
  if($rec.Hit -ne 'NONE' -and $cdbText -match '(?ms)^===HIT_.*?===\s*$.*?(?:Child-SP|RetAddr)'){ $rec.Stack=$true; $gotStack=$true }
  if($rec.ExitHex -eq '0xFFFFFFFF' -and $rec.SentB){ $gotDeath=$true }

  $rec | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $runDir 'receipt.json') -Encoding UTF8
  $line=("cdb att={0:D2} pid={1} alive={2} sent={3} exit={4} hit={5} stack={6} err={7}" -f $attempt,$rec.PID,$rec.Alive,$rec.SentB,$rec.ExitHex,$rec.Hit,$rec.Stack,$rec.Err)
  $line | Tee-Object -FilePath (Join-Path $runDir 'status.txt') | Out-Host
  $summary.Add($line)

  if($rec.Alive -and $pidNative -gt 0){ Stop-Process -Id $pidNative -Force -EA SilentlyContinue }
  if($cdbProc -and -not $cdbProc.HasExited){ Stop-Process -Id $cdbProc.Id -Force -EA SilentlyContinue }
  if($hProc -ne [IntPtr]::Zero){ [void][RawrXD_T05ExitCap]::CloseHandle($hProc) }
  if($gotStack){ break }
  if($gotDeath -and $attempt -ge 5){ break }
}

$sumPath=Join-Path $base 'CAPTURE_LOOP_cdb_attach.txt'
@("ASOF_UTC=$([DateTime]::UtcNow.ToString('o'))","GOT_STACK=$gotStack","GOT_DEATH_MINUS1=$gotDeath","PROMOTE=0","")+$summary | Set-Content $sumPath -Encoding UTF8
"DONE cdb gotStack=$gotStack gotDeath=$gotDeath summary=$sumPath"
if($gotStack){ exit 0 }
if($gotDeath){ exit 3 }
exit 2
