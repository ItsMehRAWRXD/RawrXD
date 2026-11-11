param(
  [int]$MaxAttempts = 8,
  [ValidateSet('cdb_attach','cdb_launch','none')][string]$Mode = 'cdb_attach'
)
$ErrorActionPreference = 'Continue'
$base = 'F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006\T05_REQUEST_B_EXIT_CALLSITE_001'
$exe = 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$sha = '0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E'
$cdb = 'C:\Users\Garrett\AppData\Local\Microsoft\WindowsApps\cdbX64.exe'
$dumpDir = Join-Path $base 'dumps'
$runsDir = Join-Path $base 'runs'
New-Item -ItemType Directory -Force -Path $dumpDir,$runsDir | Out-Null

$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
if ($hash -ne $sha) { throw "SHA_MISMATCH actual=$hash" }

if (-not ('RawrXD_T05ExitCall' -as [type])) {
  Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class RawrXD_T05ExitCall {
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
  Get-Process -Name 'cdb*','cdbX64*' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

function Get-ExitFromHandle([IntPtr]$h) {
  if ($h -eq [IntPtr]::Zero) { return $null }
  [uint32]$code = 0
  if (-not [RawrXD_T05ExitCall]::GetExitCodeProcess($h, [ref]$code)) { return $null }
  if ($code -eq [RawrXD_T05ExitCall]::STILL_ACTIVE) { return $null }
  return [uint32]$code
}

function Write-CdbCmds([string]$cmdFile, [string]$cdbLog, [string]$liveDump) {
  $dumpFwd = $liveDump.Replace('\','/')
  # Break at ExitProcess entry; dump stack; DO NOT continue (qd after log).
  # Also RtlExitUserProcess (covers CRT/kernel32 thunk). No NtTerminateProcess
  # (child kills false-positive qd). Fallback CRT exits if those never hit.
  @(
    ".logopen $cdbLog"
    '.sympath srv*'
    '.reload /f ntdll.dll'
    '.reload /f kernel32.dll'
    ("bp kernel32!ExitProcess `".echo ===HIT_K32_EXITPROCESS===; r rcx; kL 80; lm m RawrXD*; .dump /ma $dumpFwd; .logclose; qd`"")
    ("bp ntdll!RtlExitUserProcess `".echo ===HIT_RTL_EXITUSERPROCESS===; r rcx; kL 80; lm m RawrXD*; .dump /ma $dumpFwd; .logclose; qd`"")
    ("bp ucrtbase!exit `".echo ===HIT_UCRT_EXIT===; r rcx; kL 80; lm m RawrXD*; .dump /ma $dumpFwd; .logclose; qd`"")
    ("bp ucrtbase!_exit `".echo ===HIT_UCRT__EXIT===; r rcx; kL 80; lm m RawrXD*; .dump /ma $dumpFwd; .logclose; qd`"")
    ("bp ucrtbase!quick_exit `".echo ===HIT_UCRT_QUICKEXIT===; r rcx; kL 80; lm m RawrXD*; .dump /ma $dumpFwd; .logclose; qd`"")
    'sxd eh'
    'sxi ibp'
    'bl'
    'g'
  ) | Set-Content $cmdFile -Encoding ASCII
}

$marker = 'RAWRXD_CANCEL_RECOVERY_OK'
$summary = New-Object System.Collections.Generic.List[string]
$gotHit = $false
$gotDeathMinus1 = $false

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
  Stop-AllNative
  $runDir = Join-Path $runsDir ("{0}_{1:D2}" -f $Mode, $attempt)
  New-Item -ItemType Directory -Force -Path $runDir | Out-Null
  $cdbLog = Join-Path $runDir 'cdb.log'
  $cmdFile = Join-Path $runDir 'cdb_cmds.txt'
  $liveDump = Join-Path $dumpDir ("t05_exit_callsite_{0}_{1:D2}.dmp" -f $Mode, $attempt)
  $statusPath = Join-Path $runDir 'capture_status.txt'
  $receiptPath = Join-Path $runDir 'T05.receipt.json'
  $hProc = [IntPtr]::Zero
  $cdbProc = $null
  $pidNative = 0

  $receipt = [ordered]@{
    Gate='T05_EXIT_CALLSITE'; Attempt=$attempt; Mode=$Mode
    CandidateSHA256=$sha; PID=$null; Model=$null
    CancelObserved=$false; SecondRequestSent=$false
    ProcessAlive=$false; ExitCodeSigned=$null; ExitCodeHex=$null; ExitCodeCaptured=$false
    CdbHitMarker='NONE'; StackGot=$false; DumpPath=$null
    DeathClass=$null; Error=$null; Timeline=@()
  }

  try {
    Write-CdbCmds $cmdFile $cdbLog $liveDump

    if ($Mode -eq 'cdb_launch') {
      # Launch under debugger from start (no continue past ExitProcess hit).
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = $cdb
      $psi.Arguments = "-o `"$exe`" -cf `"$cmdFile`""
      $psi.WorkingDirectory = (Split-Path $exe)
      $psi.UseShellExecute = $false
      $psi.CreateNoWindow = $true
      $cdbProc = [Diagnostics.Process]::Start($psi)
      Start-Sleep -Seconds 4
      $native = Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | Select-Object -First 1
      if (-not $native) { throw 'LAUNCH_UNDER_CDB_NO_NATIVE' }
      $pidNative = $native.Id
    } else {
      $p = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
      $pidNative = $p.Id
      Start-Sleep -Milliseconds 900
      if (-not (Get-Process -Id $pidNative -ErrorAction SilentlyContinue)) { throw 'EARLY_EXIT_BEFORE_UI' }
      if ($Mode -eq 'cdb_attach') {
        # Attach after spawn; set BPs; g — stop at ExitProcess without further g.
        $cdbProc = Start-Process -FilePath $cdb -ArgumentList @('-p',"$pidNative",'-cf',$cmdFile) -PassThru -WindowStyle Minimized
        Start-Sleep -Seconds 3
      }
    }

    $receipt.PID = $pidNative
    $receipt.Timeline += ("{0:o} SPAWNED pid={1} mode={2}" -f [DateTime]::UtcNow, $pidNative, $Mode)
    $access = [RawrXD_T05ExitCall]::PROCESS_QUERY_LIMITED_INFORMATION -bor [RawrXD_T05ExitCall]::SYNCHRONIZE
    $hProc = [RawrXD_T05ExitCall]::OpenProcess($access, $false, $pidNative)
    if ($hProc -eq [IntPtr]::Zero) { throw "OpenProcess_FAILED" }

    $proc = Get-Process -Id $pidNative -ErrorAction Stop
    $until = [DateTime]::UtcNow.AddSeconds(90)
    do {
      $proc.Refresh()
      if ($proc.MainWindowHandle -ne [IntPtr]::Zero) {
        $probe = [RawrXD_T05ExitCall]::FindId($proc.MainWindowHandle, 1204)
        if ($probe -ne [IntPtr]::Zero) { break }
      }
      $ecEarly = Get-ExitFromHandle $hProc
      if ($null -ne $ecEarly) { throw 'EXIT_DURING_WINDOW_WAIT' }
      Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $until)
    if ($proc.MainWindowHandle -eq [IntPtr]::Zero) { throw 'NO_MAIN_WINDOW' }
    $main = $proc.MainWindowHandle
    $combo = [RawrXD_T05ExitCall]::FindId($main, 1206)
    $inputHwnd = [RawrXD_T05ExitCall]::FindId($main, 1202)
    $outputHwnd = [RawrXD_T05ExitCall]::FindId($main, 1203)
    $sendHwnd = [RawrXD_T05ExitCall]::FindId($main, 1204)
    if ($combo -eq [IntPtr]::Zero -or $inputHwnd -eq [IntPtr]::Zero -or $sendHwnd -eq [IntPtr]::Zero) { throw 'CONTROLS_MISSING' }

    $rows = @(); $hasGemma = $false
    $modelUntil = [DateTime]::UtcNow.AddSeconds(120)
    while ([DateTime]::UtcNow -lt $modelUntil) {
      $ecM = Get-ExitFromHandle $hProc
      if ($null -ne $ecM) { throw 'EXIT_DURING_MODEL_WAIT' }
      $rows = @([RawrXD_T05ExitCall]::ComboItems($combo))
      foreach ($r in $rows) { if ($r -like '*gemma3:4b*') { $hasGemma = $true; break } }
      if ($hasGemma) { break }
      Start-Sleep -Milliseconds 500
    }
    if (-not $hasGemma) { throw 'gemma3:4b not discovered' }
    $pick = -1; $model = ''
    foreach ($pref in @('gemma3:4b','qwen2.5-coder:1.5b-base','nemotron-3-nano:4b','llama3.2')) {
      for ($i = 0; $i -lt $rows.Count; $i++) {
        if ($rows[$i] -like "*$pref*") { $pick = $i; $model = $rows[$i]; break }
      }
      if ($pick -ge 0) { break }
    }
    if ($pick -lt 0) { throw 'NO_USABLE_MODEL' }
    [RawrXD_T05ExitCall]::SelectComboIndex($main, $combo, $pick, 1206)
    $receipt.Model = $model
    Start-Sleep -Milliseconds 800

    $promptA = 'Generate a very long detailed response about C++ build systems. Continue for many paragraphs and do not stop early.'
    $len = [RawrXD_T05ExitCall]::SetEditWmOnly($inputHwnd, $promptA)
    if ($len -le 0) { throw 'PROMPT_A_SET_FAILED' }
    [RawrXD_T05ExitCall]::ClickChild($sendHwnd)
    $receipt.Timeline += ("{0:o} REQUEST_A_SENT" -f [DateTime]::UtcNow)

    $stopEnabled = $false
    for ($i = 0; $i -lt 90; $i++) {
      Start-Sleep -Milliseconds 500
      $ecS = Get-ExitFromHandle $hProc
      if ($null -ne $ecS) { throw 'EXIT_DURING_REQUEST_A' }
      $null = Get-Process -Id $pidNative -ErrorAction Stop
      $stopHwnd = [RawrXD_T05ExitCall]::FindId($main, 1210)
      if ($stopHwnd -ne [IntPtr]::Zero -and [RawrXD_T05ExitCall]::IsWindowEnabled($stopHwnd)) { $stopEnabled = $true; break }
    }
    if (-not $stopEnabled) { throw 'STOP_NEVER_ENABLED' }
    [RawrXD_T05ExitCall]::ClickChild($stopHwnd)
    $receipt.CancelObserved = $true
    $receipt.Timeline += ("{0:o} CANCEL_CLICKED" -f [DateTime]::UtcNow)
    Start-Sleep -Seconds 3

    $bPrompt = "Reply exactly: $marker"
    $inputHwnd = [RawrXD_T05ExitCall]::FindId($main, 1202)
    $sendHwnd = [RawrXD_T05ExitCall]::FindId($main, 1204)
    $blen = [RawrXD_T05ExitCall]::SetEditWmOnly($inputHwnd, $bPrompt)
    if ($blen -le 0) { throw 'SET_TEXT_VERIFICATION_FAILED' }
    [RawrXD_T05ExitCall]::ClickChild($sendHwnd)
    $receipt.SecondRequestSent = $true
    $receipt.Timeline += ("{0:o} REQUEST_B_SENT" -f [DateTime]::UtcNow)

    $hitPattern = '^===HIT_(K32_EXITPROCESS|RTL_EXITUSERPROCESS|UCRT_EXIT|UCRT__EXIT|UCRT_QUICKEXIT)===$'
    for ($i = 0; $i -lt 90; $i++) {
      Start-Sleep -Milliseconds 500
      if ((Test-Path $cdbLog) -and (Select-String -Path $cdbLog -Pattern $hitPattern -Quiet)) {
        $receipt.Timeline += ("{0:o} CDB_HIT_SEEN" -f [DateTime]::UtcNow)
        break
      }
      $ecB = Get-ExitFromHandle $hProc
      if ($null -ne $ecB) {
        $receipt.ProcessAlive = $false
        $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$ecB), 0)
        $receipt.ExitCodeSigned = $signed
        $receipt.ExitCodeHex = ('0x{0:X8}' -f [uint32]$ecB)
        $receipt.ExitCodeCaptured = $true
        $receipt.Error = 'PROCESS_EXIT_DURING_REQUEST_B'
        $receipt.Timeline += ("{0:o} EXIT_DURING_REQUEST_B code={1}" -f [DateTime]::UtcNow, $receipt.ExitCodeHex)
        break
      }
      try {
        $null = Get-Process -Id $pidNative -ErrorAction Stop
        $receipt.ProcessAlive = $true
      } catch {
        $ecRace = Get-ExitFromHandle $hProc
        $receipt.ProcessAlive = $false
        if ($null -ne $ecRace) {
          $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$ecRace), 0)
          $receipt.ExitCodeSigned = $signed
          $receipt.ExitCodeHex = ('0x{0:X8}' -f [uint32]$ecRace)
          $receipt.ExitCodeCaptured = $true
        }
        $receipt.Error = 'GETPROCESS_FAIL'
        break
      }
    }
  } catch {
    if (-not $receipt.Error) { $receipt.Error = $_.Exception.Message }
    $ecCatch = Get-ExitFromHandle $hProc
    if ($null -ne $ecCatch) {
      $receipt.ProcessAlive = $false
      $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$ecCatch), 0)
      $receipt.ExitCodeSigned = $signed
      $receipt.ExitCodeHex = ('0x{0:X8}' -f [uint32]$ecCatch)
      $receipt.ExitCodeCaptured = $true
    } else {
      try { $null = Get-Process -Id $pidNative -ErrorAction Stop; $receipt.ProcessAlive = $true } catch { $receipt.ProcessAlive = $false }
    }
  }

  # Parse cdb hit / stack
  $cdbText = ''
  if (Test-Path $cdbLog) { $cdbText = Get-Content $cdbLog -Raw -ErrorAction SilentlyContinue }
  $markerHit = 'NONE'
  if ($cdbText -match '(?m)^===HIT_K32_EXITPROCESS===$') { $markerHit = 'K32_EXITPROCESS' }
  elseif ($cdbText -match '(?m)^===HIT_RTL_EXITUSERPROCESS===$') { $markerHit = 'RTL_EXITUSERPROCESS' }
  elseif ($cdbText -match '(?m)^===HIT_UCRT_EXIT===$') { $markerHit = 'UCRT_EXIT' }
  elseif ($cdbText -match '(?m)^===HIT_UCRT__EXIT===$') { $markerHit = 'UCRT__EXIT' }
  elseif ($cdbText -match '(?m)^===HIT_UCRT_QUICKEXIT===$') { $markerHit = 'UCRT_QUICKEXIT' }
  $receipt.CdbHitMarker = $markerHit
  $stackGot = $false
  if ($markerHit -ne 'NONE' -and $cdbText -match '(?ms)^===HIT_.*?===\s*$.*?(?:Child-SP|RetAddr)') { $stackGot = $true }
  $receipt.StackGot = $stackGot
  if (Test-Path $liveDump) { $receipt.DumpPath = $liveDump }

  if ($receipt.ExitCodeCaptured -and -not $receipt.ProcessAlive) {
    if ($markerHit -ne 'NONE') { $receipt.DeathClass = 'SILENT_EXIT_VIA_' + $markerHit }
    elseif ($Mode -eq 'none') { $receipt.DeathClass = 'SILENT_EXIT_NONZERO_NO_DEBUGGER' }
    else { $receipt.DeathClass = 'SILENT_EXIT_NO_EXITPROCESS_BP' }
  } elseif ($markerHit -ne 'NONE') {
    $receipt.DeathClass = 'BP_HIT_' + $markerHit
  } elseif ($receipt.ProcessAlive) {
    $receipt.DeathClass = 'NO_DEATH_IN_WINDOW'
  }

  $receipt | ConvertTo-Json -Depth 8 | Set-Content $receiptPath -Encoding UTF8
  $line = ("mode={0} att={1:D2} pid={2} alive={3} sent={4} exitHex={5} hit={6} stack={7} err={8}" -f `
    $Mode, $attempt, $receipt.PID, $receipt.ProcessAlive, $receipt.SecondRequestSent, `
    $receipt.ExitCodeHex, $receipt.CdbHitMarker, $receipt.StackGot, $receipt.Error)
  $line | Tee-Object -FilePath $statusPath | Out-Host
  $summary.Add($line)

  if ($stackGot) { $gotHit = $true }
  if ($receipt.ExitCodeHex -eq '0xFFFFFFFF' -and $receipt.SecondRequestSent) { $gotDeathMinus1 = $true }

  # Do not Stop-Process live victims after Request-B death window — preserves ExitCode evidence.
  if ($receipt.ProcessAlive -and $pidNative -gt 0) {
    Get-Process -Id $pidNative -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  }
  if ($cdbProc -and -not $cdbProc.HasExited) {
    Stop-Process -Id $cdbProc.Id -Force -ErrorAction SilentlyContinue
  }
  if ($hProc -ne [IntPtr]::Zero) { [void][RawrXD_T05ExitCall]::CloseHandle($hProc) }

  if ($gotHit) { break }
  # Progress: Request-B -1 death without BP is still evidence; keep a few attempts.
  if ($gotDeathMinus1 -and $Mode -ne 'none' -and $attempt -ge 4) { break }
}

$summaryPath = Join-Path $base ("CAPTURE_LOOP_{0}.txt" -f $Mode)
@(
  "ASOF_UTC=$([DateTime]::UtcNow.ToString('o'))"
  "Mode=$Mode"
  "MaxAttempts=$MaxAttempts"
  "GOT_EXITPROCESS_STACK=$gotHit"
  "GOT_REQUEST_B_EXIT_MINUS1=$gotDeathMinus1"
  "PROMOTE=0"
  "CERTIFIED=0"
  ""
) + $summary | Set-Content $summaryPath -Encoding UTF8
"DONE summary=$summaryPath gotStack=$gotHit gotDeathMinus1=$gotDeathMinus1"
if ($gotHit) { exit 0 }
if ($gotDeathMinus1) { exit 3 }
exit 2
