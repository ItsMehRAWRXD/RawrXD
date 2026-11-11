param(
  [int]$MaxAttempts = 24,
  [ValidateSet('none','procdump','procdump_wait')][string]$DumpMode = 'none',
  [string]$RunPrefix = 'cap'
)
$ErrorActionPreference = 'Continue'
$base = 'F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006\T05_REQUEST_B_FAULTING_STACK_001'
$exe = 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$sha = '0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E'
$procdump = 'F:\rawrxd\scripts\procdump_tools\procdump64.exe'
$cdb = 'C:\Users\Garrett\AppData\Local\Microsoft\WindowsApps\cdbX64.exe'
$dumpDir = Join-Path $base 'dumps'
$crashDumps = Join-Path $env:LOCALAPPDATA 'CrashDumps'
New-Item -ItemType Directory -Force -Path $dumpDir,(Join-Path $base 'runs') | Out-Null

$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
if ($hash -ne $sha) { throw "SHA_MISMATCH actual=$hash" }

# Keep LocalDumps armed (DumpType=2 full).
$ldKey = 'HKCU:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\RawrXD-Win32IDE-Native.exe'
New-Item -Path $ldKey -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpFolder -Value $dumpDir -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpCount -Value 10 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null

if (-not ('RawrXD_T05ExitCap' -as [type])) {
  Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class RawrXD_T05ExitCap {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool b, int p);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr h, out uint c);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
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
  Get-Process -Name 'procdump*' -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -notmatch 'cdb' } |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

function Get-ExitFromHandle([IntPtr]$h) {
  if ($h -eq [IntPtr]::Zero) { return $null }
  [uint32]$code = 0
  if (-not [RawrXD_T05ExitCap]::GetExitCodeProcess($h, [ref]$code)) { return $null }
  if ($code -eq [RawrXD_T05ExitCap]::STILL_ACTIVE) { return $null }
  return [uint32]$code
}

function Set-ExitFields($receipt, [uint32]$code) {
  # Unchecked uint32->int32 so 0xFFFFFFFF becomes -1, not a cast exception.
  $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$code), 0)
  $receipt.ExitCodeSigned = $signed
  $receipt.ExitCodeHex = ('0x{0:X8}' -f [uint32]$code)
  $receipt.ExitCodeCaptured = $true
}

function List-NewDumps([datetime]$since, [string]$dir) {
  if (-not (Test-Path $dir)) { return @() }
  @(Get-ChildItem $dir -Filter '*.dmp' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since })
}

$marker = 'RAWRXD_CANCEL_RECOVERY_OK'
$hitExit = $false
$hitDump = $false
$firstExitAttempt = 0
$summary = New-Object System.Collections.Generic.List[string]

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
  Stop-AllNative
  $runDir = Join-Path $base ("runs\{0}_{1:D2}" -f $RunPrefix, $attempt)
  New-Item -ItemType Directory -Force -Path $runDir | Out-Null
  $since = Get-Date
  $hProc = [IntPtr]::Zero
  $pdProc = $null
  $pidNative = 0

  $receipt = [ordered]@{
    Gate='T05_EXITCODE_CAPTURE'; Attempt=$attempt; DumpMode=$DumpMode
    CandidateSHA256=$sha; PID=$null; Model=$null
    CancelObserved=$false; SecondRequestSent=$false; SecondRequestRecovered=$false
    ProcessAlive=$false; StopFeedbackObserved=$false; MarkerExact=$false
    TranscriptDelta=$null; Error=$null
    ExitCodeSigned=$null; ExitCodeHex=$null; ExitCodeCaptured=$false
    DeathClass=$null; DumpPaths=@(); ProcdumpLog=$null
    Timeline=@()
  }

  try {
    $p = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
    $pidNative = $p.Id
    $receipt.PID = $pidNative
    $receipt.Timeline += ("{0:o} SPAWNED pid={1}" -f [DateTime]::UtcNow, $pidNative)

    $access = [RawrXD_T05ExitCap]::PROCESS_QUERY_LIMITED_INFORMATION -bor [RawrXD_T05ExitCap]::SYNCHRONIZE
    $hProc = [RawrXD_T05ExitCap]::OpenProcess($access, $false, $pidNative)
    if ($hProc -eq [IntPtr]::Zero) { throw "OpenProcess_FAILED err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }

    if ($DumpMode -eq 'procdump' -or $DumpMode -eq 'procdump_wait') {
      $pdOut = Join-Path $runDir ("procdump_pid{0}.dmp" -f $pidNative)
      $pdLog = Join-Path $runDir 'procdump.log'
      # -e unhandled exception, -t on terminate, -ma full. No interactive cdb.
      $pdArgs = @('-accepteula','-ma','-e','-t','-n','3',"$pidNative",$pdOut)
      $pdProc = Start-Process -FilePath $procdump -ArgumentList $pdArgs -PassThru -RedirectStandardOutput $pdLog -WindowStyle Hidden
      $receipt.ProcdumpLog = $pdLog
      $receipt.Timeline += ("{0:o} PROCDUMP_ATTACHED pdPid={1}" -f [DateTime]::UtcNow, $pdProc.Id)
      Start-Sleep -Milliseconds 400
    }

    Start-Sleep -Milliseconds 800
    if (-not (Get-Process -Id $pidNative -ErrorAction SilentlyContinue)) {
      $ec = Get-ExitFromHandle $hProc
      $receipt.ProcessAlive = $false
      $receipt.Error = 'EARLY_EXIT_BEFORE_UI'
      if ($null -ne $ec) { Set-ExitFields $receipt $ec }
      throw 'EARLY_EXIT_BEFORE_UI'
    }

    $proc = Get-Process -Id $pidNative -ErrorAction Stop
    $until = [DateTime]::UtcNow.AddSeconds(90)
    do {
      $proc.Refresh()
      if ($proc.MainWindowHandle -ne [IntPtr]::Zero) {
        $probe = [RawrXD_T05ExitCap]::FindId($proc.MainWindowHandle, 1204)
        if ($probe -ne [IntPtr]::Zero) { break }
      }
      $ecEarly = Get-ExitFromHandle $hProc
      if ($null -ne $ecEarly) {
        $receipt.ProcessAlive = $false
        Set-ExitFields $receipt $ecEarly
        throw 'EXIT_DURING_WINDOW_WAIT'
      }
      Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $until)
    if ($proc.MainWindowHandle -eq [IntPtr]::Zero) { throw 'NO_MAIN_WINDOW' }
    $main = $proc.MainWindowHandle
    $combo = [RawrXD_T05ExitCap]::FindId($main, 1206)
    $inputHwnd = [RawrXD_T05ExitCap]::FindId($main, 1202)
    $outputHwnd = [RawrXD_T05ExitCap]::FindId($main, 1203)
    $sendHwnd = [RawrXD_T05ExitCap]::FindId($main, 1204)
    if ($combo -eq [IntPtr]::Zero -or $inputHwnd -eq [IntPtr]::Zero -or $sendHwnd -eq [IntPtr]::Zero) { throw 'CONTROLS_MISSING' }

    $rows = @(); $hasGemma = $false
    $modelUntil = [DateTime]::UtcNow.AddSeconds(120)
    while ([DateTime]::UtcNow -lt $modelUntil) {
      $ecM = Get-ExitFromHandle $hProc
      if ($null -ne $ecM) {
        $receipt.ProcessAlive = $false
        Set-ExitFields $receipt $ecM
        throw 'EXIT_DURING_MODEL_WAIT'
      }
      $null = Get-Process -Id $pidNative -ErrorAction Stop
      $rows = @([RawrXD_T05ExitCap]::ComboItems($combo))
      foreach ($r in $rows) { if ($r -like '*gemma3:4b*') { $hasGemma = $true; break } }
      if ($hasGemma) { break }
      Start-Sleep -Milliseconds 500
    }
    if (-not $hasGemma) { throw 'gemma3:4b not discovered' }
    $pick = -1; $model = ''
    foreach ($pref in @('gemma3:4b','qwen2.5-coder:1.5b-base','nemotron-3-nano:4b','llama3.2','bigdaddyg-productivity-local')) {
      for ($i = 0; $i -lt $rows.Count; $i++) {
        if ($rows[$i] -like "*$pref*") { $pick = $i; $model = $rows[$i]; break }
      }
      if ($pick -ge 0) { break }
    }
    if ($pick -lt 0) { throw 'NO_USABLE_MODEL' }
    [RawrXD_T05ExitCap]::SelectComboIndex($main, $combo, $pick, 1206)
    $receipt.Model = $model
    Start-Sleep -Milliseconds 800

    $promptA = 'Generate a very long detailed response about C++ build systems. Continue for many paragraphs and do not stop early.'
    $len = [RawrXD_T05ExitCap]::SetEditWmOnly($inputHwnd, $promptA)
    if ($len -le 0) { throw 'PROMPT_A_SET_FAILED' }
    [RawrXD_T05ExitCap]::ClickChild($sendHwnd)
    $receipt.Timeline += ("{0:o} REQUEST_A_SENT" -f [DateTime]::UtcNow)

    $stopEnabled = $false
    for ($i = 0; $i -lt 90; $i++) {
      Start-Sleep -Milliseconds 500
      $ecS = Get-ExitFromHandle $hProc
      if ($null -ne $ecS) {
        $receipt.ProcessAlive = $false
        Set-ExitFields $receipt $ecS
        throw 'EXIT_DURING_REQUEST_A'
      }
      $null = Get-Process -Id $pidNative -ErrorAction Stop
      $stopHwnd = [RawrXD_T05ExitCap]::FindId($main, 1210)
      if ($stopHwnd -ne [IntPtr]::Zero -and [RawrXD_T05ExitCap]::IsWindowEnabled($stopHwnd)) { $stopEnabled = $true; break }
    }
    if (-not $stopEnabled) { throw 'STOP_NEVER_ENABLED' }
    [RawrXD_T05ExitCap]::ClickChild($stopHwnd)
    $receipt.CancelObserved = $true
    $receipt.Timeline += ("{0:o} CANCEL_CLICKED" -f [DateTime]::UtcNow)
    Start-Sleep -Seconds 3

    $beforeB = ''
    try { $beforeB = [RawrXD_T05ExitCap]::Text($outputHwnd) } catch { $beforeB = '' }
    if ($beforeB -match '\[stopped\]|generation cancelled') { $receipt.StopFeedbackObserved = $true }

    $bPrompt = "Reply exactly: $marker"
    $inputHwnd = [RawrXD_T05ExitCap]::FindId($main, 1202)
    $sendHwnd = [RawrXD_T05ExitCap]::FindId($main, 1204)
    $outputHwnd = [RawrXD_T05ExitCap]::FindId($main, 1203)
    $blen = [RawrXD_T05ExitCap]::SetEditWmOnly($inputHwnd, $bPrompt)
    if ($blen -le 0) { throw 'SET_TEXT_VERIFICATION_FAILED' }
    [RawrXD_T05ExitCap]::ClickChild($sendHwnd)
    $receipt.SecondRequestSent = $true
    $receipt.Timeline += ("{0:o} REQUEST_B_SENT" -f [DateTime]::UtcNow)

    $seen = $false; $delta = ''
    for ($i = 0; $i -lt 90; $i++) {
      Start-Sleep -Milliseconds 500
      $ecB = Get-ExitFromHandle $hProc
      if ($null -ne $ecB) {
        $receipt.ProcessAlive = $false
        Set-ExitFields $receipt $ecB
        $receipt.Error = 'PROCESS_EXIT_DURING_REQUEST_B'
        $receipt.Timeline += ("{0:o} EXIT_DURING_REQUEST_B code={1}" -f [DateTime]::UtcNow, $receipt.ExitCodeHex)
        break
      }
      try {
        $null = Get-Process -Id $pidNative -ErrorAction Stop
        $receipt.ProcessAlive = $true
        $outputHwnd = [RawrXD_T05ExitCap]::FindId($main, 1203)
        $text = [RawrXD_T05ExitCap]::Text($outputHwnd)
        if ($beforeB.Length -gt 0 -and $text.Length -ge $beforeB.Length) { $delta = $text.Substring($beforeB.Length) } else { $delta = $text }
        if ($delta -match ("(?ms)^AI:.*{0}" -f [regex]::Escape($marker))) { $seen = $true; $receipt.MarkerExact = $true; break }
        if ($text -match '\[stopped\]|generation cancelled') { $receipt.StopFeedbackObserved = $true }
      } catch {
        # Race: process may have exited between GetExitCode and Get-Process.
        $ecRace = Get-ExitFromHandle $hProc
        $receipt.ProcessAlive = $false
        $receipt.Error = $_.Exception.Message
        if ($null -ne $ecRace) { Set-ExitFields $receipt $ecRace }
        $receipt.Timeline += ("{0:o} GETPROCESS_FAIL exitCap={1}" -f [DateTime]::UtcNow, $receipt.ExitCodeHex)
        break
      }
    }
    $receipt.TranscriptDelta = $delta
    $receipt.SecondRequestRecovered = $seen
    if ($receipt.ProcessAlive) {
      $ecFinal = Get-ExitFromHandle $hProc
      if ($null -ne $ecFinal) {
        $receipt.ProcessAlive = $false
        Set-ExitFields $receipt $ecFinal
        if (-not $receipt.Error) { $receipt.Error = 'PROCESS_EXIT_LATE' }
      } else {
        try { $null = Get-Process -Id $pidNative -ErrorAction Stop; $receipt.ProcessAlive = $true } catch {
          $receipt.ProcessAlive = $false
          if (-not $receipt.Error) { $receipt.Error = $_.Exception.Message }
          $ecLate = Get-ExitFromHandle $hProc
          if ($null -ne $ecLate) { Set-ExitFields $receipt $ecLate }
        }
      }
    }
  } catch {
    if (-not $receipt.Error) { $receipt.Error = $_.Exception.Message }
    $ecCatch = Get-ExitFromHandle $hProc
    if ($null -ne $ecCatch) {
      $receipt.ProcessAlive = $false
      Set-ExitFields $receipt $ecCatch
    } else {
      try { $null = Get-Process -Id $pidNative -ErrorAction Stop; $receipt.ProcessAlive = $true } catch { $receipt.ProcessAlive = $false }
    }
  }

  # Wait briefly for WER/procdump artifacts if process died during Request-B.
  if (-not $receipt.ProcessAlive -and $receipt.SecondRequestSent) {
    for ($w = 0; $w -lt 20; $w++) {
      $localNew = List-NewDumps $since $dumpDir
      $crashNew = List-NewDumps $since $crashDumps
      $pdNew = @(Get-ChildItem $runDir -Filter '*.dmp' -ErrorAction SilentlyContinue)
      if ($localNew.Count -gt 0 -or $crashNew.Count -gt 0 -or $pdNew.Count -gt 0) { break }
      if ($pdProc -and $pdProc.HasExited) { Start-Sleep -Seconds 1; break }
      Start-Sleep -Milliseconds 500
    }
  }

  $dumpPaths = @()
  $dumpPaths += @(List-NewDumps $since $dumpDir | ForEach-Object { $_.FullName })
  $dumpPaths += @(List-NewDumps $since $crashDumps | ForEach-Object { $_.FullName })
  $dumpPaths += @(Get-ChildItem $runDir -Filter '*.dmp' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
  $receipt.DumpPaths = @($dumpPaths | Select-Object -Unique)

  if ($receipt.ExitCodeCaptured -and -not $receipt.ProcessAlive) {
    # Heuristic class only — not root cause claim. Use hex string to avoid PS signed -band traps.
    $hx = [string]$receipt.ExitCodeHex
    if ($receipt.DumpPaths.Count -gt 0) {
      $receipt.DeathClass = 'EXCEPTION_OR_DUMPED_TERMINATE'
    } elseif ($hx -eq '0x00000000') {
      $receipt.DeathClass = 'SILENT_EXIT_CODE_0'
    } elseif ($hx -match '^0x[Cc]') {
      $receipt.DeathClass = 'NTSTATUS_EXCEPTION_STYLE_EXITCODE'
    } else {
      $receipt.DeathClass = 'SILENT_EXIT_NONZERO'
    }
  }

  $receipt | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $runDir 'T05.receipt.json') -Encoding UTF8

  $line = ("cap={0:D2} mode={1} pid={2} alive={3} sent={4} recov={5} exitSigned={6} exitHex={7} death={8} dumps={9} err={10}" -f `
    $attempt, $DumpMode, $receipt.PID, $receipt.ProcessAlive, $receipt.SecondRequestSent, $receipt.SecondRequestRecovered, `
    $receipt.ExitCodeSigned, $receipt.ExitCodeHex, $receipt.DeathClass, $receipt.DumpPaths.Count, $receipt.Error)
  $line | Tee-Object -FilePath (Join-Path $runDir 'capture_status.txt') | Out-Host
  $summary.Add($line)

  # Count Request-B window: SecondRequestSent, or cancel observed then death during B text set.
  $requestBWindow = ($receipt.SecondRequestSent -or ($receipt.CancelObserved -and ($receipt.Error -match 'SET_TEXT_VERIFICATION_FAILED|PROCESS_EXIT')))
  if (-not $receipt.ProcessAlive -and $requestBWindow -and $receipt.ExitCodeCaptured) {
    $hitExit = $true
    if ($firstExitAttempt -eq 0) { $firstExitAttempt = $attempt }
    "REQUEST_B_EXIT_HIT attempt=$attempt exitHex=$($receipt.ExitCodeHex) signed=$($receipt.ExitCodeSigned) dumps=$($receipt.DumpPaths.Count) sent=$($receipt.SecondRequestSent)" |
      Set-Content (Join-Path $runDir 'crash_hit.txt') -Encoding UTF8
    if ($receipt.DumpPaths.Count -gt 0) {
      $hitDump = $true
      # Extract faulting stack with cdb -z (postmortem only; does not suppress live exit).
      $dumpPath = $receipt.DumpPaths[0]
      $stackOut = Join-Path $runDir 'cdb_stack.txt'
      $cdbCmd = '.ecxr; .echo ===T05_FAULT_STACK===; kL 50; .echo ===T05_MODULES===; lm m RawrXD*; .echo ===T05_EXR===; .exr -1; q'
      & $cdb -z $dumpPath -c $cdbCmd 2>&1 | Tee-Object -FilePath $stackOut | Out-Null
      break
    }
    # After first ExitCode hit without dump, try a few more then stop (progress vs MISSING ExitCode).
    if (($attempt - $firstExitAttempt) -ge 7) { break }
  }

  # Cleanup live process only if still alive (do not invent ExitCode from Kill).
  if ($receipt.ProcessAlive -and $pidNative -gt 0) {
    Get-Process -Id $pidNative -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  }
  if ($pdProc -and -not $pdProc.HasExited) {
    Stop-Process -Id $pdProc.Id -Force -ErrorAction SilentlyContinue
  }
  if ($hProc -ne [IntPtr]::Zero) { [void][RawrXD_T05ExitCap]::CloseHandle($hProc) }
}

$summaryPath = Join-Path $base ("CAPTURE_LOOP_{0}_{1}.txt" -f $RunPrefix, $DumpMode)
@(
  "ASOF_UTC=$([DateTime]::UtcNow.ToString('o'))"
  "DumpMode=$DumpMode"
  "MaxAttempts=$MaxAttempts"
  "HIT_REQUEST_B_EXIT=$hitExit"
  "HIT_DUMP=$hitDump"
  "PROMOTE=0"
  "CERTIFIED=0"
  ""
) + $summary | Set-Content $summaryPath -Encoding UTF8

"HIT_REQUEST_B_EXIT=$hitExit HIT_DUMP=$hitDump summary=$summaryPath"
if ($hitDump) { exit 0 }
if ($hitExit) { exit 3 }  # exit hit, stack/dump still missing
exit 2
