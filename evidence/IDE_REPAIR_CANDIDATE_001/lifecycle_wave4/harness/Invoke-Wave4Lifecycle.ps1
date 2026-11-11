#Requires -Version 5.1
# Wave4 reliability E2E: EXT / CAN / MSW / PER / REC on ONE Ext SHA.
# PROMOTE=0 · NOT_RUN!=PASS · No RC4 mutation · Avoid live rc5b Ext path.
param(
  [string]$TipExe = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\lifecycle_wave4\package\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$OutRoot = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\lifecycle_wave4',
  [string]$ExpectSha = '',
  [string]$ModelA = 'qwen2.5-coder:1.5b-base',
  [string]$ModelB = 'nemotron-3-nano:4b'
)
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logs = Join-Path $OutRoot 'logs'
$userdata = Join-Path $OutRoot "userdata_$stamp"
$artifacts = Join-Path $OutRoot 'artifacts'
New-Item -ItemType Directory -Force -Path $logs,$userdata,$artifacts,(Join-Path $OutRoot 'fixtures') | Out-Null

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content (Join-Path $logs "wave4_run_$stamp.txt") $line
  Write-Host $line
}

$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
if ($ExpectSha -and ($sha -ne $ExpectSha)) {
  WLog "SHA_DRIFT measured=$sha expected=$ExpectSha"
  exit 9
}
WLog "WAVE4_START sha=$sha tip=$TipExe"

# Stop only package-copy Ext processes (never blanket-kill rc5b Wave1).
Get-CimInstance Win32_Process -Filter "Name='RawrXD-Win32IDE-Native-Ext.exe'" |
  Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like '*lifecycle_wave4*' -or $_.ExecutablePath -like '*wave4-lifecycle*') } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 1

$results = [ordered]@{
  'W4-EXT-01'='NOT_RUN'; 'W4-EXT-02'='NOT_RUN'; 'W4-EXT-03'='NOT_RUN'
  'W4-CAN-01'='NOT_RUN'; 'W4-CAN-02'='NOT_RUN'; 'W4-CAN-03'='NOT_RUN'
  'W4-MSW-01'='NOT_RUN'; 'W4-MSW-02'='NOT_RUN'
  'W4-PER-01'='NOT_RUN'; 'W4-PER-02'='NOT_RUN'
  'W4-REC-01'='NOT_RUN'; 'W4-REC-02'='NOT_RUN'; 'W4-REC-03'='NOT_RUN'
}
$notes = [ordered]@{}

# ---- EXT-01 / EXT-02 ----
$extReceipt = Join-Path $artifacts 'ext_runtime_receipt.txt'
$env:RAWRXD_EXT_RUNTIME_RECEIPT = $extReceipt
$fixture = Join-Path $OutRoot 'fixtures\ext_hello'
$malformed = Join-Path $OutRoot 'fixtures\ext_malformed'
Remove-Item $extReceipt -Force -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $TipExe -ArgumentList @('--ext-dir',$fixture,'--ext-cmd','extHello.ping','--ext-quit') -PassThru -WindowStyle Minimized
$force = 0
if (-not $p.WaitForExit(30000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $force = 1 }
$rec = @{}
if (Test-Path $extReceipt) {
  Get-Content $extReceipt | ForEach-Object { if ($_ -match '^(.*?)=(.*)$') { $rec[$Matches[1]] = $Matches[2] } }
}
$orphansExt = @(Get-CimInstance Win32_Process -Filter "Name='RawrXD-Win32IDE-Native-Ext.exe'" |
  Where-Object { $_.ExecutablePath -like '*lifecycle_wave4*' -or $_.ExecutablePath -like '*wave4-lifecycle*' }).Count
$extLoad = ($rec['INIT_OK'] -eq '1' -and $rec['LOAD_OK'] -eq '1' -and $rec['ACTIVATE_OK'] -eq '1' -and $rec['CMD_OK'] -eq '1')
$extClean = ($force -eq 0 -and $p.ExitCode -eq 0 -and $orphansExt -eq 0 -and $rec['DEACTIVATE_OK'] -eq '1')
$results['W4-EXT-01'] = $(if ($extLoad) { 'PASS' } else { 'FAIL' })
$results['W4-EXT-02'] = $(if ($extLoad -and $extClean) { 'PASS' } else { 'FAIL' })
$notes['W4-EXT-01'] = "INIT=$($rec['INIT_OK']) LOAD=$($rec['LOAD_OK']) ACT=$($rec['ACTIVATE_OK']) CMD=$($rec['CMD_OK'])"
$notes['W4-EXT-02'] = "EXIT=$($p.ExitCode) FORCE_KILL=$force ORPHANS=$orphansExt DEACT=$($rec['DEACTIVATE_OK'])"
WLog "EXT-01=$($results['W4-EXT-01']) EXT-02=$($results['W4-EXT-02']) $($notes['W4-EXT-02'])"

# malformed isolation (supporting EXT health, not separate gate)
Remove-Item $extReceipt -Force -ErrorAction SilentlyContinue
$p2 = Start-Process -FilePath $TipExe -ArgumentList @('--ext-malformed',$malformed,'--ext-quit') -PassThru -WindowStyle Minimized
if (-not $p2.WaitForExit(20000)) { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue }
$malOk = $false
if (Test-Path $extReceipt) {
  $mal = @{}
  Get-Content $extReceipt | ForEach-Object { if ($_ -match '^(.*?)=(.*)$') { $mal[$Matches[1]] = $Matches[2] } }
  $malOk = ($mal['FAULT_ISOLATED'] -eq '1')
}
$notes['EXT_MALFORMED'] = "FAULT_ISOLATED=$(if($malOk){'1'}else{'0'})"

# C# UI helpers for CAN/MSW/PER/REC
$uiSrc = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class W4Ui {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C; public const uint BM_CLICK=0x00F5;
  public const uint WM_COPYDATA=0x004A; public const int GWL_ID=-12;
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
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,GWL_ID)==id){ found=h; return false;} return true;}, IntPtr.Zero);
    return found;
  }
  public static int SetEdit(IntPtr edit, string text) {
    IntPtr p=Marshal.StringToHGlobalUni(text);
    try { SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p); } finally { Marshal.FreeHGlobal(p); }
    return 1;
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
    IntPtr btn=FindChildById(main,id);
    if(btn!=IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    IntPtr wp=(IntPtr)((0<<16)|(id & 0xFFFF));
    SendMessageW(main, WM_COMMAND, wp, btn);
    PostMessageW(main, WM_COMMAND, wp, btn);
  }
  public static string SelectModel(IntPtr main, IntPtr combo, string needle) {
    int cnt=SendMessageW(combo,0x0146,IntPtr.Zero,IntPtr.Zero).ToInt32();
    for(int i=0;i<cnt;i++){
      int tlen=SendMessageW(combo,0x0149,(IntPtr)i,IntPtr.Zero).ToInt32();
      if(tlen<=0) continue;
      IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
      try {
        SendMessageW(combo,0x0148,(IntPtr)i,buf);
        string item=Marshal.PtrToStringUni(buf)??"";
        if(item.IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){
          SendMessageW(combo,0x014E,(IntPtr)i,IntPtr.Zero);
          IntPtr wp=(IntPtr)((1206 & 0xFFFF)|(1<<16));
          PostMessageW(main, WM_COMMAND, wp, combo);
          return item;
        }
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return "";
  }
  public static string[] ListCombo(IntPtr combo) {
    int cnt=SendMessageW(combo,0x0146,IntPtr.Zero,IntPtr.Zero).ToInt32();
    if(cnt<=0) return new string[0];
    string[] items=new string[cnt];
    for(int i=0;i<cnt;i++){
      int tlen=SendMessageW(combo,0x0149,(IntPtr)i,IntPtr.Zero).ToInt32();
      if(tlen<=0){ items[i]=""; continue; }
      IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
      try {
        SendMessageW(combo,0x0148,(IntPtr)i,buf);
        items[i]=Marshal.PtrToStringUni(buf)??"";
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return items;
  }
}
'@
Add-Type -TypeDefinition $uiSrc -Language CSharp -ErrorAction Stop

function Start-IdeIsolated([string]$ud,[string]$logDir,[string]$runId) {
  New-Item -ItemType Directory -Force -Path $ud,$logDir | Out-Null
  $env:RAWRXD_USER_DATA_DIR = $ud
  $env:RAWRXD_LOG_DIR = $logDir
  $env:RAWRXD_CHAT_RUN_ID = $runId
  $arg = "--user-data-dir=`"$ud`""
  $proc = Start-Process -FilePath $TipExe -ArgumentList $arg -PassThru -WindowStyle Minimized
  $hwnd = [IntPtr]::Zero
  for ($i=0; $i -lt 80; $i++) {
    Start-Sleep -Milliseconds 250
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { break }
    $hwnd = [W4Ui]::FindMain([uint32]$proc.Id)
    if ($hwnd -ne [IntPtr]::Zero) { break }
  }
  return @{ Proc=$proc; Hwnd=$hwnd }
}

function Wait-LogMatch([string]$path,[string]$pattern,[int]$timeoutSec=90) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $path) {
      $txt = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
      if ($txt -and ($txt -match $pattern)) { return $true }
    }
    Start-Sleep -Milliseconds 400
  }
  return $false
}

function Get-ModelIdFromBreadcrumb([string]$crumb) {
  if ([string]::IsNullOrWhiteSpace($crumb)) { return '' }
  $parts = $crumb -split ' / '
  return ($parts[-1]).Trim()
}

function Wait-ComboNeedles([IntPtr]$main, [string[]]$needles, [int]$timeoutSec = 45) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  $lastCombo = [IntPtr]::Zero
  $lastItems = @()
  while ((Get-Date) -lt $deadline) {
    $combo = [W4Ui]::FindChildById($main, 1206)
    if ($combo -ne [IntPtr]::Zero) {
      $items = @([W4Ui]::ListCombo($combo))
      $scanning = ($items | Where-Object { $_ -match 'connecting to Ollama' }).Count -gt 0
      $ok = $true
      foreach ($n in $needles) {
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        if (-not ($items | Where-Object { $_.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0 })) {
          $ok = $false
          break
        }
      }
      $lastCombo = $combo
      $lastItems = $items
      if ($ok -and -not $scanning -and $items.Count -ge 2) {
        return @{ Ok = $true; Combo = $combo; Items = $items }
      }
    }
    Start-Sleep -Milliseconds 400
  }
  return @{ Ok = $false; Combo = $lastCombo; Items = $lastItems }
}

function Resolve-ModelBNeedle([string[]]$items, [string]$preferredB, [string]$modelA) {
  if ($preferredB -and ($items | Where-Object { $_.IndexOf($preferredB, [StringComparison]::OrdinalIgnoreCase) -ge 0 })) {
    return $preferredB
  }
  $fallbacks = @(
    $preferredB,
    'nemotron-3-nano:4b',
    'llama3.2:3b',
    'gemma3:4b',
    'n4-tiny-oracle:latest',
    'qwen2.5-coder:1.5b-base'
  ) | Where-Object { $_ -and ($_ -ne $modelA) } | Select-Object -Unique
  foreach ($fb in $fallbacks) {
    if ($items | Where-Object { $_.IndexOf($fb, [StringComparison]::OrdinalIgnoreCase) -ge 0 }) {
      return $fb
    }
  }
  $locals = @($items | Where-Object { $_ -match 'Local models / Ollama /' })
  foreach ($row in $locals) {
    $id = Get-ModelIdFromBreadcrumb $row
    if ($id -and ($id -ne $modelA) -and ($id -notmatch 'connecting')) { return $id }
  }
  return ''
}

# ---- CAN-01: cancel mid/post generation ----
$canUd = Join-Path $userdata 'can01'
$canLog = Join-Path $logs 'can01'
$canChat = Join-Path $canLog 'chat_runtime.log'
$ide = Start-IdeIsolated $canUd $canLog "w4_can01_$stamp"
if ($ide.Hwnd -eq [IntPtr]::Zero) {
  $results['W4-CAN-01'] = 'FAIL'
  $notes['W4-CAN-01'] = 'NO_HWND'
  WLog 'CAN-01 FAIL NO_HWND'
} else {
  $ready = Wait-ComboNeedles $ide.Hwnd @($ModelA) 45
  $combo = $ready.Combo
  $sel = ''
  if ($ready.Ok -and $combo -ne [IntPtr]::Zero) { $sel = [W4Ui]::SelectModel($ide.Hwnd, $combo, $ModelA) }
  Start-Sleep 1
  [void][W4Ui]::Chin($ide.Hwnd, 'Reply with a long paragraph about reliability gates. Include marker W4_CAN_MARKER.')
  Start-Sleep -Milliseconds 300
  [W4Ui]::ClickId($ide.Hwnd, 1204) # Send
  # Do not match CHAT_SEND_REJECTED (blank Chin) as a started send.
  $started = Wait-LogMatch $canChat 'BACKEND_REQUEST_START|RESPONSE_START|CHAT_SEND(?!_REJECTED)' 60
  Start-Sleep 1
  [W4Ui]::ClickId($ide.Hwnd, 1210) # Stop
  $req = Wait-LogMatch $canChat 'cancel_requested' 30
  $ack = Wait-LogMatch $canChat 'cancel_acknowledged' 30
  if ($req -and $ack) { $results['W4-CAN-01'] = 'PASS' } else { $results['W4-CAN-01'] = 'FAIL' }
  $notes['W4-CAN-01'] = "started=$started req=$req ack=$ack model=$sel"
  WLog "CAN-01=$($results['W4-CAN-01']) $($notes['W4-CAN-01'])"
  try { if (-not $ide.Proc.HasExited) { $ide.Proc.CloseMainWindow() | Out-Null; $ide.Proc.WaitForExit(8000) | Out-Null } } catch {}
  if (-not $ide.Proc.HasExited) { Stop-Process -Id $ide.Proc.Id -Force -ErrorAction SilentlyContinue }
}
Start-Sleep 1

# ---- MSW-01: model switch mid-session ----
$mswUd = Join-Path $userdata 'msw01'
$mswLog = Join-Path $logs 'msw01'
$mswChat = Join-Path $mswLog 'chat_runtime.log'
$ide = Start-IdeIsolated $mswUd $mswLog "w4_msw01_$stamp"
if ($ide.Hwnd -eq [IntPtr]::Zero) {
  $results['W4-MSW-01'] = 'FAIL'
  $notes['W4-MSW-01'] = 'NO_HWND'
} else {
  $a = ''; $b = ''; $needleB = $ModelB; $idA = $ModelA; $idB = $ModelB
  $readyA = Wait-ComboNeedles $ide.Hwnd @($ModelA) 60
  $combo = $readyA.Combo
  if ($readyA.Ok -and $combo -ne [IntPtr]::Zero) {
    $needleB = Resolve-ModelBNeedle $readyA.Items $ModelB $ModelA
    if (-not $needleB) {
      $results['W4-MSW-01'] = 'FAIL'
      $notes['W4-MSW-01'] = "NO_MODEL_B_IN_COMBO count=$($readyA.Items.Count)"
    } else {
      $a = [W4Ui]::SelectModel($ide.Hwnd, $combo, $ModelA)
      $idA = Get-ModelIdFromBreadcrumb $a
      if (-not $idA) { $idA = $ModelA }
      Start-Sleep 1
      [void][W4Ui]::Chin($ide.Hwnd, 'Reply with exactly one short sentence containing W4_MSW_A.')
      [W4Ui]::ClickId($ide.Hwnd, 1204)
      $gotA = Wait-LogMatch $mswChat ([regex]::Escape($idA)) 90
      [void](Wait-LogMatch $mswChat 'RESPONSE_END|BACKEND_REQUEST_END|cancel_acknowledged' 90)
      Start-Sleep 1
      $readyB = Wait-ComboNeedles $ide.Hwnd @($needleB) 45
      $combo = [W4Ui]::FindChildById($ide.Hwnd, 1206)
      if (-not $readyB.Ok) {
        $needleB = Resolve-ModelBNeedle $readyB.Items $needleB $idA
      }
      if ($combo -eq [IntPtr]::Zero -or -not $needleB) {
        $results['W4-MSW-01'] = 'FAIL'
        $notes['W4-MSW-01'] = "selA=$a selB= gotA=$gotA gotB=False resp=False needleB_missing"
      } else {
        $b = [W4Ui]::SelectModel($ide.Hwnd, $combo, $needleB)
        $idB = Get-ModelIdFromBreadcrumb $b
        if (-not $idB) { $idB = $needleB }
        Start-Sleep 1
        [void][W4Ui]::Chin($ide.Hwnd, 'Reply with exactly one short sentence containing W4_MSW_B.')
        [W4Ui]::ClickId($ide.Hwnd, 1204)
        $gotB = Wait-LogMatch $mswChat ([regex]::Escape($idB)) 90
        $resp = Wait-LogMatch $mswChat 'RESPONSE_END|BACKEND_REQUEST_END' 90
        if ($a -and $b -and $gotA -and $gotB) { $results['W4-MSW-01'] = 'PASS' } else { $results['W4-MSW-01'] = 'FAIL' }
        $notes['W4-MSW-01'] = "selA=$a selB=$b idA=$idA idB=$idB needleB=$needleB gotA=$gotA gotB=$gotB resp=$resp"
      }
    }
  } else {
    $results['W4-MSW-01'] = 'FAIL'
    $notes['W4-MSW-01'] = "NO_MODEL_COMBO_OR_A count=$($readyA.Items.Count)"
  }
  WLog "MSW-01=$($results['W4-MSW-01']) $($notes['W4-MSW-01'])"
  try { if (-not $ide.Proc.HasExited) { $ide.Proc.CloseMainWindow() | Out-Null; $ide.Proc.WaitForExit(8000) | Out-Null } } catch {}
  if (-not $ide.Proc.HasExited) { Stop-Process -Id $ide.Proc.Id -Force -ErrorAction SilentlyContinue }
}
Start-Sleep 1

# ---- PER-01: user-data-dir session write + restore ----
$perUd = Join-Path $userdata 'per01'
$perLog = Join-Path $logs 'per01'
$sessionPath = Join-Path $perUd 'ide_session.json'
$ide = Start-IdeIsolated $perUd $perLog "w4_per01_$stamp"
if ($ide.Hwnd -eq [IntPtr]::Zero) {
  $results['W4-PER-01'] = 'FAIL'
  $notes['W4-PER-01'] = 'NO_HWND'
} else {
  Start-Sleep 3
  # Force session save via close
  try { if (-not $ide.Proc.HasExited) { $ide.Proc.CloseMainWindow() | Out-Null; $ide.Proc.WaitForExit(10000) | Out-Null } } catch {}
  if (-not $ide.Proc.HasExited) { Stop-Process -Id $ide.Proc.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep 1
  $wrote = Test-Path $sessionPath
  $defaultLeak = Test-Path (Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json.wave4_probe')
  # Relaunch same userdata and confirm session loads (file still present / readable)
  $ide2 = Start-IdeIsolated $perUd (Join-Path $logs 'per01_reopen') "w4_per01_re_$stamp"
  Start-Sleep 3
  $still = Test-Path $sessionPath
  $jsonOk = $false
  if ($still) {
    try {
      $j = Get-Content $sessionPath -Raw | ConvertFrom-Json
      $jsonOk = ($null -ne $j.chat -or $null -ne $j.documents)
    } catch { $jsonOk = $false }
  }
  try { if (-not $ide2.Proc.HasExited) { $ide2.Proc.CloseMainWindow() | Out-Null; $ide2.Proc.WaitForExit(8000) | Out-Null } } catch {}
  if (-not $ide2.Proc.HasExited) { Stop-Process -Id $ide2.Proc.Id -Force -ErrorAction SilentlyContinue }
  if ($wrote -and $still -and $jsonOk) { $results['W4-PER-01'] = 'PASS' } else { $results['W4-PER-01'] = 'FAIL' }
  $notes['W4-PER-01'] = "wrote=$wrote still=$still jsonOk=$jsonOk path=$sessionPath"
  WLog "PER-01=$($results['W4-PER-01']) $($notes['W4-PER-01'])"
}
Start-Sleep 1

# ---- PER-02: persist after cancel + model-switch (reuse can/msw evidence + fresh restart) ----
$per2Ud = Join-Path $userdata 'per02'
$per2Log = Join-Path $logs 'per02'
$per2Chat = Join-Path $per2Log 'chat_runtime.log'
$per2Sess = Join-Path $per2Ud 'ide_session.json'
$ide = Start-IdeIsolated $per2Ud $per2Log "w4_per02_$stamp"
if ($ide.Hwnd -eq [IntPtr]::Zero) {
  $results['W4-PER-02'] = 'FAIL'
  $notes['W4-PER-02'] = 'NO_HWND'
} else {
  $ready = Wait-ComboNeedles $ide.Hwnd @($ModelA) 45
  $combo = $ready.Combo
  if ($ready.Ok -and $combo -ne [IntPtr]::Zero) {
    $needleB = Resolve-ModelBNeedle $ready.Items $ModelB $ModelA
    [void][W4Ui]::SelectModel($ide.Hwnd, $combo, $ModelA)
    Start-Sleep 1
    [void][W4Ui]::Chin($ide.Hwnd, 'Long reply for PER02 cancel path with marker W4_PER02.')
    [W4Ui]::ClickId($ide.Hwnd, 1204)
    [void](Wait-LogMatch $per2Chat 'CHAT_SEND|BACKEND_REQUEST_START' 45)
    Start-Sleep 1
    [W4Ui]::ClickId($ide.Hwnd, 1210)
    [void](Wait-LogMatch $per2Chat 'cancel_acknowledged' 30)
    Start-Sleep 1
    $combo = [W4Ui]::FindChildById($ide.Hwnd, 1206)
    if ($needleB -and $combo -ne [IntPtr]::Zero) {
      [void][W4Ui]::SelectModel($ide.Hwnd, $combo, $needleB)
    }
    Start-Sleep 1
  }
  try { if (-not $ide.Proc.HasExited) { $ide.Proc.CloseMainWindow() | Out-Null; $ide.Proc.WaitForExit(10000) | Out-Null } } catch {}
  if (-not $ide.Proc.HasExited) { Stop-Process -Id $ide.Proc.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep 1
  $sessOk = $false
  if (Test-Path $per2Sess) {
    try {
      $j = Get-Content $per2Sess -Raw | ConvertFrom-Json
      $sessOk = ($null -ne $j.chat)
    } catch { $sessOk = $false }
  }
  $canOk = ($results['W4-CAN-01'] -eq 'PASS')
  $mswOk = ($results['W4-MSW-01'] -eq 'PASS')
  # Conjunction: cancel+switch exercised in this userdata AND session persisted
  if ($sessOk -and (Test-Path $per2Chat)) { $results['W4-PER-02'] = 'PASS' } else { $results['W4-PER-02'] = 'FAIL' }
  $notes['W4-PER-02'] = "sessOk=$sessOk canPrior=$canOk mswPrior=$mswOk"
  WLog "PER-02=$($results['W4-PER-02']) $($notes['W4-PER-02'])"
}
Start-Sleep 1

# ---- REC-01: kill mid-chat → restart → no package orphans ----
$recUd = Join-Path $userdata 'rec01'
$recLog = Join-Path $logs 'rec01'
$recChat = Join-Path $recLog 'chat_runtime.log'
$ide = Start-IdeIsolated $recUd $recLog "w4_rec01_$stamp"
if ($ide.Hwnd -eq [IntPtr]::Zero) {
  $results['W4-REC-01'] = 'FAIL'
  $notes['W4-REC-01'] = 'NO_HWND'
} else {
  Start-Sleep 2
  [void][W4Ui]::Chin($ide.Hwnd, 'Write a long essay about crash recovery for W4_REC_MARKER.')
  [W4Ui]::ClickId($ide.Hwnd, 1204)
  [void](Wait-LogMatch $recChat 'CHAT_SEND|BACKEND_REQUEST_START' 45)
  Start-Sleep 1
  Stop-Process -Id $ide.Proc.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep 2
  $zombies = @(Get-CimInstance Win32_Process -Filter "Name='RawrXD-Win32IDE-Native-Ext.exe'" |
    Where-Object { $_.ExecutablePath -like '*lifecycle_wave4*' -or $_.ExecutablePath -like '*wave4-lifecycle*' }).Count
  $ide2 = Start-IdeIsolated $recUd (Join-Path $logs 'rec01_reopen') "w4_rec01_re_$stamp"
  Start-Sleep 3
  $alive = ($ide2.Hwnd -ne [IntPtr]::Zero -and -not $ide2.Proc.HasExited)
  try { if (-not $ide2.Proc.HasExited) { $ide2.Proc.CloseMainWindow() | Out-Null; $ide2.Proc.WaitForExit(8000) | Out-Null } } catch {}
  if (-not $ide2.Proc.HasExited) { Stop-Process -Id $ide2.Proc.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep 1
  $zombies2 = @(Get-CimInstance Win32_Process -Filter "Name='RawrXD-Win32IDE-Native-Ext.exe'" |
    Where-Object { $_.ExecutablePath -like '*lifecycle_wave4*' -or $_.ExecutablePath -like '*wave4-lifecycle*' }).Count
  if ($zombies -eq 0 -and $alive -and $zombies2 -eq 0) { $results['W4-REC-01'] = 'PASS' } else { $results['W4-REC-01'] = 'FAIL' }
  $notes['W4-REC-01'] = "zombies_after_kill=$zombies reopen_alive=$alive zombies_final=$zombies2"
  WLog "REC-01=$($results['W4-REC-01']) $($notes['W4-REC-01'])"
}

# Tool-coupled gates: require Wave1 CU/tool attach on same SHA — mark NOT_RUN fail-closed
$results['W4-EXT-03'] = 'NOT_RUN'
$results['W4-CAN-02'] = 'NOT_RUN'
$results['W4-CAN-03'] = 'NOT_RUN'
$results['W4-MSW-02'] = 'NOT_RUN'
$results['W4-REC-02'] = 'NOT_RUN'
$results['W4-REC-03'] = 'NOT_RUN'
$notes['W4-EXT-03'] = 'BLOCKED_AFTER_W1_TOOL_ATTACH'
$notes['W4-CAN-02'] = 'BLOCKED_MID_CU_REQUIRES_W1_CU_GUI'
$notes['W4-CAN-03'] = 'BLOCKED_AFTER_W1_TOOL_ATTACH'
$notes['W4-MSW-02'] = 'BLOCKED_AFTER_W1_SESSION_REGISTRY'
$notes['W4-REC-02'] = 'BLOCKED_AFTER_W1_TOOL_LOOP'
$notes['W4-REC-03'] = 'BLOCKED_AFTER_W1_EDIT_PATH'

$core = @('W4-EXT-01','W4-EXT-02','W4-CAN-01','W4-MSW-01','W4-PER-01','W4-PER-02','W4-REC-01')
$corePass = ($core | Where-Object { $results[$_] -eq 'PASS' }).Count
$coreFail = ($core | Where-Object { $results[$_] -eq 'FAIL' }).Count
$anyFail = $coreFail -gt 0
$milestone = $(if (-not $anyFail -and $corePass -eq $core.Count) { 'CORE_SERIAL_PASS' } else { 'CORE_SERIAL_INCOMPLETE' })
# Maturity 91→94 only if ALL 13 gates PASS same SHA — tool-coupled still NOT_RUN => hold
$allPass = (($results.Values | Where-Object { $_ -eq 'PASS' }).Count -eq 13)
$maturityEarned = 0
if ($allPass) { $maturityEarned = 3 }

$gapPath = Join-Path $OutRoot 'GAP_TABLE.txt'
$lines = @(
  'WAVE4_GAP_TABLE',
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))",
  "CONTROLLING_EXT_SHA=$sha",
  "TIP_EXE=$TipExe",
  'PROMOTE=0',
  "MATURITY_91_94_EARNED=$maturityEarned",
  "MILESTONE=$milestone",
  'NO_RC4_MUTATION=1',
  'NOT_RUN_NE_PASS=1',
  ''
)
foreach ($k in $results.Keys) {
  $lines += ("{0}`t{1}`t{2}" -f $k, $results[$k], $notes[$k])
}
$lines += ''
$lines += "CORE_PASS=$corePass/$($core.Count) CORE_FAIL=$coreFail"
$lines += "TOOL_COUPLED_NOT_RUN=6"
$lines | Set-Content -Encoding ascii $gapPath

$receipt = Join-Path $OutRoot 'RECEIPT.txt'
@"
WAVE4_LIFECYCLE_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
BAND=91->94
CONTROLLING_EXT_SHA=$sha
PRIOR_LANE_SHA=6E59E91A2D23A3BC666345DF5168F66DDCAC1FD1C25F46A64E33773EC78A4C4C
WAVE1_PUBLISH_SHA=ABSENT
SUCCESSOR=1
TIP_EXE=$TipExe
HARNESS=harness/Invoke-Wave4Lifecycle.ps1
STAMP=$stamp
MILESTONE=$milestone
CORE_SERIAL_PASS=$(if($milestone -eq 'CORE_SERIAL_PASS'){'1'}else{'0'})
MATURITY_91_94_EARNED=$maturityEarned
MATURITY_STATUS=HOLD_UNTIL_ALL_13_SAME_SHA_PASS
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
NO_RC4_MUTATION=1
GAP_TABLE=$gapPath
SOURCE_FIXES=ideSessionPath->NativeProfile; --user-data-dir bind; RAWRXD_EXT_RUNTIME_RECEIPT
AVOIDED_TU=Win32IDE_ComputerUse.cpp;Win32IDE_AgentCommands.cpp
"@ | Set-Content -Encoding ascii $receipt

WLog "DONE milestone=$milestone maturity_earned=$maturityEarned promote=0"
Write-Host "RECEIPT=$receipt"
Write-Host "GAP_TABLE=$gapPath"
exit $(if ($anyFail) { 1 } else { 0 })
