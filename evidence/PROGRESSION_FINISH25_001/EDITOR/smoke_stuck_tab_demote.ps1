#Requires -Version 5.1
# Brief smoke: leaf-only stuck tab demotes to Untitled. PROMOTE=0. No Finish-25 PASS claim.
$ErrorActionPreference = 'Stop'
$OutDir = 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001\EDITOR'
$SmokeLog = Join-Path $OutDir 'SMOKE_DOC_TAB_MAX1000_STUCK_TAB.txt'
$Exe = 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe'
$SessionJson = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$SessionBak = Join-Path $OutDir 'ide_session_pre_stuck_tab_smoke.json'
$GoodFile = Join-Path $OutDir 'workdir_retest\t08_doc_00.txt'
if (-not (Test-Path $GoodFile)) {
  New-Item -ItemType Directory -Force -Path (Split-Path $GoodFile) | Out-Null
  Set-Content -LiteralPath $GoodFile -Value 'GOOD_ANCHOR' -Encoding UTF8
}
$sha = (Get-FileHash $Exe -Algorithm SHA256).Hash
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$m) {
  $t = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  $script:lines.Add($t)
  Write-Host $t
}

L 'SMOKE=DOC_TAB_STUCK_DEMOTE'
L "EXE=$Exe"
L "SHA=$sha"
L 'PROMOTE=0'
L 'INVENT_PASS=0'

New-Item -ItemType Directory -Force -Path (Split-Path $SessionJson) | Out-Null
if (Test-Path $SessionJson) {
  Copy-Item $SessionJson $SessionBak -Force
  L "SESSION_BAK=$SessionBak"
} else {
  L 'SESSION_BAK=NONE'
}

$seedObj = [ordered]@{
  active = 1
  chat_mode = 0
  documents = @(
    [ordered]@{ path = $GoodFile; text = ''; modified = $false }
    [ordered]@{ path = 't8 01 doc'; text = ''; modified = $false }
  )
}
($seedObj | ConvertTo-Json -Depth 6 -Compress) | Set-Content -LiteralPath $SessionJson -Encoding UTF8
L 'SESSION_SEEDED=leaf_only_t8_01_doc_active1'

Get-Process RawrXD-Win32IDE-Native -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class StuckSmoke {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string n);
  public const uint WM_CLOSE=0x0010, BM_CLICK=0x00F5;
  public const uint TCM_GETITEMCOUNT=0x1304, TCM_GETCURSEL=0x130B, TCM_GETITEMW=0x133C;
  public const int IDC_DOC_TABS=1030;
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct TCITEMW {
    public uint mask; public uint dwState; public uint dwStateMask;
    public IntPtr pszText; public int cchTextMax; public int iImage; public IntPtr lParam;
  }
  public static string ClassName(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint p){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p) return true;
      if(ClassName(h)=="RawrXD_IDE_Window" && IsWindowVisible(h)){ f=h; return false;} return true; }, IntPtr.Zero); return f;
  }
  public static IntPtr FindDocTabs(IntPtr root){
    IntPtr byProp=IntPtr.Zero; IntPtr best=IntPtr.Zero; int bestCount=-1;
    EnumChildWindows(root,(h,l)=>{
      if(GetPropW(h,"RawrXDDocTabs")!=IntPtr.Zero){ byProp=h; }
      if(GetDlgCtrlID(h)!=IDC_DOC_TABS) return true;
      if(ClassName(h).IndexOf("SysTabControl",StringComparison.OrdinalIgnoreCase)<0) return true;
      int n=SendMessageW(h,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
      if(n>bestCount){ bestCount=n; best=h; }
      return true;
    }, IntPtr.Zero);
    return byProp!=IntPtr.Zero ? byProp : best;
  }
  public static IntPtr FindDialogByTitle(uint pid, string titleSub){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=pid) return true;
      if(!IsWindowVisible(h)) return true;
      string t=TitleOf(h);
      if(t.IndexOf(titleSub,StringComparison.OrdinalIgnoreCase)>=0){ f=h; return false; }
      return true; }, IntPtr.Zero); return f;
  }
  public static bool ClickOk(IntPtr dlg){
    IntPtr btn=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{
      string c=ClassName(h); string t=TitleOf(h);
      if(c=="Button" && (t=="OK" || t=="Ok")){ btn=h; return false; }
      return true;
    }, IntPtr.Zero);
    if(btn==IntPtr.Zero) return false;
    SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    return true;
  }
  public static string TabText(IntPtr tabs, int index){
    IntPtr buf = Marshal.AllocHGlobal(512);
    try {
      for(int i=0;i<512;i+=2) Marshal.WriteInt16(buf,i,0);
      TCITEMW it = new TCITEMW();
      it.mask = 0x0001;
      it.pszText = buf;
      it.cchTextMax = 256;
      IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TCITEMW)));
      try {
        Marshal.StructureToPtr(it, p, false);
        IntPtr r = SendMessageW(tabs, TCM_GETITEMW, new IntPtr(index), p);
        if(r==IntPtr.Zero) return "";
        return Marshal.PtrToStringUni(buf) ?? "";
      } finally { Marshal.FreeHGlobal(p); }
    } finally { Marshal.FreeHGlobal(buf); }
  }
}
'@

$proc = Start-Process -FilePath $Exe -PassThru
L "PID=$($proc.Id)"
$deadline = (Get-Date).AddSeconds(25)
$main = [IntPtr]::Zero
$dlgSeen = $false
$tabTexts = @()
$tabCount = -1
$curSel = -1

while ((Get-Date) -lt $deadline) {
  if ($main -eq [IntPtr]::Zero) { $main = [StuckSmoke]::FindMain([uint32]$proc.Id) }
  $dlg = [StuckSmoke]::FindDialogByTitle([uint32]$proc.Id, 'Invalid Document Tab')
  if ($dlg -ne [IntPtr]::Zero) {
    $dlgSeen = $true
    L ("MSGBOX_SEEN title=" + [StuckSmoke]::TitleOf($dlg))
    [void][StuckSmoke]::ClickOk($dlg)
    Start-Sleep -Milliseconds 400
  }
  if ($main -ne [IntPtr]::Zero) {
    $tabs = [StuckSmoke]::FindDocTabs($main)
    if ($tabs -ne [IntPtr]::Zero) {
      $tabCount = [StuckSmoke]::SendMessageW(
        $tabs, [StuckSmoke]::TCM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
      $curSel = [StuckSmoke]::SendMessageW(
        $tabs, [StuckSmoke]::TCM_GETCURSEL, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
      $tabTexts = @()
      for ($i = 0; $i -lt $tabCount; $i++) {
        $tabTexts += [StuckSmoke]::TabText($tabs, $i)
      }
      if ($dlgSeen -and (($tabTexts -join '|') -match 'Untitled')) { break }
    }
  }
  Start-Sleep -Milliseconds 300
  if ($proc.HasExited) {
    L "PROC_EXITED early code=$($proc.ExitCode)"
    break
  }
}

L ("MAIN=0x{0:X}" -f $main.ToInt64())
L "MSGBOX_INVALID_DOC_TAB=$dlgSeen"
L "TAB_COUNT=$tabCount"
L "TAB_CURSEL=$curSel"
L ('TAB_LABELS=' + ($tabTexts -join ' | '))
$hasUntitled = @($tabTexts | Where-Object { $_ -match 'Untitled' }).Count -gt 0
$hasLeafStuck = @($tabTexts | Where-Object { $_ -match 't8 01 doc' }).Count -gt 0
L "HAS_UNTITLED_LABEL=$hasUntitled"
L "HAS_LEAF_STUCK_LABEL=$hasLeafStuck"

$demote = 'NOT_CONFIRMED'
if ($dlgSeen -and $hasUntitled -and -not $hasLeafStuck) { $demote = 'CONFIRMED_UI' }
elseif ($dlgSeen -and $hasUntitled) { $demote = 'CONFIRMED_MSGBOX_AND_UNTITLED' }
elseif ($dlgSeen) { $demote = 'MSGBOX_ONLY' }
elseif ($hasUntitled -and -not $hasLeafStuck -and $tabCount -ge 1) { $demote = 'LABEL_ONLY_NO_MSGBOX' }
L "DEMOTE_OBSERVATION=$demote"
L 'FINISH25_PASS=NOT_CLAIMED'
L 'PROMOTE=0'

if (-not $proc.HasExited -and $main -ne [IntPtr]::Zero) {
  [void][StuckSmoke]::PostMessageW($main, [StuckSmoke]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  $null = $proc.WaitForExit(5000)
}
if (-not $proc.HasExited) {
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  L 'FORCE_KILL=1'
} else {
  L 'CLEAN_CLOSE=1'
}

if (Test-Path $SessionBak) {
  Copy-Item $SessionBak $SessionJson -Force
  L 'SESSION_RESTORED_FROM_BAK=1'
}

Set-Content -LiteralPath $SmokeLog -Value ($lines -join "`r`n") -Encoding UTF8
Write-Host "DEMOTE_OBSERVATION=$demote"
Write-Host "SMOKE_LOG=$SmokeLog"
