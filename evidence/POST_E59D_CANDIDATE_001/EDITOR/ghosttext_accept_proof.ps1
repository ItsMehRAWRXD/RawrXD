#Requires -Version 5.1
# Fail-closed GhostText render+accept+save proof on POST_E59D candidate.
# PASS only if editor text grows after Tab OR accepted bytes appear on disk beyond seed.
$ErrorActionPreference='Continue'
$OutDir='F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR'
$WorkDir=Join-Path $OutDir 'workdir'
$TipExe='F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha='3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$Log=Join-Path $OutDir 'GHOSTTEXT_ACCEPT_RUNLOG.txt'
Set-Content $Log ''
function WLog([string]$m){ $l='[{0}] {1}' -f (Get-Date -Format 'o'),$m; Add-Content $Log $l; Write-Host $l }

$sha=(Get-FileHash $TipExe -Algorithm SHA256).Hash
WLog "SHA=$sha"
if($sha -ne $ExpectedSha){ WLog 'SHA_MISMATCH'; exit 3 }

Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class GT {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_CLOSE=0x0010;
  public const uint EM_SETSEL=0x00B1, EM_REPLACESEL=0x00C2, BM_CLICK=0x00F5;
  public const int IDM_FILE_OPEN=2002, IDM_FILE_SAVE=2003, IDC_EDITOR=1001, IDC_DEBUG=1014;
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra; }
  public static string ClassName(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindById(IntPtr root, int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,l)=>{ if(GetDlgCtrlID(h)==id && IsWindowVisible(h)){ f=h; return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindEditor(IntPtr root){ return FindById(root, IDC_EDITOR); }
  public static IntPtr FindDebug(IntPtr root){ return FindById(root, IDC_DEBUG); }
  public static IntPtr FindAnyDialog(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="#32770"&&IsWindowVisible(h)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static void Focus(IntPtr main, IntPtr ed){ ShowWindow(main,9); SetForegroundWindow(main); uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId(); bool a=false; if(gui!=me)a=AttachThreadInput(me,gui,true); SetFocus(ed); if(a)AttachThreadInput(me,gui,false); }
  public static string GetText(IntPtr h){ int len=SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero).ToInt32(); if(len<=0)return ""; IntPtr buf=Marshal.AllocHGlobal((len+2)*2); try{ int got=SendMessageW(h,WM_GETTEXT,(IntPtr)(len+1),buf).ToInt32(); return got>0?Marshal.PtrToStringUni(buf)??"":""; } finally{ Marshal.FreeHGlobal(buf);} }
  public static void SetText(IntPtr h, string t){ SendMessageW(h,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1)); SendMessageW(h,EM_REPLACESEL,(IntPtr)1,t??""); }
  public static void Chord(ushort a, ushort b){ var i=new INPUT[4]; for(int k=0;k<4;k++) i[k].type=1; i[0].ki.wVk=a; i[1].ki.wVk=b; i[2].ki.wVk=b; i[2].ki.dwFlags=2; i[3].ki.wVk=a; i[3].ki.dwFlags=2; SendInput(4,i,Marshal.SizeOf(typeof(INPUT))); }
  public static void Tab(){ var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x09; i[1].type=1; i[1].ki.wVk=0x09; i[1].ki.dwFlags=2; SendInput(2,i,Marshal.SizeOf(typeof(INPUT))); }
  public static bool Drive(IntPtr dlg, string path){
    if(dlg==IntPtr.Zero) return false; IntPtr edit=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ string c=ClassName(h); int id=GetDlgCtrlID(h); if((c=="Edit"||c.StartsWith("RichEdit"))&&(id==0x47C||id==0x480)&&IsWindowVisible(h)){edit=h;return false;} return true;},IntPtr.Zero);
    if(edit==IntPtr.Zero) EnumChildWindows(dlg,(h,l)=>{ if(ClassName(h)=="ComboBoxEx32"){ EnumChildWindows(h,(c,q)=>{ if(ClassName(c)=="Edit"){edit=c;return false;} return true;},IntPtr.Zero); return edit==IntPtr.Zero;} return true;},IntPtr.Zero);
    if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg); SetWindowTextW(edit,path); SendMessageW(edit,WM_SETTEXT,IntPtr.Zero,path);
    IntPtr ok=IntPtr.Zero; EnumChildWindows(dlg,(h,l)=>{ if(GetDlgCtrlID(h)==1&&ClassName(h)=="Button"){ok=h;return false;} return true;},IntPtr.Zero);
    if(ok!=IntPtr.Zero){ PostMessageW(dlg,WM_COMMAND,(IntPtr)1,ok); SendMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero);} else PostMessageW(dlg,WM_COMMAND,(IntPtr)1,IntPtr.Zero);
    System.Threading.Thread.Sleep(200);
    if(IsWindowVisible(dlg)){ var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x0D; i[1].type=1; i[1].ki.wVk=0x0D; i[1].ki.dwFlags=2; SendInput(2,i,Marshal.SizeOf(typeof(INPUT))); }
    return true;
  }
}
'@

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

# Probe ollama
$ollama='DOWN'
try {
  $r=Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -UseBasicParsing -TimeoutSec 5
  $ollama="UP status=$($r.StatusCode)"
} catch { $ollama="DOWN $($_.Exception.Message)" }
WLog "OLLAMA=$ollama"

$gPath=Join-Path $WorkDir 'gt_accept.txt'
$seed="def add(a, b):`r`n    "
[IO.File]::WriteAllText($gPath, $seed, [Text.UTF8Encoding]::new($false))
$seedLen=(Get-Item $gPath).Length

$psi=New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName=$TipExe; $psi.WorkingDirectory=(Split-Path $TipExe); $psi.UseShellExecute=$false
$proc=[Diagnostics.Process]::Start($psi)
WLog "LAUNCHED pid=$($proc.Id)"
$main=[IntPtr]::Zero
for($i=0;$i -lt 80;$i++){ $main=[GT]::FindMain([uint32]$proc.Id); if($main -ne [IntPtr]::Zero){break}; Start-Sleep -Milliseconds 250 }
$ed=[GT]::FindEditor($main)
WLog ("main=0x{0:X} editor=0x{1:X}" -f $main.ToInt64(), $ed.ToInt64())

# Open seed file
[void][GT]::PostMessageW($main,[GT]::WM_COMMAND,[IntPtr][GT]::IDM_FILE_OPEN,[IntPtr]::Zero)
Start-Sleep -Milliseconds 500
$dlg=[GT]::FindAnyDialog([uint32]$proc.Id)
[void][GT]::Drive($dlg,$gPath)
Start-Sleep -Seconds 1
$ed=[GT]::FindEditor($main)
[GT]::Focus($main,$ed)
[GT]::SetText($ed,$seed)
Start-Sleep -Milliseconds 300
$before=[GT]::GetText($ed)
WLog "before_len=$($before.Length) before='$($before.Replace("`r","\\r").Replace("`n","\\n"))'"

# Trigger GhostText
[GT]::Focus($main,$ed)
[GT]::Chord(0x11,0x20) # Ctrl+Space
WLog 'ctrlspace'
$deadline=(Get-Date).AddSeconds(90)
$sawOverlay=$false; $maxDebug=0; $maxEd=$before.Length
$sessionLog=Get-ChildItem (Join-Path (Split-Path $TipExe) 'logs') -Filter 'RawrXD_IDE_*.log' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
WLog "session_log=$($sessionLog.FullName)"
while((Get-Date) -lt $deadline){
  if($proc.HasExited){ WLog 'PROCESS_DEAD'; break }
  Start-Sleep -Milliseconds 500
  $ed=[GT]::FindEditor($main)
  $dbg=[GT]::FindDebug($main)
  $edText=[GT]::GetText($ed)
  $dbgText=if($dbg -ne [IntPtr]::Zero){[GT]::GetText($dbg)}else{''}
  if($edText.Length -gt $maxEd){ $maxEd=$edText.Length }
  if($dbgText.Length -gt $maxDbg){ $maxDbg=$dbgText.Length; $sawOverlay=$true }
  # Look for new completion-ish log lines after trigger
  if($sessionLog){
    $tail=Get-Content $sessionLog.FullName -Tail 40 -EA SilentlyContinue
    if($tail -match 'eligible=1|suggestion|GhostText response|completion ready|inline ghost|Accept'){
      WLog 'LOG_COMPLETION_SIGNAL'
      $sawOverlay=$true
    }
  }
  if($maxEd -gt $before.Length + 2){ WLog 'EDITOR_GREW_BEFORE_TAB'; break }
  if($sawOverlay -and $maxDbg -gt 0){ WLog "DEBUG_OVERLAY_LEN=$maxDbg"; break }
}
WLog "pre_tab maxEd=$maxEd maxDbg=$maxDbg sawOverlay=$sawOverlay"

[GT]::Focus($main,[GT]::FindEditor($main))
[GT]::Tab()
Start-Sleep -Seconds 1
$after=[GT]::GetText([GT]::FindEditor($main))
WLog "after_len=$($after.Length)"
[void][GT]::PostMessageW($main,[GT]::WM_COMMAND,[IntPtr][GT]::IDM_FILE_SAVE,[IntPtr]::Zero)
Start-Sleep -Seconds 1
$diskLen=(Get-Item $gPath).Length
$disk=Get-Content $gPath -Raw
$diskSha=(Get-FileHash $gPath -Algorithm SHA256).Hash
WLog "disk_len=$diskLen seed_len=$seedLen sha=$diskSha"

$result='NOT_VERIFIED_NO_ACCEPT'
if($proc.HasExited){ $result='FAIL_PROCESS_DEAD' }
elseif($after.Length -gt $before.Length + 2 -or $diskLen -gt $seedLen + 2){
  # accepted completion changed buffer/disk
  if($disk -match [regex]::Escape('def add') -and ($after.Length -gt $before.Length -or $diskLen -gt $seedLen)){
    $result='PASS'
  } else { $result='FAIL_INCONSISTENT' }
} elseif($sawOverlay){
  $result='NOT_VERIFIED_OVERLAY_NO_ACCEPT'
} else {
  $result='NOT_VERIFIED_NO_COMPLETION'
}

# Close
[void][GT]::PostMessageW($main,[GT]::WM_CLOSE,[IntPtr]::Zero,[IntPtr]::Zero)
Start-Sleep -Milliseconds 500
$d=[GT]::FindAnyDialog([uint32]$proc.Id)
if($d -ne [IntPtr]::Zero){ [GT]::PostMessageW($d,[GT]::WM_COMMAND,[IntPtr]7,[IntPtr]::Zero) }
[void]$proc.WaitForExit(10000)
if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }

$receipt=@"
# GhostText accept proof (fail-closed)

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE_SHA=$sha
OLLAMA=$ollama
BEFORE_LEN=$($before.Length)
AFTER_LEN=$($after.Length)
DISK_LEN=$diskLen
SEED_LEN=$seedLen
SAW_OVERLAY=$sawOverlay
MAX_DEBUG_LEN=$maxDbg
GHOSTTEXT_RENDER_ACCEPT_SAVE=$result
PROMOTE=0
CERTIFIED=0
NOTE=Route-log-only is NOT accept. PASS requires buffer/disk growth after Tab.
"@
Set-Content (Join-Path $OutDir 'GHOSTTEXT_ACCEPT_RECEIPT.md') $receipt -Encoding UTF8
WLog "RESULT=$result"
if($result -eq 'PASS'){ exit 0 } else { exit 1 }
