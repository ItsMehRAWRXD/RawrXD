# Dump Output/vars after single START to locate GUI SESSION_REAL gap.
$ErrorActionPreference = 'Continue'
Get-Process RawrXD*, debuggee* -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class DbgDump {
  public const uint WM_COMMAND=0x0111; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_NORMAL=0;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,256); if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero); return f; }
  public static IntPtr FindId(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static string RichText(IntPtr h){
    if(h==IntPtr.Zero) return "<null>";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    var cls=new StringBuilder(64); GetClassNameW(h,cls,64);
    string prefix="cls="+cls.ToString()+" n="+n+" ";
    if(n<=0){ var t=new StringBuilder(256); GetWindowTextW(h,t,256); return prefix+"gt='"+t.ToString()+"'"; }
    if(n>8000) n=8000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    string s=sb.ToString().Replace("\r"," ").Replace("\n"," | ");
    if(s.Length>600) s=s.Substring(0,600);
    return prefix+"'"+s+"'";
  }
  public static string DumpIds(IntPtr root,int[] ids){
    var sb=new StringBuilder();
    foreach(var id in ids){
      IntPtr h=FindId(root,id);
      sb.AppendLine("ID"+id+" hwnd=0x"+h.ToInt64().ToString("X")+" vis="+(h!=IntPtr.Zero && IsWindowVisible(h))+" "+RichText(h));
    }
    return sb.ToString();
  }
  public static string Scan(IntPtr root){
    var sb=new StringBuilder();
    EnumChildWindows(root,(h,lp)=>{
      var t=new StringBuilder(512); GetWindowTextW(h,t,512); string tx=t.ToString();
      if(tx.IndexOf("debug",StringComparison.OrdinalIgnoreCase)>=0 || tx.IndexOf("Native",StringComparison.OrdinalIgnoreCase)>=0 || tx.IndexOf("breakpoint",StringComparison.OrdinalIgnoreCase)>=0 || tx.IndexOf("WaitFor",StringComparison.OrdinalIgnoreCase)>=0 || tx.IndexOf("RAWRXD_DEBUGGEE",StringComparison.OrdinalIgnoreCase)>=0 || tx.IndexOf("launch",StringComparison.OrdinalIgnoreCase)>=0 || tx.IndexOf("Creating",StringComparison.OrdinalIgnoreCase)>=0){
        var c=new StringBuilder(64); GetClassNameW(h,c,64);
        sb.AppendLine("id="+GetDlgCtrlID(h)+" cls="+c.ToString()+" vis="+IsWindowVisible(h)+" txt="+tx.Replace("\r"," ").Replace("\n"," "));
      }
      return true;
    },IntPtr.Zero);
    return sb.ToString();
  }
}
"@
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe'
$debuggee = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\debuggee_fixture.exe'
$broken = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$logDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\debug_dump_27e2'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
$runlog = Join-Path $outDir ("debug_dump_" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".txt")
function Log([string]$m) { $line = "$(Get-Date -Format o) $m"; Add-Content $runlog $line; Write-Host $line }
$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_DEBUGGEE = $debuggee
$env:RAWRXD_PROBLEMS_FIXTURE = $broken
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
Log "TIP_SHA256=$sha"
$p = Start-Process $exe -ArgumentList @($broken) -WorkingDirectory 'F:\rawrxd' -PassThru
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 400
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  $main = [DbgDump]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64()) exited=$($p.HasExited)"
if ($main -eq [IntPtr]::Zero) { exit 2 }
[void][DbgDump]::ShowWindow($main, 9)
[void][DbgDump]::SetForegroundWindow($main)
Start-Sleep 1
[void][DbgDump]::Cmd($main, 1104, 2000)
[void][DbgDump]::Cmd($main, 6004, 2000)
Start-Sleep 1
Log "BEFORE vars=$([DbgDump]::IdList($main,6043))"
Log "BEFORE_IDS`n$([DbgDump]::DumpIds($main,@(1011,1012,1013,1014,1604,6043)))"
$sw = [Diagnostics.Stopwatch]::StartNew()
$ok = [DbgDump]::Cmd($main, 5060, 20000)
$sw.Stop()
Log "START5060=$ok elapsed_ms=$($sw.ElapsedMilliseconds)"
Start-Sleep 2
Log "AFTER2 vars=$([DbgDump]::IdList($main,6043)) childDbg=$((Get-Process debuggee_fixture -EA SilentlyContinue | Measure-Object).Count) ideExited=$($p.HasExited)"
Log "AFTER_IDS`n$([DbgDump]::DumpIds($main,@(1011,1012,1013,1014,1604,6043)))"
Log "SCAN`n$([DbgDump]::Scan($main))"
Start-Sleep 5
Log "AFTER7 vars=$([DbgDump]::IdList($main,6043)) childDbg=$((Get-Process debuggee_fixture -EA SilentlyContinue | Measure-Object).Count) ideExited=$($p.HasExited)"
Log "SCAN2`n$([DbgDump]::Scan($main))"
try { if (-not $p.HasExited) { $p.Kill() } } catch {}
Get-Process RawrXD*, debuggee* -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Log "DONE runlog=$runlog"
