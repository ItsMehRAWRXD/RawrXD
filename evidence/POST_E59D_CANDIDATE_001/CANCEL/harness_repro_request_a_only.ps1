#Requires -Version 5.1
# Minimal Request A repro on CERT 3B720981 — no Stop/B. PROMOTE=0 REBUILD=HELD
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL'
$Logs = Join-Path $OutDir 'logs'
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$Log = Join-Path $OutDir 'REPRO_REQUEST_A_RUNLOG.txt'
Set-Content $Log ''
function WLog($m){ $l='[{0}] {1}' -f (Get-Date -Format o),$m; Add-Content $Log $l; $l }

$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class ReproA {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  public const uint WM_SETTEXT=0x000C; public const uint WM_COMMAND=0x0111; public const uint BM_CLICK=0x00F5;
  public static void Click(IntPtr parent, IntPtr btn, int id) {
    if (btn != IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    IntPtr wp = (IntPtr)((0 << 16) | (id & 0xFFFF));
    SendMessageW(parent, WM_COMMAND, wp, btn);
  }
  public static void SetEdit(IntPtr edit, string text) {
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p);
    Marshal.FreeHGlobal(p); SetWindowTextW(edit, text);
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var c=new StringBuilder(256); GetClassNameW(h,c,256);
      if(c.ToString()=="RawrXD_IDE_Window"){ found=h; return false;} return true;}, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindId(IntPtr parent, int id) {
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,-12)==id){found=h;return false;} return true;}, IntPtr.Zero);
    return found;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$sha=(Get-FileHash $CandExe -Algorithm SHA256).Hash
WLog "SHA_PRE=$sha"
if ($sha -ne $ExpectSha) { WLog 'SHA_DRIFT'; exit 3 }
Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$psi=New-Object Diagnostics.ProcessStartInfo
$psi.FileName=$CandExe; $psi.WorkingDirectory=(Split-Path $CandExe); $psi.UseShellExecute=$false
$proc=[Diagnostics.Process]::Start($psi)
WLog "PID=$($proc.Id)"
$main=[IntPtr]::Zero
$dl=(Get-Date).AddSeconds(60)
while((Get-Date) -lt $dl){
  if($proc.HasExited){ WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main=[ReproA]::FindMain([uint32]$proc.Id)
  if($main -ne [IntPtr]::Zero -and [ReproA]::IsWindowVisible($main) -and [ReproA]::FindId($main,1204) -ne [IntPtr]::Zero){ break }
  Start-Sleep -Milliseconds 300
}
[void][ReproA]::ShowWindow($main,9)
WLog ("HWND=0x{0:X}" -f $main.ToInt64())
$input=[ReproA]::FindId($main,1202)
$send=[ReproA]::FindId($main,1204)
$combo=[ReproA]::FindId($main,1206)
# select gemma3:4b if possible (CB_FINDSTRINGExactish via scan)
$cnt=[ReproA]::SendMessageW($combo,0x0146,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32()
for($i=0;$i -lt $cnt;$i++){
  $tlen=[ReproA]::SendMessageW($combo,0x0149,[IntPtr]$i,[IntPtr]::Zero).ToInt32()
  if($tlen -le 0){continue}
  $buf=[Runtime.InteropServices.Marshal]::AllocHGlobal(($tlen+2)*2)
  try{ [void][ReproA]::SendMessageW($combo,0x0148,[IntPtr]$i,$buf); $item=[Runtime.InteropServices.Marshal]::PtrToStringUni($buf) }
  finally{ [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
  if($item -like '*gemma3:4b*'){ [void][ReproA]::SendMessageW($combo,0x014E,[IntPtr]$i,[IntPtr]::Zero); WLog "MODEL=$item"; break }
}
Start-Sleep -Milliseconds 500
# Single BM_CLICK only (reduce harness multi-notify) — still product path
[ReproA]::SetEdit($input, 'Write a very long detailed essay of at least 2000 words about Windows kernel scheduling.')
Start-Sleep -Milliseconds 200
# Variant: only PostMessage BN_CLICKED to parent (no BM_CLICK) — actually use single SendMessage BM_CLICK
[void][ReproA]::SendMessageW($send, [ReproA]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero)
WLog 'REQUEST_A_SUBMITTED_SINGLE_BM_CLICK'
$armDl=(Get-Date).AddSeconds(30)
while((Get-Date) -lt $armDl){
  if($proc.HasExited){
    $code=$proc.ExitCode
    WLog ("CRASH_REPRO exit=$code hex=0x{0:X8}" -f [uint32]$code)
    $shaPost=(Get-FileHash $CandExe -Algorithm SHA256).Hash
    WLog "SHA_POST=$shaPost"
    "REPRO_CRASH=1`nEXIT=$code`nSHA_PRE=$sha`nSHA_POST=$shaPost" | Set-Content (Join-Path $OutDir 'REPRO_REQUEST_A_RESULT.txt')
    exit 1
  }
  Start-Sleep -Milliseconds 200
}
WLog 'NO_CRASH_IN_30S'
if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
$shaPost=(Get-FileHash $CandExe -Algorithm SHA256).Hash
WLog "SHA_POST=$shaPost"
"REPRO_CRASH=0`nSHA_PRE=$sha`nSHA_POST=$shaPost" | Set-Content (Join-Path $OutDir 'REPRO_REQUEST_A_RESULT.txt')
exit 0
