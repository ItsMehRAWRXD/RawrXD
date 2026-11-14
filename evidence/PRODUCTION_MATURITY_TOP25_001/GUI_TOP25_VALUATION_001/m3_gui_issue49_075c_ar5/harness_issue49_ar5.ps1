$ErrorActionPreference = 'Continue'
$outDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$stage = Join-Path $outDir 'stage'
$ws = Join-Path $outDir 'ws'
$log = Join-Path $outDir 'RUNLOG.txt'
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content $log $line
  Write-Output $line
}
Set-Content $log ''
New-Item -ItemType Directory -Force -Path $stage, (Join-Path $ws 'evidence\RAWRXD_AGENT_LOOP_E2E_001') | Out-Null
$exeSrc = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_absorb075c_ar5.exe'
$exe = Join-Path $stage 'RawrXD-Win32IDE_absorb075c_ar5.exe'
$rawr = Join-Path $stage 'rawr.exe'
Copy-Item $exeSrc $exe -Force
Copy-Item 'G:\~dev\rawrxd\build_ninja\bin\rawr_gpufwd_C7402085.exe' $rawr -Force
Set-Content (Join-Path $ws 'evidence\RAWRXD_AGENT_LOOP_E2E_001\agent_fixture.txt') "AGENT_FIXTURE_V1`n"
Set-Content (Join-Path $ws 'note.txt') "note_pre`n"
Set-Content (Join-Path $ws 'bug.cpp') "#include <cstdio>`nint main(){ std::puts(`"BUG`"); return 0; }`n"
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$rsha = (Get-FileHash $rawr -Algorithm SHA256).Hash
WLog "PIN EXE=$sha RAWR=$rsha"
$csPath = Join-Path $outDir 'H.cs'
@'
using System; using System.Text; using System.Runtime.InteropServices;
public class H {
  public delegate bool EP(IntPtr h, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool EnumWindows(EP lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EP lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true; var c=new StringBuilder(256); GetClassNameW(h,c,256); var s=c.ToString(); if(s=="RawrXD_IDE_MainWindow"||s=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool Ready(IntPtr m){ return GetPropW(m,"RawrXD.MainMenuReady")!=IntPtr.Zero; }
  public static int Post(IntPtr h,int id){ return (h!=IntPtr.Zero&&IsWindow(h)&&PostMessageW(h,0x0111,(IntPtr)id,IntPtr.Zero))?1:0; }
  public static IntPtr FindTitle(uint pid,string needle){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true; var t=new StringBuilder(256); GetWindowTextW(h,t,256); if(t.ToString().IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr ChildClass(IntPtr parent,string cls){ IntPtr f=IntPtr.Zero; EnumChildWindows(parent,(h,l)=>{ var c=new StringBuilder(64); GetClassNameW(h,c,64); if(string.Equals(c.ToString(),cls,StringComparison.OrdinalIgnoreCase)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr ChildTitle(IntPtr parent,string needle){ IntPtr f=IntPtr.Zero; EnumChildWindows(parent,(h,l)=>{ var t=new StringBuilder(128); GetWindowTextW(h,t,128); if(t.ToString().IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int Fill(uint pid,string prompt){ IntPtr d=FindTitle(pid,"Bounded Agent Loop"); if(d==IntPtr.Zero) return 0; IntPtr e=ChildClass(d,"Edit"); if(e==IntPtr.Zero) return 0; SendMessageW(e,0x000C,IntPtr.Zero,prompt); IntPtr ok=ChildTitle(d,"Run Agent"); if(ok==IntPtr.Zero) ok=ChildTitle(d,"OK"); if(ok==IntPtr.Zero) return 0; SetForegroundWindow(d); SendMessageW(ok,0x00F5,IntPtr.Zero,IntPtr.Zero); return 1; }
  public static void Dismiss(uint pid){ IntPtr mb=FindTitle(pid,"Agent Error"); if(mb==IntPtr.Zero) mb=FindTitle(pid,"Error"); if(mb==IntPtr.Zero) return; IntPtr ok=ChildTitle(mb,"OK"); if(ok!=IntPtr.Zero) SendMessageW(ok,0x00F5,IntPtr.Zero,IntPtr.Zero); }
}
'@ | Set-Content $csPath -Encoding ASCII
Add-Type -Path $csPath -ErrorAction SilentlyContinue | Out-Null
Get-Process -Name 'RawrXD-Win32IDE*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.WorkingDirectory = $stage
$psi.UseShellExecute = $false
$psi.Arguments = "--no-server `"$ws`""
$map = @{
  SKIP_DEFERRED_MODEL_LOAD = '1'
  RAWRXD_ALLOW_GPU = '0'
  RAWRXD_GUI = '1'
  RAWRXD_DISABLE_OLLAMA_FETCH = '1'
  LOCAL_ONLY = '1'
  LOCAL_ONLY_NO_OLLAMA = '1'
  RAWRXD_SKIP_GPU_POWER_PROBE = '1'
  RAWRXD_CLI_PATH = $rawr
  RAWRXD_USE_CLI_AGENT = '1'
  RAWR_AGENT_FORCE_TOOL = 'read,patch,build,test,report'
  RAWR_AGENT_FORCE_PATH = 'evidence\RAWRXD_AGENT_LOOP_E2E_001\agent_fixture.txt'
  RAWR_AGENT_FORCE_CONTENT = 'AGENT_FIXTURE_V1 / patched_by_m3_gui_ar5'
  RAWRXD_AGENT_TASK = 'Read note.txt and bug.cpp; patch bug.cpp to print AGENT_RESULT=5; build and run.'
  RAWRXD_MODEL = 'tinyllama.gguf'
  RAWRXD_WORKSPACE = $ws
}
foreach ($kv in $map.GetEnumerator()) { $psi.EnvironmentVariables[$kv.Key] = $kv.Value }
$proc = [Diagnostics.Process]::Start($psi)
WLog "SPAWN=$($proc.Id)"
$ready = $false
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "EARLY_EXIT=$($proc.ExitCode)"; break }
  $m = [H]::FindMain([uint32]$proc.Id)
  if ($m -ne [IntPtr]::Zero -and [H]::Ready($m)) { $ready = $true; break }
  Start-Sleep -Milliseconds 300
}
WLog "READY=$([int]$ready)"
$ar5 = 0; $btc = 0; $fr = 0; $pa = 0; $p4120 = 0; $fill = 0; $p4100 = 0
if ($ready) {
  $m = [H]::FindMain([uint32]$proc.Id)
  $p4120 = [H]::Post($m, 4120)
  WLog "POST_4120=$p4120"
  Start-Sleep 1
  $end = (Get-Date).AddSeconds(10)
  while ((Get-Date) -lt $end) {
    if ([H]::Fill([uint32]$proc.Id, 'Read note.txt and bug.cpp; patch bug.cpp to print AGENT_RESULT=5; build and run.') -eq 1) {
      $fill = 1; break
    }
    Start-Sleep -Milliseconds 200
  }
  WLog "FILL=$fill"
  Start-Sleep 40
  [H]::Dismiss([uint32]$proc.Id)
  $m = [H]::FindMain([uint32]$proc.Id)
  $p4100 = [H]::Post($m, 4100)
  WLog "POST_4100=$p4100"
  Start-Sleep 40
  [H]::Dismiss([uint32]$proc.Id)
  Get-ChildItem $ws -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $t = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($t -match 'AGENT_RESULT=5') { $ar5 = 1 }
    if ($t -match 'BUILD_COMPLETED=1|RAWR_AGENT_BUILD_OK') { $btc = 1 }
    if ($t -match 'FILES_READ=1') { $fr = 1 }
    if ($t -match 'patched_by_m3_gui_ar5') { $pa = 1 }
  }
  if (Test-Path (Join-Path $ws 'bug.exe')) { $btc = 1 }
}
try { if (-not $proc.HasExited) { $proc.Kill() } } catch {}
$full = [int](($ar5 -eq 1) -and ($btc -eq 1))
WLog "AGENT_RESULT5=$ar5 BUILD_TEST_CRUMB=$btc GUI_EBT_FULL=$full FILES_READ=$fr PATCH=$pa"
@(
  "ID=m3_gui_issue49_075c_ar5"
  "EXE=$exe"
  "EXE_SHA256=$sha"
  "STAGED_RAWR_SHA256=$rsha"
  "MENU_READY=$([int]$ready)"
  "POST_4120=$p4120"
  "BOUNDED_DIALOG_FILLED=$fill"
  "POST_4100=$p4100"
  "AGENT_RESULT5=$ar5"
  "BUILD_TEST_CRUMB=$btc"
  "GUI_EBT_FULL=$full"
  "FILES_READ=$fr"
  "PATCH_APPLIED=$pa"
  "DEEP2_AGENTIC_LOOP=ABSENT"
  "TIP_6754616E_THRASHED=0"
  "PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0 NOT_RUN!=PASS"
  "ASOF=$((Get-Date).ToString('o'))"
) | Set-Content (Join-Path $outDir 'run.meta.txt')
@(
  "AGENT_RESULT5=$ar5"
  "BUILD_TEST_CRUMB=$btc"
  "GUI_EBT_FULL=$full"
  "EXE_SHA256=$sha"
  "STAGED_RAWR_SHA256=$rsha"
) | Set-Content (Join-Path $outDir 'RESULT.txt')
