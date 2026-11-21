param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g54_restore_result.txt"
)

# G54: verify layout restoration across restart.
# 1) Launch, move/resize the main window to a distinctive rect.
# 2) Close (WM_CLOSE) -> session.json written.
# 3) Relaunch -> verify the main window is restored to the same rect.

Add-Type -Namespace G54 -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
public struct RECT { public int Left, Top, Right, Bottom; }
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

function W([string]$m){ Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }
function FindRoot([int]$procId){
    $script:root=[IntPtr]::Zero
    $cb=[G54.Api+EnumProc]{ param($h,$l) $p2=0; [void][G54.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $procId){ $c=New-Object System.Text.StringBuilder 128; [void][G54.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G54.Api]::EnumWindows($cb,[IntPtr]::Zero)
    return $script:root
}

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -ErrorAction SilentlyContinue
$sess = Join-Path $env:APPDATA 'RawrXD\session.json'

# --- Launch #1 ---
$p1 = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.p1.err"
$root1=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $root1 -eq [IntPtr]::Zero -and -not $p1.HasExited){ Start-Sleep -Milliseconds 500; $root1 = FindRoot $p1.Id }
if($root1 -eq [IntPtr]::Zero){ W "P1_ROOT_NOT_FOUND"; if(-not $p1.HasExited){Stop-Process -Id $p1.Id -Force}; exit 3 }
Start-Sleep -Seconds 3
# set distinctive rect
$tx=123; $ty=77; $tw=900; $th=640
[void][G54.Api]::MoveWindow($root1,$tx,$ty,$tw,$th,$true)
Start-Sleep -Seconds 2
$r1=New-Object G54.Api+RECT; [void][G54.Api]::GetWindowRect($root1,[ref]$r1)
W ("SET_RECT=({0},{1},{2},{3})" -f $r1.Left,$r1.Top,$r1.Right,$r1.Bottom)
[void][G54.Api]::PostMessage($root1,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)  # WM_CLOSE
$null=$p1.WaitForExit(8000); if(-not $p1.HasExited){ Stop-Process -Id $p1.Id -Force -EA SilentlyContinue }
Start-Sleep -Seconds 2
$sessExists = Test-Path $sess
W ("SESSION_WRITTEN=" + $sessExists)
if($sessExists){ $j = Get-Content $sess -Raw | ConvertFrom-Json; W ("  session panel.sidebarWidth=" + $j.panel.sidebarWidth) }

# --- Launch #2 (restore) ---
$p2 = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.p2.err"
$root2=[IntPtr]::Zero; $dl2=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl2 -and $root2 -eq [IntPtr]::Zero -and -not $p2.HasExited){ Start-Sleep -Milliseconds 500; $root2 = FindRoot $p2.Id }
if($root2 -eq [IntPtr]::Zero){ W "P2_ROOT_NOT_FOUND"; if(-not $p2.HasExited){Stop-Process -Id $p2.Id -Force}; exit 4 }
Start-Sleep -Seconds 4
$r2=New-Object G54.Api+RECT; [void][G54.Api]::GetWindowRect($root2,[ref]$r2)
W ("RESTORED_RECT=({0},{1},{2},{3})" -f $r2.Left,$r2.Top,$r2.Right,$r2.Bottom)

# compare (allow small tolerance for OS chrome)
$ok = ([Math]::Abs($r2.Left-$r1.Left) -le 40 -and [Math]::Abs($r2.Top-$r1.Top) -le 40 -and ([Math]::Abs($r2.Right-$r2.Left) - $tw) -le 60)
W ("G54_RESTORE=" + $(if($ok){'PASS'}else{'FAIL'}))
[void][G54.Api]::PostMessage($root2,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
$null=$p2.WaitForExit(6000); if(-not $p2.HasExited){ Stop-Process -Id $p2.Id -Force -EA SilentlyContinue }
W "DONE"
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue