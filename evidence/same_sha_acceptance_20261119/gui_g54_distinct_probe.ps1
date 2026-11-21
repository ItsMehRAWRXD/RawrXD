param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g54_distinct_result.txt"
)
Add-Type -Namespace G54E -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool r);
public struct RECT { public int Left, Top, Right, Bottom; }
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@
function W([string]$m){ Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }
function FindRoot {
    $script:root=[IntPtr]::Zero
    $cb=[G54E.Api+EnumProc]{ param($h,$l) $p2=0; [void][G54E.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $script:targetPid){ $c=New-Object System.Text.StringBuilder 128; [void][G54E.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G54E.Api]::EnumWindows($cb,[IntPtr]::Zero); return $script:root
}
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -EA SilentlyContinue
$env:RAWRXD_USER_DATA_DIR='F:\rawrxd\evidence\g54_distinct_profile'
New-Item -ItemType Directory -Force $env:RAWRXD_USER_DATA_DIR | Out-Null
Remove-Item (Join-Path $env:RAWRXD_USER_DATA_DIR 'ide_session.json') -Force -EA SilentlyContinue

$p1 = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.p1.err"
$script:targetPid = $p1.Id
$r1=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $r1 -eq [IntPtr]::Zero -and -not $p1.HasExited){ Start-Sleep -Milliseconds 500; $r1=FindRoot }
if($r1 -eq [IntPtr]::Zero){ W "P1_NO_ROOT"; if(-not $p1.HasExited){Stop-Process -Id $p1.Id -Force}; exit 3 }
Start-Sleep -Seconds 6
[void][G54E.Api]::MoveWindow($r1,123,77,900,640,$true)
Start-Sleep -Seconds 2
$rc1=New-Object G54E.Api+RECT; [void][G54E.Api]::GetWindowRect($r1,[ref]$rc1)
W ("SET_RECT=({0},{1},{2},{3})" -f $rc1.Left,$rc1.Top,$rc1.Right,$rc1.Bottom)
[void][G54E.Api]::PostMessage($r1,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
$exited=$p1.WaitForExit(15000)
$code = if($exited){ $p1.ExitCode } else { "TIMEOUT" }
W ("P1_EXIT=$exited CODE=$code")

Start-Sleep -Seconds 2
$p2 = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.p2.err"
$script:targetPid = $p2.Id
$r2=[IntPtr]::Zero; $dl2=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl2 -and $r2 -eq [IntPtr]::Zero -and -not $p2.HasExited){ Start-Sleep -Milliseconds 500; $r2=FindRoot }
if($r2 -eq [IntPtr]::Zero){ W "P2_NO_ROOT"; if(-not $p2.HasExited){Stop-Process -Id $p2.Id -Force}; exit 4 }
Start-Sleep -Seconds 6
$rc2=New-Object G54E.Api+RECT; [void][G54E.Api]::GetWindowRect($r2,[ref]$rc2)
W ("RESTORED_RECT=({0},{1},{2},{3})" -f $rc2.Left,$rc2.Top,$rc2.Right,$rc2.Bottom)
$ok = ([Math]::Abs($rc2.Left-123) -le 40 -and [Math]::Abs($rc2.Top-77) -le 40 -and ([Math]::Abs(($rc2.Right-$rc2.Left)-900) -le 60))
W ("DISTINCT_RECT=" + $(if($ok){'PASS'}else{'FAIL'}))
[void][G54E.Api]::PostMessage($r2,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
$null=$p2.WaitForExit(8000); if(-not $p2.HasExited){ Stop-Process -Id $p2.Id -Force -EA SilentlyContinue }
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Remove-Item Env:\RAWRXD_USER_DATA_DIR -EA SilentlyContinue
W "DONE"