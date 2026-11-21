param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Profile = "F:\rawrxd\evidence\g54_seed_profile",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g54_seed_result.txt"
)
Add-Type -Namespace G54S -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
public struct RECT { public int Left, Top, Right, Bottom; }
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@
function W([string]$m){ Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Profile | Out-Null

# seed a known window geometry (normal rect 123,77,900x640)
$seed = '{"version":2,"schemaVersion":"2.2","window":{"x":123,"y":77,"width":900,"height":640,"maximized":false},"panel":{"sidebarWidth":250,"sidebarVisible":true},"theme":"dark"}'
Set-Content -LiteralPath (Join-Path $Profile 'ide_session.json') -Value $seed -Encoding utf8
W "SEEDED=$seed"

$env:RAWRXD_USER_DATA_DIR = $Profile
$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.err"
$script:target = $proc.Id
$root=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited){
    Start-Sleep -Milliseconds 500
    $cb=[G54S.Api+EnumProc]{ param($h,$l) $p2=0; [void][G54S.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $script:target){ $c=New-Object System.Text.StringBuilder 128; [void][G54S.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G54S.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
if($root -eq [IntPtr]::Zero){ W "NO_ROOT"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }
Start-Sleep -Seconds 8
$r=New-Object G54S.Api+RECT; [void][G54S.Api]::GetWindowRect($root,[ref]$r)
W ("RESTORED_RECT=({0},{1},{2},{3})" -f $r.Left,$r.Top,$r.Right,$r.Bottom)
$ok = ([Math]::Abs($r.Left-123) -le 40 -and [Math]::Abs($r.Top-77) -le 40 -and ([Math]::Abs(($r.Right-$r.Left)-900) -le 60) -and ([Math]::Abs(($r.Bottom-$r.Top)-640) -le 60))
W ("G54_SEED_RESTORE=" + $(if($ok){'PASS'}else{'FAIL'}))
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Remove-Item Env:\RAWRXD_USER_DATA_DIR -EA SilentlyContinue
W "DONE"