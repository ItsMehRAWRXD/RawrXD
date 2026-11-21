param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Fixture = "F:\rawrxd\evidence\g52_fixture\invalid",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g52_runtime_result.txt"
)
Add-Type -Namespace G52 -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetDlgCtrlID(IntPtr h);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint ms, out IntPtr r);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@
function W([string]$m){ Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -EA SilentlyContinue
$env:RAWRXD_USER_DATA_DIR = "F:\rawrxd\evidence\g52_profile"
New-Item -ItemType Directory -Force $env:RAWRXD_USER_DATA_DIR | Out-Null

$proc = Start-Process -FilePath $Exe -ArgumentList "--root", $Fixture -PassThru -RedirectStandardError "$Result.err"
$root=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited){
    Start-Sleep -Milliseconds 500
    $cb=[G52.Api+EnumProc]{ param($h,$l) $p2=0; [void][G52.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $proc.Id){ $c=New-Object System.Text.StringBuilder 128; [void][G52.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G52.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
W "ROOT=$root"
if($root -eq [IntPtr]::Zero){ W "NO_ROOT"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }
Start-Sleep -Seconds 8

# enumerate child windows (class + id + listview item count)
$rows=@()
$ecb=[G52.Api+EnumProc]{
    param($h,$l)
    $c=New-Object System.Text.StringBuilder 128; [void][G52.Api]::GetClassName($h,$c,128)
    $id=[G52.Api]::GetDlgCtrlID($h)
    $extra=""
    if($c.ToString() -eq "SysListView32"){
        $r=[IntPtr]::Zero
        $n=[G52.Api]::SendTO($h, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 3000, [ref]$r)  # LVM_GETITEMCOUNT
        $extra=" items=$($r.ToInt64())"
    }
    $script:rows += ("{0} id={1}{2}" -f $c.ToString(), $id, $extra)
    return $true
}
[void][G52.Api]::EnumChildWindows($root,$ecb,[IntPtr]::Zero)
W "CHILD_WINDOWS:"; $rows | ForEach-Object { W "  $_" }

# trigger build
W "SEND IDM_BUILD_COMPILE(5001)"
[void][G52.Api]::PostMessage($root, 0x0111, [IntPtr]5001, [IntPtr]::Zero)
Start-Sleep -Seconds 25

# re-enumerate list views
$rows2=@()
$ecb2=[G52.Api+EnumProc]{
    param($h,$l)
    $c=New-Object System.Text.StringBuilder 128; [void][G52.Api]::GetClassName($h,$c,128)
    if($c.ToString() -eq "SysListView32"){
        $r=[IntPtr]::Zero
        [void][G52.Api]::SendTO($h, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 3000, [ref]$r)
        $script:rows2 += ("id={0} items={1}" -f [G52.Api]::GetDlgCtrlID($h), $r.ToInt64())
    }
    return $true
}
[void][G52.Api]::EnumChildWindows($root,$ecb2,[IntPtr]::Zero)
W "LISTVIEWS_AFTER_BUILD:"; $rows2 | ForEach-Object { W "  $_" }

[void][G52.Api]::PostMessage($root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$null=$proc.WaitForExit(8000); if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
W "DONE"