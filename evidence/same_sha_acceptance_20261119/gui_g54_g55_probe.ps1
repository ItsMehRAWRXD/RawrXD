param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g54_g55_result.txt"
)

# G54 (layout persistence) + G55 (Git menu) runtime check.
Add-Type -Namespace G55b -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern IntPtr GetMenu(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetMenuItemCount(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern IntPtr GetSubMenu(IntPtr h, int n);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern uint GetMenuItemID(IntPtr h, int n);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetMenuString(IntPtr h, uint id, System.Text.StringBuilder s, int n, uint flags);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

function W([string]$m){ Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$sess = Join-Path $env:APPDATA 'RawrXD\session.json'
Remove-Item $Result -Force -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.stderr.log"
$root=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited){
    Start-Sleep -Milliseconds 600
    $cb=[G55b.Api+EnumProc]{ param($h,$l) $p2=0; [void][G55b.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $proc.Id){ $c=New-Object System.Text.StringBuilder 128; [void][G55b.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G55b.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
if($root -eq [IntPtr]::Zero){ W "ROOT_NOT_FOUND"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }

Start-Sleep -Seconds 8
# G55: enumerate top-level menu item command IDs; Git IDs are 3020-3025
$menu = [G55b.Api]::GetMenu($root)
$top = [G55b.Api]::GetMenuItemCount($menu)
$found = @{}
for($i=0;$i -lt $top;$i++){
    $id = [G55b.Api]::GetMenuItemID($menu, $i)
    if($id -ge 3020 -and $id -le 3025){ $found[$id]=$true }
}
# Also check submenu items (Git menu submenu)
$gitPresent = $found.Count -gt 0
W ("GIT_CMD_IDS_FOUND=" + (($found.Keys | Sort-Object) -join ','))
W ("G55_GIT_MENU=" + $(if($gitPresent){'PASS'}else{'FAIL'}))

[void][G55b.Api]::PostMessage($root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$closed = $proc.WaitForExit(8000)
if(-not $closed){ Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
$hasSess = Test-Path $sess
W ("G54_SESSION_JSON=" + $(if($hasSess){'PASS'}else{'FAIL'}) + " size=" + $(if($hasSess){(Get-Item $sess).Length}else{0}))
W "DONE"
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue