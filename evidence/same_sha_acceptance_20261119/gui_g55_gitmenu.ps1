Add-Type -Namespace G55d -Name Api -MemberDefinition @"
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern IntPtr GetMenu(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetMenuItemCount(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern IntPtr GetSubMenu(IntPtr h, int n);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern uint GetMenuItemID(IntPtr h, int n);
public delegate bool EnumProc(IntPtr h, IntPtr p);
"@
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$proc = Start-Process -FilePath 'F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe' -PassThru -RedirectStandardError "$env:TEMP\g55.err"
$root=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited){
    Start-Sleep -Milliseconds 600
    $cb=[G55d.Api+EnumProc]{ param($h,$l) $p2=0; [void][G55d.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $proc.Id){ $c=New-Object System.Text.StringBuilder 128; [void][G55d.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G55d.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
if($root -eq [IntPtr]::Zero){ "ROOT_NOT_FOUND"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }
Start-Sleep -Seconds 8
$menu=[G55d.Api]::GetMenu($root); $top=[G55d.Api]::GetMenuItemCount($menu); $found=@()
for($i=0;$i -lt $top;$i++){
    $sub=[G55d.Api]::GetSubMenu($menu,$i)
    if($sub -ne [IntPtr]::Zero){
        $n=[G55d.Api]::GetMenuItemCount($sub)
        for($j=0;$j -lt $n;$j++){ $id=[G55d.Api]::GetMenuItemID($sub,$j); if($id -ge 3020 -and $id -le 3025){ $found+=$id } }
    }
}
"GIT_SUBMENU_IDS=" + (($found | Sort-Object) -join ',')
"G55_GIT_MENU=" + $(if($found.Count -gt 0){'PASS'}else{'FAIL'})
[void][G55d.Api]::PostMessage($root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$null=$proc.WaitForExit(6000); if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
"DONE"