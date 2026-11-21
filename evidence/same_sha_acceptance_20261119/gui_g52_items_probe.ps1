param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g52_items_result.txt"
)
Add-Type -Namespace G52I -Name Api -MemberDefinition @'
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
function FindRoot([int]$procId){
    $script:root=[IntPtr]::Zero
    $cb=[G52I.Api+EnumProc]{ param($h,$l) $p2=0; [void][G52I.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $procId){ $c=New-Object System.Text.StringBuilder 128; [void][G52I.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G52I.Api]::EnumWindows($cb,[IntPtr]::Zero); return $script:root
}
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -EA SilentlyContinue
$env:RAWRXD_BUILD_DIR='F:\rawrxd\evidence\g52_fixture\invalid\build'
$env:RAWRXD_BUILD_TARGET='g52invalid'
$env:RAWRXD_USER_DATA_DIR='F:\rawrxd\evidence\g52_profile'

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.err"
$root=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited){ Start-Sleep -Milliseconds 500; $root=FindRoot $proc.Id }
if($root -eq [IntPtr]::Zero){ W "NO_ROOT"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }
Start-Sleep -Seconds 8
[void][G52I.Api]::PostMessage($root, 0x0111, [IntPtr]5001, [IntPtr]::Zero)
Start-Sleep -Seconds 40

# find list view 1312
$lv=[IntPtr]::Zero
$ccb=[G52I.Api+EnumProc]{ param($h,$l) if([G52I.Api]::GetDlgCtrlID($h) -eq 1312){ $c=New-Object System.Text.StringBuilder 64; [void][G52I.Api]::GetClassName($h,$c,64); if($c.ToString() -eq "SysListView32"){$script:lv=$h} }; return $true }
[void][G52I.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
if($lv -eq [IntPtr]::Zero){ W "NO_LISTVIEW"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 4 }

$r=[IntPtr]::Zero
$cnt=[G52I.Api]::SendTO($lv, 0x1004, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 4000, [ref]$r)
$count=$r.ToInt64()
W "PROBLEMS_COUNT=$count"

# read item text via LVM_GETITEMTEXT (0x1073) with LVITEM in unmanaged memory
for($k=0; $k -lt [Math]::Min($count,5); $k++){
    $buf=[Runtime.InteropServices.Marshal]::AllocHGlobal(2048)
    $lvitem=[Runtime.InteropServices.Marshal]::AllocHGlobal(64)
    try{
        [Runtime.InteropServices.Marshal]::WriteInt32($lvitem, 0, 1)          # mask=LVIF_TEXT
        [Runtime.InteropServices.Marshal]::WriteInt32($lvitem, 4, $k)         # iItem
        [Runtime.InteropServices.Marshal]::WriteInt32($lvitem, 8, 0)         # iSubItem
        [Runtime.InteropServices.Marshal]::WriteInt64($lvitem, 24, $buf.ToInt64())  # pszText
        [Runtime.InteropServices.Marshal]::WriteInt32($lvitem, 32, 1024)     # cchTextMax
        $rr=[IntPtr]::Zero
        [void][G52I.Api]::SendTO($lv, 0x1073, [IntPtr]::Zero, $lvitem, 0x12, 4000, [ref]$rr)
        $txt=[Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
        W ("ITEM[{0}]='{1}'" -f $k, $txt)
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($lvitem)
    }
}
[void][G52I.Api]::PostMessage($root,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
$null=$proc.WaitForExit(8000); if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Remove-Item Env:\RAWRXD_BUILD_DIR,Env:\RAWRXD_BUILD_TARGET,Env:\RAWRXD_USER_DATA_DIR -EA SilentlyContinue
W "DONE"