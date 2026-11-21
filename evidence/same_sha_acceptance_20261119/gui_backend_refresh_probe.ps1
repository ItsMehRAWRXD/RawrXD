param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Rawr = "F:\rawrxd\build\bin-msvc\Release\rawr.exe",
    [string]$Backend = "strata",
    [int]$ExpectSel = 1,
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\backend_refresh_result.txt"
)

# Sprint 7C: backend refresh stability. Read 1226, exercise a selection/refresh
# cycle (CBN_SELCHANGE + CB_SETCURSEL same index), then re-read. PASS requires
# three entries, unchanged selection and zero blank items before and after.

Add-Type -Namespace G7R -Name Api -MemberDefinition @'
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
function SendMsg([IntPtr]$h,[uint32]$m,[IntPtr]$w,[IntPtr]$l){ $r=[IntPtr]::Zero; $ok=[G7R.Api]::SendTO($h,$m,$w,$l,0x12,5000,[ref]$r); if($ok -eq [IntPtr]::Zero){throw "transport fail"}; return $r }
function Get-ItemText([IntPtr]$h,[int]$i){ $b=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024*2); try{ $r=[IntPtr]::Zero; [void][G7R.Api]::SendTO($h,0x0148,[IntPtr]$i,$b,0x12,5000,[ref]$r); return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($b) } finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($b) } }

Remove-Item $Result -Force -ErrorAction SilentlyContinue
Remove-Item Env:\RAWRXD_BACKEND -ErrorAction SilentlyContinue
Remove-Item Env:\RAWRXD_CHAT_BACKEND -ErrorAction SilentlyContinue
& $Rawr backend select $Backend *> $null

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800
$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.stderr.log"
$root=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited){
    Start-Sleep -Milliseconds 500
    $cb=[G7R.Api+EnumProc]{ param($h,$l) $p2=0; [void][G7R.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $proc.Id){ $cc=New-Object System.Text.StringBuilder 128; [void][G7R.Api]::GetClassName($h,$cc,128); if($cc.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G7R.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
$combo=[IntPtr]::Zero; $cd=(Get-Date).AddSeconds(25)
while((Get-Date) -lt $cd -and $combo -eq [IntPtr]::Zero){
    $ccb=[G7R.Api+EnumProc]{ param($h,$l) if([G7R.Api]::GetDlgCtrlID($h) -eq 1226){$script:combo=$h}; return $true }
    [void][G7R.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
    if($combo -eq [IntPtr]::Zero){ Start-Sleep -Milliseconds 500 }
}
if($combo -eq [IntPtr]::Zero){ W "RESULT=NO_1226"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }

function Read-State([string]$tag){
    $count=(SendMsg $combo 0x0146 ([IntPtr]::Zero) ([IntPtr]::Zero)).ToInt64()
    $sel=(SendMsg $combo 0x0147 ([IntPtr]::Zero) ([IntPtr]::Zero)).ToInt64()
    $blank=0; for($k=0;$k -lt $count;$k++){ if([string]::IsNullOrWhiteSpace((Get-ItemText $combo $k))){$blank++} }
    $line = ("{0} COUNT={1} CURSEL={2} BLANK={3}" -f $tag,$count,$sel,$blank)
    Write-Host $line
    Add-Content -LiteralPath $Result -Value $line -Encoding utf8
    return @($count,$sel,$blank)
}

Start-Sleep -Seconds 12   # let async discovery settle
$a = Read-State "BEFORE"
# refresh cycle: selection notification + reselect same index
$rr=[IntPtr]::Zero
[void][G7R.Api]::SendTO($root, 0x0111, [IntPtr](((1 -shl 16) -bor 1226)), $combo, 0x12, 5000, [ref]$rr)
$rr=[IntPtr]::Zero
[void][G7R.Api]::SendTO($combo, 0x014E, [IntPtr]$ExpectSel, [IntPtr]::Zero, 0x12, 5000, [ref]$rr)
Start-Sleep -Seconds 3
$b = Read-State "AFTER"

$stable = ($a[0] -eq 3 -and $a[1] -eq $ExpectSel -and $a[2] -eq 0 -and $b[0] -eq 3 -and $b[1] -eq $ExpectSel -and $b[2] -eq 0)
W ("REFRESH_STABLE=" + $(if($stable){'PASS'}else{'FAIL'}))
[void][G7R.Api]::PostMessage($root,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
$closed=$proc.WaitForExit(6000); if(-not $closed){ Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
W "DONE"