param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Rawr = "F:\rawrxd\build\bin-msvc\Release\rawr.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\backend_restore_result.txt"
)

# Sprint 7A: verify the IDE restores the persisted backend from the portable
# preference store for all three values. Uses the corrected out-param message
# read (transport success separate from result).

Add-Type -Namespace G7 -Name Api -MemberDefinition @'
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

function W([string]$m) { Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }
function SendMsg([IntPtr]$h,[uint32]$m){ $r=[IntPtr]::Zero; $ok=[G7.Api]::SendTO($h,$m,[IntPtr]::Zero,[IntPtr]::Zero,0x12,5000,[ref]$r); if($ok -eq [IntPtr]::Zero){throw "transport fail"}; return $r }

Remove-Item $Result -Force -ErrorAction SilentlyContinue
Remove-Item Env:\RAWRXD_BACKEND -ErrorAction SilentlyContinue
Remove-Item Env:\RAWRXD_CHAT_BACKEND -ErrorAction SilentlyContinue
Remove-Item Env:\RAWRXD_MODEL_PATH -ErrorAction SilentlyContinue

$cases = @(@('deep2',0), @('strata',1), @('ollama',2))
$allPass = $true
foreach ($c in $cases) {
    $backend = $c[0]; $expect = $c[1]
    # persist via the shared resolver (portable store)
    & $Rawr backend select $backend *> $null
    Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
    $proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.$backend.stderr.log"
    $root=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
    while((Get-Date) -lt $dl -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited){
        Start-Sleep -Milliseconds 500
        $cb=[G7.Api+EnumProc]{ param($h,$l) $p2=0; [void][G7.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $proc.Id){ $cc=New-Object System.Text.StringBuilder 128; [void][G7.Api]::GetClassName($h,$cc,128); if($cc.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
        [void][G7.Api]::EnumWindows($cb,[IntPtr]::Zero)
    }
    $combo=[IntPtr]::Zero; $cd=(Get-Date).AddSeconds(25)
    while((Get-Date) -lt $cd -and $combo -eq [IntPtr]::Zero){
        $ccb=[G7.Api+EnumProc]{ param($h,$l) if([G7.Api]::GetDlgCtrlID($h) -eq 1226){$script:combo=$h}; return $true }
        [void][G7.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
        if($combo -eq [IntPtr]::Zero){ Start-Sleep -Milliseconds 500 }
    }
    if($combo -eq [IntPtr]::Zero){ W "backend=$backend RESULT=NO_1226"; $allPass=$false; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; continue }
    $count = (SendMsg $combo 0x0146).ToInt64()
    $sel = (SendMsg $combo 0x0147).ToInt64()
    $ok = ($count -eq 3 -and $sel -eq $expect)
    if(-not $ok){ $allPass=$false }
    W ("backend={0} persisted={1} COUNT={2} CURSEL={3} expect={4} => {5}" -f $backend,$backend,$count,$sel,$expect,$(if($ok){'PASS'}else{'FAIL'}))
    [void][G7.Api]::PostMessage($root,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
    $closed=$proc.WaitForExit(6000); if(-not $closed){ Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}
W ("GUI_RESTORE_ALL=" + $(if($allPass){'PASS'}else{'FAIL'}))
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
W "DONE"