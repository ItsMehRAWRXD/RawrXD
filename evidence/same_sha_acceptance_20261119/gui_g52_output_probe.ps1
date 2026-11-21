param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g52_output_result.txt"
)
Add-Type -Namespace G52O -Name Api -MemberDefinition @'
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
    $cb=[G52O.Api+EnumProc]{ param($h,$l) $p2=0; [void][G52O.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $proc.Id){ $c=New-Object System.Text.StringBuilder 128; [void][G52O.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G52O.Api]::EnumWindows($cb,[IntPtr]::Zero); return $script:root
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
[void][G52O.Api]::PostMessage($root, 0x0111, [IntPtr]5001, [IntPtr]::Zero)
Start-Sleep -Seconds 28

# read every RichEdit control's text and search for C2065/error
$found=0
$ecb=[G52O.Api+EnumProc]{
    param($h,$l)
    $c=New-Object System.Text.StringBuilder 64; [void][G52O.Api]::GetClassName($h,$c,64)
    if($c.ToString() -like "RichEdit*"){
        $cap=65536
        $buf=[Runtime.InteropServices.Marshal]::AllocHGlobal($cap*2)
        try{
            $rr=[IntPtr]::Zero
            $n=[G52O.Api]::SendTO($h, 0x000D, [IntPtr]$cap, $buf, 0x12, 5000, [ref]$rr)  # WM_GETTEXT
            if($n.ToInt64() -gt 0){
                $txt=[Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
                if($txt -match 'C2065|error C|undefined_symbol'){
                    $script:found++
                    Write-Output ("RICHEDIT id={0} match: {1}" -f [G52O.Api]::GetDlgCtrlID($h), ($txt -split "`n" | Where-Object { $_ -match 'C2065|error C|undefined_symbol' } | Select-Object -First 3))
                }
            }
        } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
    }
    return $true
}
[void][G52O.Api]::EnumChildWindows($root,$ecb,[IntPtr]::Zero)
W "RICHEDIT_MATCHES=$found"
[void][G52O.Api]::PostMessage($root,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
$null=$proc.WaitForExit(8000); if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Remove-Item Env:\RAWRXD_BUILD_DIR,Env:\RAWRXD_BUILD_TARGET,Env:\RAWRXD_USER_DATA_DIR -EA SilentlyContinue
W "DONE"