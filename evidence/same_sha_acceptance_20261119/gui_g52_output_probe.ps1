param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g52_output_result.txt"
)
Add-Type -Namespace G52P -Name Api -MemberDefinition @'
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
    $cb=[G52P.Api+EnumProc]{ param($h,$l) $p2=0; [void][G52P.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $proc.Id){ $c=New-Object System.Text.StringBuilder 128; [void][G52P.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G52P.Api]::EnumWindows($cb,[IntPtr]::Zero); return $script:root
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
[void][G52P.Api]::PostMessage($root, 0x0111, [IntPtr]5001, [IntPtr]::Zero)
Start-Sleep -Seconds 28

$script:found=0
$ecb=[G52P.Api+EnumProc]{
    param($h,$l)
    $c=New-Object System.Text.StringBuilder 64; [void][G52P.Api]::GetClassName($h,$c,64)
    if($c.ToString() -like "RichEdit*"){
        $cap=65536
        $buf=[Runtime.InteropServices.Marshal]::AllocHGlobal($cap*2)
        try{
            $rr=[IntPtr]::Zero
            $n=[G52P.Api]::SendTO($h, 0x000D, [IntPtr]$cap, $buf, 0x12, 5000, [ref]$rr)
            if($n.ToInt64() -gt 0){
                $txt=[Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
                $lines = $txt -split "`r?`n" | Where-Object { $_ -match 'C2065|error C|undefined_symbol' }
                if($lines){
                    $script:found++
                    Add-Content -LiteralPath $Result -Value ("MATCH id=" + [G52P.Api]::GetDlgCtrlID($h) + " :: " + (($lines | Select-Object -First 3) -join ' || ')) -Encoding utf8
                }
            }
        } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
    }
    return $true
}
[void][G52P.Api]::EnumChildWindows($root,$ecb,[IntPtr]::Zero)
W "RICHEDIT_MATCHES=$script:found"
[void][G52P.Api]::PostMessage($root,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
$null=$proc.WaitForExit(8000); if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Remove-Item Env:\RAWRXD_BUILD_DIR,Env:\RAWRXD_BUILD_TARGET,Env:\RAWRXD_USER_DATA_DIR -EA SilentlyContinue
W "DONE"