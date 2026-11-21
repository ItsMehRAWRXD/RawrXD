param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Profile = "F:\rawrxd\evidence\g54_profile",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g54_max_result.txt"
)
Add-Type -Namespace G54M -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
[DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr h);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@
function W([string]$m){ Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }
function FindRoot([int]$procId){
    $script:root=[IntPtr]::Zero
    $cb=[G54M.Api+EnumProc]{ param($h,$l) $p2=0; [void][G54M.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $procId){ $c=New-Object System.Text.StringBuilder 128; [void][G54M.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G54M.Api]::EnumWindows($cb,[IntPtr]::Zero); return $script:root
}
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -EA SilentlyContinue
New-Item -ItemType Directory -Force $Profile | Out-Null
Remove-Item (Join-Path $Profile 'ide_session.json') -Force -EA SilentlyContinue
$env:RAWRXD_USER_DATA_DIR = $Profile
$sess = Join-Path $Profile 'ide_session.json'

# launch 1
$p1 = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.p1.err"
$r1=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl -and $r1 -eq [IntPtr]::Zero -and -not $p1.HasExited){ Start-Sleep -Milliseconds 500; $r1=FindRoot $p1.Id }
W "ROOT1=$r1 PID1=$($p1.Id)"
if($r1 -eq [IntPtr]::Zero){ W "NO_ROOT1"; if(-not $p1.HasExited){Stop-Process -Id $p1.Id -Force}; exit 3 }
Start-Sleep -Seconds 6
[void][G54M.Api]::ShowWindow($r1, 3)
Start-Sleep -Seconds 3
W ("MAXIMIZED1=" + [G54M.Api]::IsZoomed($r1))
$sw=[Diagnostics.Stopwatch]::StartNew()
[void][G54M.Api]::PostMessage($r1, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$exited = $p1.WaitForExit(30000)
$sw.Stop()
W ("EXITED=$exited EXITCODE=" + $(if($exited){$p1.ExitCode}else{'n/a'}) + " ELAPSED_MS=" + $sw.ElapsedMilliseconds)
Start-Sleep -Seconds 2
if(Test-Path $sess){ $j=Get-Content $sess -Raw | ConvertFrom-Json; W ("SAVED_MAX=" + $(if($j.window){$j.window.maximized}else{'no-key'})) } else { W "NO_SESSION" }
W "---- [G54] stderr ----"
if(Test-Path "$Result.p1.err"){ Select-String -LiteralPath "$Result.p1.err" -Pattern '\[G54\]' | ForEach-Object { $_.Line } }

# launch 2
$p2 = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.p2.err"
$r2=[IntPtr]::Zero; $dl2=(Get-Date).AddSeconds(40)
while((Get-Date) -lt $dl2 -and $r2 -eq [IntPtr]::Zero -and -not $p2.HasExited){ Start-Sleep -Milliseconds 500; $r2=FindRoot $p2.Id }
W "ROOT2=$r2 PID2=$($p2.Id)"
if($r2 -ne [IntPtr]::Zero){ Start-Sleep -Seconds 6; W ("MAXIMIZED2=" + [G54M.Api]::IsZoomed($r2)); [void][G54M.Api]::PostMessage($r2,0x0010,[IntPtr]::Zero,[IntPtr]::Zero); $null=$p2.WaitForExit(10000); if(-not $p2.HasExited){Stop-Process -Id $p2.Id -Force -EA SilentlyContinue} }
Remove-Item Env:\RAWRXD_USER_DATA_DIR -EA SilentlyContinue
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
W "DONE"