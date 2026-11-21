param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Profile = "F:\rawrxd\evidence\g54_profile",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\g54_profile_result.txt"
)

Add-Type -Namespace G54P -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr h);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
public struct RECT { public int Left, Top, Right, Bottom; }
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

function W([string]$m){ Write-Output $m; Add-Content -LiteralPath $Result -Value $m -Encoding utf8 }
function FindRoot([int]$procId){
    $script:root=[IntPtr]::Zero
    $cb=[G54P.Api+EnumProc]{ param($h,$l) $p2=0; [void][G54P.Api]::GetWindowThreadProcessId($h,[ref]$p2); if($p2 -eq $procId){ $c=New-Object System.Text.StringBuilder 128; [void][G54P.Api]::GetClassName($h,$c,128); if($c.ToString() -like "RawrXD_IDE_Window*"){$script:root=$h} }; return $true }
    [void][G54P.Api]::EnumWindows($cb,[IntPtr]::Zero); return $script:root
}
function Launch([string]$tag){
    $p = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.$tag.err"
    $r=[IntPtr]::Zero; $dl=(Get-Date).AddSeconds(40)
    while((Get-Date) -lt $dl -and $r -eq [IntPtr]::Zero -and -not $p.HasExited){ Start-Sleep -Milliseconds 500; $r = FindRoot $p.Id }
    return @{ proc=$p; root=$r }
}

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Profile | Out-Null
Remove-Item (Join-Path $Profile 'ide_session.json') -Force -ErrorAction SilentlyContinue
$env:RAWRXD_USER_DATA_DIR = $Profile
$sess = Join-Path $Profile 'ide_session.json'
W "PROFILE=$Profile"
W "SESSION=$sess"

# ---- normal: set rect, close, verify session ----
$a = Launch "n1"
if($a.root -eq [IntPtr]::Zero){ W "N1_NO_ROOT"; if(-not $a.proc.HasExited){Stop-Process -Id $a.proc.Id -Force}; exit 3 }
Start-Sleep -Seconds 6
$r1=New-Object G54P.Api+RECT; [void][G54P.Api]::GetWindowRect($a.root,[ref]$r1)
W ("SET_RECT=({0},{1},{2},{3})" -f $r1.Left,$r1.Top,$r1.Right,$r1.Bottom)
[void][G54P.Api]::PostMessage($a.root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$null=$a.proc.WaitForExit(12000)
$exit1 = if($a.proc.HasExited){ $a.proc.ExitCode } else { "TIMEOUT" }
W ("N1_EXIT=$exit1")
Start-Sleep -Seconds 2
if(Test-Path $sess){
    $j = Get-Content $sess -Raw | ConvertFrom-Json
    if($j.window){ W ("SAVED_WINDOW x={0} y={1} w={2} h={3} max={4}" -f $j.window.x,$j.window.y,$j.window.width,$j.window.height,$j.window.maximized) }
    else { W "SAVED_NO_WINDOW_KEY keys=" + (($j.PSObject.Properties.Name) -join ',') }
} else { W "NO_SESSION_FILE" }

# ---- relaunch: verify restore ----
$b = Launch "n2"
if($b.root -eq [IntPtr]::Zero){ W "N2_NO_ROOT"; if(-not $b.proc.HasExited){Stop-Process -Id $b.proc.Id -Force}; exit 4 }
Start-Sleep -Seconds 6
$r2=New-Object G54P.Api+RECT; [void][G54P.Api]::GetWindowRect($b.root,[ref]$r2)
W ("RESTORED_RECT=({0},{1},{2},{3})" -f $r2.Left,$r2.Top,$r2.Right,$r2.Bottom)
$ok = ([Math]::Abs($r2.Left-$r1.Left) -le 40 -and [Math]::Abs($r2.Top-$r1.Top) -le 40 -and ([Math]::Abs(($r2.Right-$r2.Left)-($r1.Right-$r1.Left)) -le 60))
W ("NORMAL_RESTORE=" + $(if($ok){'PASS'}else{'FAIL'}))
[void][G54P.Api]::PostMessage($b.root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$null=$b.proc.WaitForExit(8000); if(-not $b.proc.HasExited){ Stop-Process -Id $b.proc.Id -Force -EA SilentlyContinue }

# ---- maximized: maximize, close, relaunch, verify zoomed + unmaximize rect ----
Remove-Item $sess -Force -ErrorAction SilentlyContinue
$c = Launch "m1"
if($c.root -eq [IntPtr]::Zero){ W "M1_NO_ROOT"; if(-not $c.proc.HasExited){Stop-Process -Id $c.proc.Id -Force}; exit 5 }
Start-Sleep -Seconds 6
[void][G54P.Api]::ShowWindow($c.root, 3)  # SW_MAXIMIZE
Start-Sleep -Seconds 2
W ("M1_ZOOMED=" + [G54P.Api]::IsZoomed($c.root))
[void][G54P.Api]::PostMessage($c.root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$null=$c.proc.WaitForExit(12000); if(-not $c.proc.HasExited){ Stop-Process -Id $c.proc.Id -Force -EA SilentlyContinue }
Start-Sleep -Seconds 2
if(Test-Path $sess){ $j2=Get-Content $sess -Raw | ConvertFrom-Json; W ("M1_SAVED_MAX=" + $(if($j2.window){$j2.window.maximized}else{'no-key'})) }
$d = Launch "m2"
if($d.root -eq [IntPtr]::Zero){ W "M2_NO_ROOT"; if(-not $d.proc.HasExited){Stop-Process -Id $d.proc.Id -Force}; exit 6 }
Start-Sleep -Seconds 6
W ("M2_ZOOMED=" + [G54P.Api]::IsZoomed($d.root))
[void][G54P.Api]::ShowWindow($d.root, 9)  # SW_RESTORE
Start-Sleep -Seconds 1
$r3=New-Object G54P.Api+RECT; [void][G54P.Api]::GetWindowRect($d.root,[ref]$r3)
W ("M2_RESTORE_RECT=({0},{1},{2},{3})" -f $r3.Left,$r3.Top,$r3.Right,$r3.Bottom)
$maxOk = [G54P.Api]::IsZoomed($d.root)
W ("MAXIMIZED_RESTORE=" + $(if($maxOk){'PASS'}else{'FAIL'}))
[void][G54P.Api]::PostMessage($d.root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$null=$d.proc.WaitForExit(8000); if(-not $d.proc.HasExited){ Stop-Process -Id $d.proc.Id -Force -EA SilentlyContinue }

Remove-Item Env:\RAWRXD_USER_DATA_DIR -ErrorAction SilentlyContinue
Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -EA SilentlyContinue
W "DONE"