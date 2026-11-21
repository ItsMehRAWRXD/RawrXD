param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Log = "F:\rawrxd\evidence\same_sha_acceptance_20261119\model_probe3_stderr.log",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\model_probe3_result.txt",
    [int]$SettleSec = 18
)

Add-Type -Namespace MP3 -Name Api -MemberDefinition @'
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

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" -or $_.ProcessName -like "*RawrXD-Win32*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Log,$Result -Force -ErrorAction SilentlyContinue
Remove-Item Env:\RAWRXD_MODEL_PATH -ErrorAction SilentlyContinue
Remove-Item Env:\RAWRXD_P11_FORCE_OLLAMA_MODEL -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError $Log
W "PID=$($proc.Id)"

$root = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited) {
    Start-Sleep -Milliseconds 600
    $cb = [MP3.Api+EnumProc]{
        param($h,$l)
        $p2=0; [void][MP3.Api]::GetWindowThreadProcessId($h,[ref]$p2)
        if ($p2 -eq $proc.Id) {
            $c = New-Object System.Text.StringBuilder 128
            [void][MP3.Api]::GetClassName($h,$c,128)
            if ($c.ToString() -like "RawrXD_IDE_Window*") { $script:root = $h }
        }
        return $true
    }
    [void][MP3.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
W "HWND=$root"
if ($root -eq [IntPtr]::Zero) { W "RESULT=NO_WINDOW"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }

$combo = [IntPtr]::Zero
$ctrlDeadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ctrlDeadline -and $combo -eq [IntPtr]::Zero) {
    $ccb = [MP3.Api+EnumProc]{
        param($h,$l)
        if ([MP3.Api]::GetDlgCtrlID($h) -eq 1206) { $script:combo = $h }
        return $true
    }
    [void][MP3.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
    if ($combo -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 500 }
}
W "COMBO=$combo ID=$(if($combo -ne [IntPtr]::Zero){[MP3.Api]::GetDlgCtrlID($combo)}else{-1})"

function Get-ItemText([IntPtr]$h, [int]$index) {
    $cap = 1024
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($cap * 2)
    try {
        $r = [IntPtr]::Zero
        [void][MP3.Api]::SendTO($h, 0x0148, [IntPtr]$index, $buf, 0x12, 5000, [ref]$r)  # CB_GETLBTEXT
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
}

function Dump-Combo([string]$tag) {
    $r0 = [IntPtr]::Zero
    [void][MP3.Api]::SendTO($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 5000, [ref]$r0)  # CB_GETCOUNT
    $count = [int]$r0.ToInt64()
    [void][MP3.Api]::SendTO($combo, 0x0147, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 5000, [ref]$r0)  # CB_GETCURSEL
    $sel = [int]$r0.ToInt64()
    W ("$tag COUNT=$count CURSEL=$sel")
    $blank = 0
    $limit = [Math]::Min($count, 400)
    for ($k=0; $k -lt $limit; $k++) {
        $t = Get-ItemText $combo $k
        if ([string]::IsNullOrWhiteSpace($t)) { $blank++; W ("$tag BLANK at ITEM[$k]") }
    }
    W ("$tag BLANK_ITEMS=$blank enumerated=$limit of $count")
    # sample a few
    for ($k=0; $k -lt [Math]::Min($count,3); $k++) { W ("  $tag ITEM[$k]='" + (Get-ItemText $combo $k) + "'") }
}

Dump-Combo "EARLY"
W "SETTLING=${SettleSec}s"
Start-Sleep -Seconds $SettleSec
Dump-Combo "FINAL"

[void][MP3.Api]::PostMessage($root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$closed = $proc.WaitForExit(8000)
if (-not $closed) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
W "NATURAL_EXIT=$closed"
W "DONE"