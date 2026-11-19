param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [int]$ProbeCmd = 9614,
    [int]$TimeoutSec = 300,
    [string]$ReceiptDir = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119",
    [string]$StderrPath = ""
)

$ErrorActionPreference = "Stop"

Add-Type -Namespace Win32 -Name Probe -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
[DllImport("user32.dll", SetLastError = true)]
public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
[DllImport("user32.dll")]
public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
[DllImport("user32.dll")]
public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
[DllImport("user32.dll")]
public static extern bool IsWindowVisible(IntPtr hWnd);
'@

$log = "F:\rawrxd\evidence\TOP25_C08_C09_DEEP2.log"
$resp = "F:\rawrxd\evidence\TOP25_C08_C09_DEEP2_RESPONSE.txt"
Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $resp -ErrorAction SilentlyContinue

$env:RAWRXD_DEEP2_PROBE_MODEL = $Model
$env:RAWRXD_CHAT_SESSION_ID = "deep2probe-" + (Get-Date -Format "yyyyMMddHHmmss")

$startArgs = @{
    FilePath = $Exe
    PassThru = $true
    Environment = @{
        RAWRXD_DEEP2_PROBE_MODEL = $Model
        DEEP2_GPU_FORWARD_TRACE = '1'
    RAWRXD_GPU_POLICY = 'SOLO'
    }
}
if ($StderrPath -ne "") { $startArgs.RedirectStandardError = $StderrPath }
$proc = Start-Process @startArgs
Write-Output "PID=$($proc.Id) MODEL=$Model"

$hwnd = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline -and $hwnd -eq [IntPtr]::Zero) {
    Start-Sleep -Milliseconds 500
    $p = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if (-not $p) { break }
    if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $hwnd = $p.MainWindowHandle }
}
if ($hwnd -eq [IntPtr]::Zero) {
    # fall back to enumeration by pid
    $targetPid = $proc.Id
    $found = [IntPtr]::Zero
    $cb = [Win32.Probe+EnumWindowsProc]{
        param($h, $l)
        $pid2 = 0
        [void][Win32.Probe]::GetWindowThreadProcessId($h, [ref]$pid2)
        if ($pid2 -eq $targetPid -and [Win32.Probe]::IsWindowVisible($h)) {
            $sb = New-Object System.Text.StringBuilder 512
            [void][Win32.Probe]::GetWindowText($h, $sb, 512)
            if ($sb.Length -gt 0) { $script:found = $h }
        }
        return $true
    }
    [void][Win32.Probe]::EnumWindows($cb, [IntPtr]::Zero)
    $hwnd = $found
}
Write-Output "HWND=$hwnd"

if ($hwnd -eq [IntPtr]::Zero) {
    Write-Output "RESULT=NO_WINDOW"
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    exit 3
}

# WM_COMMAND = 0x0111, wParam = probe menu id
$posted = [Win32.Probe]::PostMessage($hwnd, 0x0111, [IntPtr]$ProbeCmd, [IntPtr]::Zero)
Write-Output "POSTED=$posted CMD=$ProbeCmd"

$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
    if (Test-Path $log) {
        $txt = Get-Content -LiteralPath $log -Raw
        # The BEGIN line also contains "gen=0"; wait for the terminal line
        # which starts with init= and carries model_info=.
        if ($txt -match "(?m)^init=\d+ load=\d+ gen=\d+ .*model_info=") { break }
    }
    Start-Sleep -Seconds 2
}

Start-Sleep -Seconds 2
Write-Output "---- LOG ----"
if (Test-Path $log) { Get-Content -LiteralPath $log -Raw } else { Write-Output "MISSING" }
Write-Output "---- RESPONSE ----"
if (Test-Path $resp) { Get-Content -LiteralPath $resp -Raw } else { Write-Output "MISSING" }

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
Write-Output "DONE"
