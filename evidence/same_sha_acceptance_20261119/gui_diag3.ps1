param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [int]$StartupSec = 30,
    [int]$ObserveSec = 45,
    [string]$OutFile = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui3_diag.txt"
)

Add-Type -Namespace D -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetDlgCtrlID(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, IntPtr l, uint flags, uint ms, out IntPtr res);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOText(IntPtr h, uint m, IntPtr w, string l, uint flags, uint ms, out IntPtr res);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

$flags = 0x12
$log = New-Object System.Collections.ArrayList
function L([string]$m) { [void]$log.Add($m); Write-Output $m }
function TO([IntPtr]$h, [uint32]$m) {
    $r = [IntPtr]::Zero
    return [D.Api]::SendTO($h, $m, [IntPtr]::Zero, [IntPtr]::Zero, $flags, 4000, [ref]$r)
}
function TT([IntPtr]$h, [string]$s) {
    $r = [IntPtr]::Zero
    return [D.Api]::SendTOText($h, 0x000C, [IntPtr]::Zero, $s, $flags, 4000, [ref]$r)
}

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force
Start-Sleep -Seconds 3
L "PRE_KILL_DONE alive=$((Get-Process | Where-Object { $_.ProcessName -like '*Win32IDE*' } | Measure-Object).Count)"

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui3_stderr.log" `
    -Environment @{ RAWRXD_DEEP2_PROBE_MODEL = $Model }
L "PID=$($proc.Id) START"

$root = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds($StartupSec)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero) {
    Start-Sleep -Milliseconds 500
    if ($proc.HasExited) { break }
    $cb = [D.Api+EnumProc]{
        param($h, $l)
        $pid2 = 0
        [void][D.Api]::GetWindowThreadProcessId($h, [ref]$pid2)
        if ($pid2 -eq $proc.Id) {
            $cls = New-Object System.Text.StringBuilder 128
            [void][D.Api]::GetClassName($h, $cls, 128)
            if ($cls.ToString() -like "RawrXD_IDE_Window*") { $script:root = $h }
        }
        return $true
    }
    [void][D.Api]::EnumWindows($cb, [IntPtr]::Zero)
}
L "ALIVE_AFTER_WINDOW=$(-not $proc.HasExited) HWND=$root"
if ($root -eq [IntPtr]::Zero) {
    if ($proc.HasExited) { L "EXIT_CODE_EARLY=$($proc.ExitCode)" }
    $log | Out-File $OutFile -Encoding utf8; exit 3
}

$script:ctrl = @{}
$ccb = [D.Api+EnumProc]{
    param($h, $l)
    $id = [D.Api]::GetDlgCtrlID($h)
    if (-not $script:ctrl.ContainsKey($id)) { $script:ctrl[$id] = $h }
    return $true
}
[void][D.Api]::EnumChildWindows($root, $ccb, [IntPtr]::Zero)
$combo = $script:ctrl[1206]; $input = $script:ctrl[1203]; $send = $script:ctrl[1204]

L "CB_GETCOUNT=$(TO $combo 0x0146)"
L "CB_GETCURSEL=$(TO $combo 0x0147)"
for ($i = 0; $i -lt 4; $i++) { L "CB_GETITEMDATA[$i]=$(TO $combo 0x0150)" }
L "ALIVE_BEFORE_SELECT=$(-not $proc.HasExited)"

if ($combo -ne $null -and $combo -ne [IntPtr]::Zero) {
    [void][D.Api]::SendTO($combo, 0x014E, [IntPtr]0, [IntPtr]::Zero, $flags, 4000, [ref]([IntPtr]::Zero))
    [void][D.Api]::SendTO($root, 0x0111, [IntPtr]0x0356, [IntPtr]::Zero, $flags, 4000, [ref]([IntPtr]::Zero))
    Start-Sleep -Seconds 5
    L "CB_GETCURSEL_AFTER=$(TO $combo 0x0147)"
    L "ALIVE_AFTER_SELECT=$(-not $proc.HasExited)"
}

$null = TT $input "What is 2+2?"
Start-Sleep -Milliseconds 500
L "ALIVE_BEFORE_SEND=$(-not $proc.HasExited)"
[void][D.Api]::SendTO($send, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero, $flags, 4000, [ref]([IntPtr]::Zero))
L "SENT"

$deadline = (Get-Date).AddSeconds($ObserveSec)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if ($proc.HasExited) { L "ALIVE_AFTER_SEND=0 EXIT_CODE=$($proc.ExitCode)"; break }
    L "ALIVE_AFTER_SEND=1 t=$([int]((Get-Date) - $deadline).TotalSeconds)"
}

L "FINAL_ALIVE=$(-not $proc.HasExited)"
if ($proc.HasExited) { L "FINAL_EXIT_CODE=$($proc.ExitCode)" }
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }

L "---- WER ----"
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction Stop |
        Where-Object { $_.Message -match "$($proc.Id)" -or $_.ProviderName -match "Application Error|Windows Error Reporting" } |
        Select-Object -First 4
    foreach ($e in $ev) { L ("WER {0} {1}" -f $e.TimeCreated, ($e.Message -replace "\s+", " ").Substring(0, [Math]::Min(300, $e.Message.Length))) }
    if (-not $ev) { L "WER_NONE" }
} catch { L "WER_QUERY_FAILED" }

$log | Out-File -FilePath $OutFile -Encoding utf8
Write-Output "OUT=$OutFile"