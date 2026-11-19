param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [int]$StartupSec = 30,
    [int]$ExitWaitSec = 90,
    [string]$StderrPath = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui4_stderr.log",
    [string]$OutFile = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui4_diag.txt"
)

Add-Type -Namespace C -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetDlgCtrlID(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, IntPtr l, uint flags, uint ms, out IntPtr res);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOText(IntPtr h, uint m, IntPtr w, string l, uint flags, uint ms, out IntPtr res);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOGetText(IntPtr h, uint m, IntPtr w, System.Text.StringBuilder l, uint flags, uint ms, out IntPtr res);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

$flags = 0x12
$log = New-Object System.Collections.ArrayList
function L([string]$m) { [void]$log.Add($m); Write-Output $m }
function TO([IntPtr]$h, [uint32]$m) { $r=[IntPtr]::Zero; return [C.Api]::SendTO($h,$m,[IntPtr]::Zero,[IntPtr]::Zero,$flags,4000,[ref]$r) }
function ReadT([IntPtr]$h,[int]$cap=8000) {
    $sb = New-Object System.Text.StringBuilder $cap
    $r = [IntPtr]::Zero
    $o = [C.Api]::SendTOGetText($h, 0x000D, [IntPtr]$cap, $sb, $flags, 4000, [ref]$r)
    if ($o -eq [IntPtr]::Zero) { return "<no-reply>" }
    return $sb.ToString()
}

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force
Start-Sleep -Seconds 3
if (Test-Path $StderrPath) { Remove-Item $StderrPath -Force -ErrorAction SilentlyContinue }

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError $StderrPath `
    -Environment @{ RAWRXD_DEEP2_PROBE_MODEL = $Model }
$t0 = Get-Date
L "PID=$($proc.Id) LAUNCH_OK=$(-not $proc.HasExited)"

$root = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds($StartupSec)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited) {
    Start-Sleep -Milliseconds 500
    $cb = [C.Api+EnumProc]{
        param($h,$l)
        $p2=0; [void][C.Api]::GetWindowThreadProcessId($h,[ref]$p2)
        if ($p2 -eq $proc.Id) {
            $c=New-Object System.Text.StringBuilder 128
            [void][C.Api]::GetClassName($h,$c,128)
            if ($c.ToString() -like "RawrXD_IDE_Window*") { $script:root=$h }
        }
        return $true
    }
    [void][C.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
L "WINDOW_HWND=$root ALIVE=$(-not $proc.HasExited)"
if ($root -eq [IntPtr]::Zero) {
    if ($proc.HasExited) { L "EXIT_EARLY_CODE=$($proc.ExitCode)" }
    $log | Out-File $OutFile -Encoding utf8; exit 3
}

$script:ctrl=@{}
$ccb=[C.Api+EnumProc]{
    param($h,$l)
    $id=[C.Api]::GetDlgCtrlID($h)
    if (-not $script:ctrl.ContainsKey($id)) { $script:ctrl[$id]=$h }
    return $true
}
[void][C.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
$input=$script:ctrl[1203]; $send=$script:ctrl[1204]
L "CTRL input=$input send=$send"

# type + send
$r=[IntPtr]::Zero
[void][C.Api]::SendTOText($input,0x000C,[IntPtr]::Zero,"What is 2+2?",$flags,4000,[ref]$r)
Start-Sleep -Milliseconds 400
L "TYPED=[" + (ReadT $input 200) + "] ALIVE=$(-not $proc.HasExited)"
[void][C.Api]::SendTO($send,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero,$flags,4000,[ref]$r)
$tSend = Get-Date
L "SEND_AT=$($tSend.ToString('HH:mm:ss.fff'))"

# poll liveness + transcript for ExitWaitSec
$lastLen = 0
while (((Get-Date) - $tSend).TotalSeconds -lt $ExitWaitSec) {
    Start-Sleep -Milliseconds 1500
    if ($proc.HasExited) {
        L ("EXITED code={0} after={1:N1}s" -f $proc.ExitCode, ((Get-Date)-$tSend).TotalSeconds)
        break
    }
    $txt = ReadT $script:ctrl[1302] 200000
    $len = $txt.Length
    if ($len -ne $lastLen) {
        $tail = $txt
        if ($tail.Length -gt 400) { $tail = $tail.Substring($tail.Length - 400) }
        L ("TRANSCRIPT_LEN=$len at=$([int]((Get-Date)-$tSend).TotalSeconds)s TEXT=[" + $tail + "]")
        $lastLen = $len
    }
}
L "ALIVE_FINAL=$(-not $proc.HasExited)"
if ($proc.HasExited) { L "EXIT_CODE=$($proc.ExitCode) (0x{0:X8})" -f $proc.ExitCode }

L "---- TRANSCRIPT TAIL ----"
if ($script:ctrl.ContainsKey(1302)) {
    $tt = ReadT $script:ctrl[1302] 200000
    if ($tt.Length -gt 500) { $tt = $tt.Substring($tt.Length - 500) }
    L $tt
}

L "---- STDERR ----"
if (Test-Path $StderrPath) {
    foreach ($x in (Get-Content $StderrPath | Select-String -Pattern "BRIDGE_STREAM|BRIDGE_GEN|GEMV_TRACE|LW_GATE|error|Error" | Select-Object -Last 10)) { L $x.Line }
} else { L "STDERR_MISSING" }

L "---- WER ----"
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$t0.AddMinutes(-5) } -ErrorAction Stop |
        Where-Object { $_.Message -match ("\b" + $proc.Id + "\b") } | Select-Object -First 3
    if ($ev) { foreach ($e in $ev) { L ("WER {0} prov={1} :: {2}" -f $e.TimeCreated, $e.ProviderName, (($e.Message -replace "\s+"," "))) } }
    else { L "WER_NONE_FOR_PID" }
} catch { L "WER_QUERY_FAILED" }

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
$log | Out-File -FilePath $OutFile -Encoding utf8
Write-Output "OUT=$OutFile"