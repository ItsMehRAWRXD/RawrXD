param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [string[]]$Prompts = @("What is 2+2?", "Name one color."),
    [int]$StartupSec = 30,
    [int]$ReplyTimeoutSec = 120,
    [int]$MsgTimeoutMs = 4000,
    [string]$StderrPath = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui2_stderr.log",
    [string]$OutFile = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui2_result.txt"
)

Add-Type -Namespace W -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetDlgCtrlID(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, IntPtr l, uint flags, uint ms, out IntPtr res);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOGetText(IntPtr h, uint m, IntPtr w, System.Text.StringBuilder l, uint flags, uint ms, out IntPtr res);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOText(IntPtr h, uint m, IntPtr w, string l, uint flags, uint ms, out IntPtr res);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

$SMTO_ABORTIFHUNG = 0x2
$SMTO_ERRORONFAIL = 0x10
$flags = $SMTO_ABORTIFHUNG -bor $SMTO_ERRORONFAIL
$log = New-Object System.Collections.ArrayList
function L([string]$m) { [void]$log.Add($m); Write-Output $m }

function Send-Timeout([IntPtr]$h, [uint32]$m, [IntPtr]$w, [IntPtr]$l) {
    $res = [IntPtr]::Zero
    $out = [W.Api]::SendTO($h, $m, $w, $l, $flags, $MsgTimeoutMs, [ref]$res)
    return $out
}
function Send-Text([IntPtr]$h, [uint32]$m, [string]$s) {
    $res = [IntPtr]::Zero
    $out = [W.Api]::SendTOText($h, $m, [IntPtr]::Zero, $s, $flags, $MsgTimeoutMs, [ref]$res)
    return $out
}
function Read-Text([IntPtr]$h, [int]$cap = 200000) {
    $sb = New-Object System.Text.StringBuilder $cap
    $res = [IntPtr]::Zero
    $out = [W.Api]::SendTOGetText($h, 0x000D, [IntPtr]$cap, $sb, $flags, $MsgTimeoutMs, [ref]$res)
    if ($out -eq [IntPtr]::Zero) { return "<no-reply>" }
    return $sb.ToString()
}

Get-Process llama-server -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $StderrPath) { Remove-Item $StderrPath -Force -ErrorAction SilentlyContinue }

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError $StderrPath `
    -Environment @{ RAWRXD_DEEP2_PROBE_MODEL = $Model }
L "PID=$($proc.Id)"
L "MODEL=$Model"

# ---- resolve main window ----
$root = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds($StartupSec)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero) {
    Start-Sleep -Milliseconds 600
    $cb = [W.Api+EnumProc]{
        param($h, $l)
        $pid2 = 0
        [void][W.Api]::GetWindowThreadProcessId($h, [ref]$pid2)
        if ($pid2 -eq $proc.Id) {
            $cls = New-Object System.Text.StringBuilder 128
            [void][W.Api]::GetClassName($h, $cls, 128)
            if ($cls.ToString() -like "RawrXD_IDE_Window*") { $script:root = $h }
        }
        return $true
    }
    [void][W.Api]::EnumWindows($cb, [IntPtr]::Zero)
}
if ($root -eq [IntPtr]::Zero) { L "RESULT=NO_WINDOW"; $log | Out-File $OutFile -Encoding utf8; exit 3 }
L "HWND=$root class=RawrXD_IDE_Window"

# ---- resolve controls in one pass (same approach as gui_enum.ps1) ----
$script:ctrl = @{}
$ccb = [W.Api+EnumProc]{
    param($h, $l)
    $id = [W.Api]::GetDlgCtrlID($h)
    if (-not $script:ctrl.ContainsKey($id)) { $script:ctrl[$id] = $h }
    return $true
}
[void][W.Api]::EnumChildWindows($root, $ccb, [IntPtr]::Zero)

$modelCombo = $script:ctrl[1206]; $input = $script:ctrl[1203]
$send = $script:ctrl[1204]; $transcript = $script:ctrl[1302]
foreach ($pair in @(@("model", 1206, $modelCombo), @("input", 1203, $input), @("send", 1204, $send), @("transcript", 1302, $transcript))) {
    $h = $pair[2]
    $valid = ($h -ne $null -and $h -ne [IntPtr]::Zero -and [W.Api]::IsWindow($h))
    L ("CTRL {0} id={1} hwnd={2} valid={3}" -f $pair[0], $pair[1], $h, $valid)
}
if ($input -eq $null -or $input -eq [IntPtr]::Zero -or $send -eq $null -or $send -eq [IntPtr]::Zero) {
    L "RESULT=CONTROL_RESOLVE_FAILED"; $log | Out-File $OutFile -Encoding utf8; exit 4
}

# ---- model selection (production combo) ----
$res = [IntPtr]::Zero
[void][W.Api]::SendTO($modelCombo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero, $flags, $MsgTimeoutMs, [ref]$res); $count = $res.ToInt64()
L "MODEL_ITEMS=$count"
if ($count -gt 0) {
    [void][W.Api]::SendTO($modelCombo, 0x014E, [IntPtr]0, [IntPtr]::Zero, $flags, $MsgTimeoutMs, [ref]$res)
    [void][W.Api]::SendTO($root, 0x0111, [IntPtr]0x0356, [IntPtr]::Zero, $flags, $MsgTimeoutMs, [ref]$res)
    Start-Sleep -Seconds 8
    L "MODEL_AFTER_SELECTION=" + (Read-Text $modelCombo 512)
}

foreach ($prompt in $Prompts) {
    $null = Send-Text $input 0x000C $prompt
    Start-Sleep -Milliseconds 400
    $typed = Read-Text $input 1024
    $base = (Read-Text $transcript).Length
    $null = Send-Timeout $send 0x00F5 ([IntPtr]::Zero) ([IntPtr]::Zero)   # BM_CLICK
    $deadline = (Get-Date).AddSeconds($ReplyTimeoutSec)
    $final = $base
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        if ($proc.HasExited) { L "PROCESS_EXITED_EARLY"; break }
        $len = (Read-Text $transcript).Length
        if ($len -gt $final) { $final = $len }
        elseif ($len -eq $final -and $final -gt $base) {
            Start-Sleep -Seconds 4
            $len2 = (Read-Text $transcript).Length
            if ($len2 -eq $final) { break }
            $final = $len2
        }
    }
    $delta = $final - $base
    L ("PROMPT=[{0}] TYPED=[{1}] TRANSCRIPT_DELTA={2}" -f $prompt, $typed, $delta)
    if ($delta -gt 0) {
        $all = Read-Text $transcript
        $tail = $all.Substring([Math]::Max(0, $all.Length - 300))
        L "REPLY_TAIL=$tail"
    } else {
        L "REPLY=NONE_OR_TIMEOUT"
    }
}

L "---- CANDIDATE CONTROL TEXT ----"
foreach ($cid in @(1203, 1225, 1302, 1303, 1305, 1200)) {
    if ($script:ctrl.ContainsKey($cid)) {
        $t = Read-Text $script:ctrl[$cid] 4000
        $short = $t
        if ($short.Length -gt 600) { $short = $short.Substring(0, 600) + "..." }
        L ("CID={0} LEN={1} TEXT=[{2}]" -f $cid, $t.Length, $short)
    } else { L ("CID={0} ABSENT" -f $cid) }
}
L "---- STDERR ----"
if (Test-Path $StderrPath) {
    foreach ($line in (Get-Content $StderrPath | Select-String -Pattern "BRIDGE_STREAM|BRIDGE_GEN" | Select-Object -Last 6)) { L $line.Line }
} else { L "STDERR_MISSING" }

$log | Out-File -FilePath $OutFile -Encoding utf8
Write-Output "OUT=$OutFile"
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
Write-Output "DONE"