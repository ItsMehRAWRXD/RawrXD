param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Log = "F:\rawrxd\evidence\same_sha_acceptance_20261119\model_probe_stderr.log",
    [int]$SettleSec = 15,
    [switch]$ForceModelPath
)

# Focused model-selector probe (control 1206): launch, wait for async model
# discovery to settle, then enumerate every combo item and dump the
# [MODEL_...] stderr trace. Read-only w.r.t. product state.

Add-Type -Namespace MP -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetDlgCtrlID(IntPtr h);
[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint ms, out IntPtr r);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOGetText(IntPtr h, uint m, IntPtr w, System.Text.StringBuilder l, uint f, uint ms, out IntPtr r);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" -or $_.ProcessName -like "*RawrXD-Win32*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if (Test-Path $Log) { Remove-Item $Log -Force -ErrorAction SilentlyContinue }

if (-not $ForceModelPath) {
    Remove-Item Env:\RAWRXD_MODEL_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:\RAWRXD_P11_FORCE_OLLAMA_MODEL -ErrorAction SilentlyContinue
}

$flags = 0x12
$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError $Log
Write-Output "PID=$($proc.Id)"

$root = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited) {
    Start-Sleep -Milliseconds 600
    $cb = [MP.Api+EnumProc]{
        param($h,$l)
        $p2=0; [void][MP.Api]::GetWindowThreadProcessId($h,[ref]$p2)
        if ($p2 -eq $proc.Id) {
            $c = New-Object System.Text.StringBuilder 128
            [void][MP.Api]::GetClassName($h,$c,128)
            if ($c.ToString() -like "RawrXD_IDE_Window*") { $script:root = $h }
        }
        return $true
    }
    [void][MP.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
Write-Output "HWND=$root"
if ($root -eq [IntPtr]::Zero) { Write-Output "RESULT=NO_WINDOW"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }

# wait for control 1206 to exist
$combo = [IntPtr]::Zero
$ctrlDeadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ctrlDeadline -and $combo -eq [IntPtr]::Zero) {
    $ccb = [MP.Api+EnumProc]{
        param($h,$l)
        if ([MP.Api]::GetDlgCtrlID($h) -eq 1206) { $script:combo = $h }
        return $true
    }
    [void][MP.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
    if ($combo -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 500 }
}

function Get-ComboText([IntPtr]$h, [int]$index) {
    $r0 = [IntPtr]::Zero
    $n = [MP.Api]::SendTO($h, 0x0150, [IntPtr]$index, [IntPtr]::Zero, 0x12, 4000, [ref]$r0)  # CB_GETLBTEXTLEN
    if ($n.ToInt64() -le 0) { return "" }
    $sb = New-Object System.Text.StringBuilder ([int]$n.ToInt64() + 2)
    $o = [MP.Api]::SendTOGetText($h, 0x0148, [IntPtr]$index, $sb, 0x12, 4000, [ref]$r0)   # CB_GETLBTEXT
    if ($o -eq [IntPtr]::Zero) { return "" }
    return $sb.ToString()
}

function Dump-Combo([string]$tag) {
    if ($combo -eq $null -or $combo -eq [IntPtr]::Zero) { Write-Output "$tag COMBO=<none>"; return }
    $r0 = [IntPtr]::Zero
    [void][MP.Api]::SendTO($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 5000, [ref]$r0) # CB_GETCOUNT
    $count = [int]$r0.ToInt64()
    [void][MP.Api]::SendTO($combo, 0x0147, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 5000, [ref]$r0) # CB_GETCURSEL
    $sel = [int]$r0.ToInt64()
    Write-Output ("$tag COUNT=$count CURSEL=$sel")
    $blank = 0
    for ($k=0; $k -lt $count; $k++) {
        $t = Get-ComboText $combo $k
        if ([string]::IsNullOrEmpty($t)) { $blank++ }
        Write-Output ("  ITEM[{0}]='{1}'" -f $k, $t)
    }
    Write-Output ("$tag BLANK_ITEMS=$blank")
}

Write-Output "COMBO_HWND=$combo ID=$(if($combo -ne [IntPtr]::Zero){[MP.Api]::GetDlgCtrlID($combo)}else{-1})"
Dump-Combo "EARLY"
Write-Output "SETTLING=${SettleSec}s ..."
Start-Sleep -Seconds $SettleSec
Dump-Combo "FINAL"

# normal close
[void][MP.Api]::PostMessage($root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)  # WM_CLOSE
$closed = $proc.WaitForExit(8000)
if (-not $closed) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Write-Output "NATURAL_EXIT=$closed"

Write-Output "---- MODEL trace (stderr) ----"
if (Test-Path $Log) {
    Select-String -LiteralPath $Log -Pattern '\[MODEL_(DISCOVERY|DISCOVERY_ENTRY|DISCOVERY_PATH|DISCOVERY_ADD|ADD|SETCURSEL|PATH)' | ForEach-Object { $_.Line }
}
Write-Output "DONE"