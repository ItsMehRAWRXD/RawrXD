param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [string]$Prompt = "What is 2+2?",
    [string]$Log = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\repro2_stderr.log",
    [string]$Out = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\repro2_result.txt",
    [int]$ReplyTimeoutSec = 120,
    [int]$CloseWaitSec = 90
)

Add-Type -Namespace R2 -Name Api -MemberDefinition @'
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
[DllImport("user32.dll", CharSet=CharSet.Auto, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOA(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint ms, out IntPtr r);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class Chin4 {
    [StructLayout(LayoutKind.Sequential)]
    struct Cds { public IntPtr dwData; public uint cbData; public IntPtr lpData; }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
    static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, ref Cds l, uint f, uint ms, out IntPtr r);
    public static bool Stage(IntPtr h, string t) {
        byte[] b = Encoding.UTF8.GetBytes(t);
        IntPtr p = Marshal.AllocHGlobal(b.Length);
        try {
            Marshal.Copy(b, 0, p, b.Length);
            Cds c = new Cds();
            c.dwData = (IntPtr)0x4348494E; c.cbData = (uint)b.Length; c.lpData = p;
            IntPtr r; IntPtr o = SendTO(h, 0x004A, IntPtr.Zero, ref c, 0x12, 5000, out r);
            return o != IntPtr.Zero;
        } finally { Marshal.FreeHGlobal(p); }
    }
}
'@

$flags = 0x12
$entries = New-Object System.Collections.ArrayList
function L([string]$m) { [void]$entries.Add($m); Write-Output $m }
function ReadT([IntPtr]$h, [int]$cap = 200000) {
    $sb = New-Object System.Text.StringBuilder $cap
    $r = [IntPtr]::Zero
    $o = [R2.Api]::SendTOGetText($h, 0x000D, [IntPtr]$cap, $sb, $flags, 5000, [ref]$r)
    if ($o -eq [IntPtr]::Zero) { return "<no-reply>" }
    return $sb.ToString()
}

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path $Log) { Remove-Item $Log -Force -ErrorAction SilentlyContinue }

$env:RAWRXD_CHAT_BACKEND = "deep2"
$env:RAWRXD_MODEL_PATH = $Model
$env:RAWRXD_DEEP2_PROBE_MODEL = $Model
$p = Start-Process -FilePath $Exe -PassThru -RedirectStandardError $Log
L "PID=$($p.Id) START=$(Get-Date -Format 'HH:mm:ss')"

$root = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero -and -not $p.HasExited) {
    Start-Sleep -Milliseconds 600
    $cb = [R2.Api+EnumProc]{
        param($h,$l)
        $p2=0; [void][R2.Api]::GetWindowThreadProcessId($h,[ref]$p2)
        if ($p2 -eq $p.Id) {
            $c=New-Object System.Text.StringBuilder 128
            [void][R2.Api]::GetClassName($h,$c,128)
            if ($c.ToString() -like "RawrXD_IDE_Window*") { $script:root=$h }
        }
        return $true
    }
    [void][R2.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
L "HWND=$root"
if ($root -eq [IntPtr]::Zero) { L "RESULT=NO_WINDOW"; $entries | Out-File $Out -Encoding utf8; exit 3 }

# wait for the chat controls, then select a model
$script:ctrl=@{}
$ccb=[R2.Api+EnumProc]{
    param($h,$l)
    $id=[R2.Api]::GetDlgCtrlID($h)
    if (-not $script:ctrl.ContainsKey($id)) { $script:ctrl[$id]=$h }
    return $true
}
$ctrlDeadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ctrlDeadline) {
    $script:ctrl=@{}
    [void][R2.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
    if ($script:ctrl.ContainsKey(1202) -and $script:ctrl.ContainsKey(1204)) { break }
    Start-Sleep -Milliseconds 700
}
$combo = $script:ctrl[1206]; $input = $script:ctrl[1202]; $send = $script:ctrl[1204]; $out = $script:ctrl[1203]

# --- model combo: one HWND for every operation, with text enumeration ---
function Get-ComboText([IntPtr]$h, [int]$index) {
    $len = [ IntPtr ]::Zero
    $r0 = [IntPtr]::Zero
    [void][R2.Api]::SendTO($h, 0x0150, [IntPtr]$index, [IntPtr]::Zero, 0x12, 4000, [ref]$r0); $n = $r0.ToInt64()  # CB_GETLBTEXTLEN
    if ($n -le 0) { return "" }
    $sb = New-Object System.Text.StringBuilder ($n + 2)
    $o = [R2.Api]::SendTOGetText($h, 0x0148, [IntPtr]$index, $sb, 0x12, 4000, [ref]$r0)  # CB_GETLBTEXT 0x0148
    if ($o -eq [IntPtr]::Zero) { return "" }
    return $sb.ToString()
}

$comboText = ""
$count = 0
$sel = -1
if ($combo -ne $null -and $combo -ne [IntPtr]::Zero) {
    $r0 = [IntPtr]::Zero
    $count = 0; $sel = -1
    [void][R2.Api]::SendTO($combo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 5000, [ref]$r0)
    $count = [int]$r0.ToInt64()
    [void][R2.Api]::SendTO($combo, 0x0147, [IntPtr]::Zero, [IntPtr]::Zero, 0x12, 5000, [ref]$r0)
    $sel = [int]$r0.ToInt64()
    L ("COMBO_HWND={0} ID={1} COUNT={2} CURSEL={3}" -f $combo, [R2.Api]::GetDlgCtrlID($combo), $count, $sel)
    for ($k = 0; $k -lt [Math]::Min($count, 8); $k++) {
        $t = Get-ComboText $combo $k
        L ("  ITEM[{0}]='{1}'" -f $k, $t)
    }
    $want = Split-Path $Model -Leaf
    $match = -1
    for ($k = 0; $k -lt $count; $k++) {
        $t = Get-ComboText $combo $k
        if ($t -like "*$want*") { $match = $k; break }
    }
    if ($match -lt 0 -and $count -gt 0) { $match = 0 }
    if ($match -ge 0) {
        $r1 = [IntPtr]::Zero
        [void][R2.Api]::SendTO($combo, 0x014E, [IntPtr]$match, [IntPtr]::Zero, 0x12, 5000, [ref]$r1)
        [void][R2.Api]::SendTO($root, 0x0111, [IntPtr](((1 -shl 16) -bor 1206)), $combo, 0x12, 5000, [ref]$r1)
        Start-Sleep -Seconds 6
        $sel = $match
        $comboText = $want
        L ("MODEL_SELECTED index={0} text='{1}' alive={2}" -f $sel, $comboText, (-not $p.HasExited))
    }
}

$selectionValid = ($count -gt 0 -and $sel -ge 0 -and $sel -lt $count)
L ("MODEL_SELECTION_READY={0}" -f $selectionValid)
if (-not $selectionValid) {
    L "RESULT=MODEL_SELECTION_NOT_READY"
    $entries | Out-File -FilePath $Out -Encoding utf8
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
    exit 4
}
L "ALIVE_BEFORE_SEND=$(-not $p.HasExited)"
L "CHIN=$([Chin4]::Stage($root, $Prompt))"
Start-Sleep -Milliseconds 600
$base = (ReadT $out).Length
[void][R2.Api]::SendTO($send, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero, $flags, 5000, [ref]$r)
L "SENT"

$deadline = (Get-Date).AddSeconds($ReplyTimeoutSec)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if ($p.HasExited) { L "EXITED_DURING_GENERATION"; break }
    $len = (ReadT $out).Length
    if ($len -gt $base + 20) { L "TRANSCRIPT_DELTA=$($len - $base)"; break }
}
Start-Sleep -Seconds 5
L "ALIVE_AFTER_RESPONSE=$(-not $p.HasExited)"

# normal close, no Stop-Process
[void][R2.Api]::PostMessage($root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)   # WM_CLOSE
$closed = $p.WaitForExit($CloseWaitSec * 1000)
if ($closed) {
    $code = [uint32]($p.ExitCode -band 0xFFFFFFFF)
    L ("NATURAL_EXIT=1 EXIT_HEX=0x{0:X8}" -f $code)
} else {
    L "NATURAL_EXIT=0 (still running after ${CloseWaitSec}s)"
    Stop-Process -Id $p.Id -Force
}
$entries | Out-File -FilePath $Out -Encoding utf8
Write-Output "OUT=$Out"