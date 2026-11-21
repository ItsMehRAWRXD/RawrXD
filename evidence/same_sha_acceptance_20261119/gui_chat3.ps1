param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [string[]]$Prompts = @("What is 2+2?", "Name one color."),
    [int]$StartupSec = 30,
    [int]$ReplyTimeoutSec = 60,
    [string]$StderrPath = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui5_stderr.log",
    [string]$OutFile = "F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui5_result.txt"
)

Add-Type -Namespace G -Name Api -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
[DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetDlgCtrlID(IntPtr h);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, IntPtr l, uint flags, uint ms, out IntPtr res);
[DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
public static extern IntPtr SendTOGetText(IntPtr h, uint m, IntPtr w, System.Text.StringBuilder l, uint flags, uint ms, out IntPtr res);
public delegate bool EnumProc(IntPtr h, IntPtr p);
'@

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class Chin {
    [StructLayout(LayoutKind.Sequential)]
    private struct COPYDATASTRUCT { public IntPtr dwData; public uint cbData; public IntPtr lpData; }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
    private static extern IntPtr SendTO(IntPtr h, uint m, IntPtr w, ref COPYDATASTRUCT l, uint flags, uint ms, out IntPtr res);
    public const uint CMD = 0x4348494E;
    public static bool Stage(IntPtr hwnd, string text) {
        byte[] b = Encoding.UTF8.GetBytes(text);
        IntPtr p = Marshal.AllocHGlobal(b.Length);
        try {
            Marshal.Copy(b, 0, p, b.Length);
            COPYDATASTRUCT cds = new COPYDATASTRUCT();
            cds.dwData = (IntPtr)CMD;
            cds.cbData = (uint)b.Length;
            cds.lpData = p;
            IntPtr res = IntPtr.Zero;
            IntPtr r = SendTO(hwnd, 0x004A, IntPtr.Zero, ref cds, 0x12, 5000, out res);
            return r != IntPtr.Zero;
        } finally { Marshal.FreeHGlobal(p); }
    }
}
'@

$flags = 0x12
$log = New-Object System.Collections.ArrayList
function L([string]$m) { [void]$log.Add($m); Write-Output $m }
function TO([IntPtr]$h,[uint32]$m) { $r=[IntPtr]::Zero; [void][G.Api]::SendTO($h,$m,[IntPtr]::Zero,[IntPtr]::Zero,$flags,4000,[ref]$r); return $r }
function ReadT([IntPtr]$h,[int]$cap=200000) {
    $sb=New-Object System.Text.StringBuilder $cap
    $r=[IntPtr]::Zero
    $o=[G.Api]::SendTOGetText($h,0x000D,[IntPtr]$cap,$sb,$flags,5000,[ref]$r)
    if ($o -eq [IntPtr]::Zero) { return "<no-reply>" }
    return $sb.ToString()
}

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force
Start-Sleep -Seconds 3
if (Test-Path $StderrPath) { Remove-Item $StderrPath -Force -ErrorAction SilentlyContinue }

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError $StderrPath `
    -Environment @{ RAWRXD_DEEP2_PROBE_MODEL = $Model; RAWRXD_CHAT_BACKEND = "deep2"; RAWRXD_MODEL_PATH = $Model; RAWRXD_CHAT_DEEP2_SYNC = $env:RAWRXD_CHAT_SYNC }
L "PID=$($proc.Id)"
$root=[IntPtr]::Zero
$deadline=(Get-Date).AddSeconds($StartupSec)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited) {
    Start-Sleep -Milliseconds 500
    $cb=[G.Api+EnumProc]{
        param($h,$l)
        $p2=0; [void][G.Api]::GetWindowThreadProcessId($h,[ref]$p2)
        if ($p2 -eq $proc.Id) {
            $c=New-Object System.Text.StringBuilder 128
            [void][G.Api]::GetClassName($h,$c,128)
            if ($c.ToString() -like "RawrXD_IDE_Window*") { $script:root=$h }
        }
        return $true
    }
    [void][G.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
L "HWND=$root ALIVE=$(-not $proc.HasExited)"
if ($root -eq [IntPtr]::Zero) { $log|Out-File $OutFile -Encoding utf8; exit 3 }

$script:ctrl=@{}
$ccb=[G.Api+EnumProc]{
    param($h,$l)
    $id=[G.Api]::GetDlgCtrlID($h)
    if (-not $script:ctrl.ContainsKey($id)) { $script:ctrl[$id]=$h }
    return $true
}
# The chat sidebar is created during startup; poll until the controls exist.
$ctrlDeadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $ctrlDeadline) {
    $script:ctrl=@{}
    [void][G.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
    if ($script:ctrl.ContainsKey(1202) -and $script:ctrl.ContainsKey(1204) -and $script:ctrl.ContainsKey(1203)) { break }
    Start-Sleep -Milliseconds 800
}
L "IDS=" + (($script:ctrl.Keys | Sort-Object) -join ",")
$combo=$script:ctrl[1206]
L "CB_COUNT=$(TO $combo 0x0146) CB_CURSEL=$(TO $combo 0x0147)"
# WM_COMMAND: HIWORD(wParam)=CBN_SELCHANGE(1), LOWORD=control id, lParam=combo HWND
$r0=[IntPtr]::Zero
[void][G.Api]::SendTO($root, 0x0111, [IntPtr](((1 -shl 16) -bor 1206)), $combo, 0x12, 5000, [ref]$r0)
Start-Sleep -Seconds 10
L "AFTER_SELCHANGE alive=$(-not $proc.HasExited)"
$input=$script:ctrl[1202]; $send=$script:ctrl[1204]; $out=$script:ctrl[1203]
if ($null -eq $input -or $null -eq $send -or $null -eq $out) {
    L "CONTROL_RESOLVE_FAILED ids=" + (($script:ctrl.Keys | Sort-Object) -join ",")
    $log | Out-File $OutFile -Encoding utf8
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    exit 4
}
L "CTRL input1202=$input send1204=$send output1203=$out"

foreach ($prompt in $Prompts) {
    $ok = [Chin]::Stage($root, $prompt)
    L "CHIN_STAGE=$ok PROMPT=[$prompt] ALIVE=$(-not $proc.HasExited)"
    Start-Sleep -Milliseconds 500
    $base = (ReadT $out).Length
    $r=[IntPtr]::Zero
    [void][G.Api]::SendTO($send,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero,$flags,5000,[ref]$r)
    $t0=Get-Date; $last=$base; $stable=0
    while (((Get-Date)-$t0).TotalSeconds -lt $ReplyTimeoutSec) {
        Start-Sleep -Milliseconds 1200
        if ($proc.HasExited) { L ("EXITED code={0} after={1:N1}s" -f $proc.ExitCode, ((Get-Date)-$t0).TotalSeconds); break }
        $txt = ReadT $out
        $len = $txt.Length
        if ($len -ne $last) {
            $tail=$txt; if ($tail.Length -gt 400) { $tail=$tail.Substring($tail.Length-400) }
            L ("OUT_LEN=$len at=$([int]((Get-Date)-$t0).TotalSeconds)s TEXT=[" + $tail + "]")
            $last=$len; $stable=0
        } else { $stable++; if ($stable -ge 15 -and $len -gt $base) { break } }
    }
    L ("PROMPT_DONE delta={0} alive={1}" -f ($last-$base), (-not $proc.HasExited))
}

L "---- STDERR ----"
if (Test-Path $StderrPath) {
    $lines = Get-Content $StderrPath | Select-String -Pattern "BRIDGE_STREAM|BRIDGE_GEN|GEMV_TRACE|LW_GATE" | Select-Object -Last 6
    if ($lines) { foreach ($x in $lines) { L $x.Line } } else { L "NO_GPU_WITNESS" }
} else { L "STDERR_MISSING" }

$log | Out-File -FilePath $OutFile -Encoding utf8
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
Write-Output "OUT=$OutFile"



