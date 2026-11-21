param(
    [string]$Exe = "F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe",
    [string]$Result = "F:\rawrxd\evidence\same_sha_acceptance_20261119\selector_inventory_result.txt",
    [int]$SettleSec = 12
)

# Sprint 5 reference probe. Correctly separates transport success (return
# value) from the message result (out param), so signed results such as
# CB_ERR=-1 are preserved and a timeout is distinguishable from a real -1.

Add-Type -Namespace G5 -Name Api -MemberDefinition @'
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

# Transport success is the return value; message result is the out param.
# Throw on transport failure so a timeout can never masquerade as a result.
function SendMsg([IntPtr]$h, [uint32]$m, [IntPtr]$w, [IntPtr]$l) {
    $r = [IntPtr]::Zero
    $ok = [G5.Api]::SendTO($h, $m, $w, $l, 0x12, 5000, [ref]$r)
    if ($ok -eq [IntPtr]::Zero) { throw ("SendMessageTimeoutW transport failure msg=0x{0:X}" -f $m) }
    return $r
}
function Get-ItemText([IntPtr]$h, [int]$index) {
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024 * 2)
    try {
        $r = [IntPtr]::Zero
        [void][G5.Api]::SendTO($h, 0x0148, [IntPtr]$index, $buf, 0x12, 5000, [ref]$r)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($buf)
    } finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
}

Get-Process | Where-Object { $_.ProcessName -like "*Win32IDE*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $Result -Force -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath $Exe -PassThru -RedirectStandardError "$Result.stderr.log"
W "PID=$($proc.Id)"

$root = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline -and $root -eq [IntPtr]::Zero -and -not $proc.HasExited) {
    Start-Sleep -Milliseconds 600
    $cb = [G5.Api+EnumProc]{
        param($h,$l)
        $p2=0; [void][G5.Api]::GetWindowThreadProcessId($h,[ref]$p2)
        if ($p2 -eq $proc.Id) {
            $c = New-Object System.Text.StringBuilder 128
            [void][G5.Api]::GetClassName($h,$c,128)
            if ($c.ToString() -like "RawrXD_IDE_Window*") { $script:root=$h }
        }
        return $true
    }
    [void][G5.Api]::EnumWindows($cb,[IntPtr]::Zero)
}
if ($root -eq [IntPtr]::Zero) { W "ROOT_NOT_FOUND"; if(-not $proc.HasExited){Stop-Process -Id $proc.Id -Force}; exit 3 }

$ctrl = @{}
$ccb = [G5.Api+EnumProc]{
    param($h,$l)
    $id=[G5.Api]::GetDlgCtrlID($h)
    if (-not $ctrl.ContainsKey($id)) { $ctrl[$id]=$h }
    return $true
}
$ctrlDeadline=(Get-Date).AddSeconds(25)
while((Get-Date) -lt $ctrlDeadline){
    $ctrl=@{}
    [void][G5.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)
    if($ctrl.ContainsKey(1226) -and $ctrl.ContainsKey(1206)){break}
    Start-Sleep -Milliseconds 600
}
Start-Sleep -Seconds $SettleSec

function Report([int]$id) {
    if (-not $ctrl.ContainsKey($id)) { W "CTRL $id = <missing>"; return }
    $h = $ctrl[$id]
    $count = (SendMsg $h 0x0146 ([IntPtr]::Zero) ([IntPtr]::Zero)).ToInt64()   # CB_GETCOUNT
    $sel   = (SendMsg $h 0x0147 ([IntPtr]::Zero) ([IntPtr]::Zero)).ToInt64()   # CB_GETCURSEL
    W ("CTRL {0} COUNT={1} CURSEL={2}" -f $id, $count, $sel)
    $blank=0
    for($k=0;$k -lt [Math]::Min($count,400);$k++){
        $t = Get-ItemText $h $k
        if([string]::IsNullOrWhiteSpace($t)){ $blank++; W ("  {0} BLANK ITEM[{1}]" -f $id,$k) }
        elseif($k -lt 3){ W ("  {0} ITEM[{1}]='{2}'" -f $id,$k,$t) }
    }
    W ("CTRL {0} BLANK_ITEMS={1}" -f $id,$blank)
}

Report 1226   # backend selector: expect exactly 3
Report 1206   # model selector: actual discovered inventory

[void][G5.Api]::PostMessage($root, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
$closed = $proc.WaitForExit(8000)
if (-not $closed) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
W "NATURAL_EXIT=$closed"
W "DONE"