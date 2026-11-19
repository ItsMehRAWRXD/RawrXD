import io, re

p = r"F:\rawrxd\evidence\SAME_SHA_ACCEPTANCE_20261119\gui_chat3.ps1"
s = io.open(p, encoding="utf-8-sig").read()

old = """$ccb=[G.Api+EnumProc]{
    param($h,$l)
    $id=[G.Api]::GetDlgCtrlID($h)
    if (-not $script:ctrl.ContainsKey($id)) { $script:ctrl[$id]=$h }
    return $true
}
[void][G.Api]::EnumChildWindows($root,$ccb,[IntPtr]::Zero)"""

new = """$ccb=[G.Api+EnumProc]{
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
}"""

if old in s:
    s = s.replace(old, new, 1)
    print("patched control wait")

old2 = """$input=$script:ctrl[1202]; $send=$script:ctrl[1204]; $out=$script:ctrl[1203]"""
new2 = """$input=$script:ctrl[1202]; $send=$script:ctrl[1204]; $out=$script:ctrl[1203]
if ($null -eq $input -or $null -eq $send -or $null -eq $out) {
    L "CONTROL_RESOLVE_FAILED ids=" + (($script:ctrl.Keys | Sort-Object) -join ",")
    $log | Out-File $OutFile -Encoding utf8
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    exit 4
}"""
if old2 in s:
    s = s.replace(old2, new2, 1)
    print("patched guard")

io.open(p, "w", encoding="utf-8-sig", newline="").write(s)
print("ok")