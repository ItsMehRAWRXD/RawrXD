<#
Localises the IDE runtime-cert hang by sampling the live process.

Facts already established:
  - RunStages() IS reached (it creates ide_cert_workspace and wrote cert_doc.txt, 68 bytes)
  - WriteReceipt() runs only AFTER RunStages() returns, so no receipt means the hang is
    inside stages S07..S16
  - S11 calls OpenClipboard(), which BLOCKS while another process owns the clipboard
  - S15 notes OpenDialog is modal, which would block a message loop indefinitely

This samples CPU time and thread count over time to separate the two classes:
  CPU RISING  -> busy/spin somewhere
  CPU FLAT    -> blocked on a wait (clipboard ownership, modal dialog, mutex, I/O)
It also re-checks the clipboard immediately after the process is killed, to see whether
this session or another process was the holder.
#>

$Exe  = 'F:\~dev\build_ide_probe\bin\RawrXD-Win32IDE.exe'
$Work = 'F:\dev_ide_cert2'
$Rec  = Join-Path $Work 'ide_runtime_cert_receipt.txt'
$Ws   = 'F:\~dev\build_ide_probe\bin\ide_cert_workspace'
New-Item -ItemType Directory -Path $Work -Force | Out-Null
Remove-Item $Rec -Force -ErrorAction SilentlyContinue

Write-Output "EXE_SHA256=$((Get-FileHash $Exe -Algorithm SHA256).Hash)"
Write-Output "WORKSPACE_BEFORE=$(if (Test-Path $Ws) { 'exists' } else { 'absent' })"
if (Test-Path $Ws) { Remove-Item "$Ws\*" -Recurse -Force -ErrorAction SilentlyContinue }

$p = Start-Process -FilePath $Exe -PassThru -WindowStyle Normal -WorkingDirectory $Work `
     -ArgumentList @('--ide-runtime-cert', '--ide-cert-receipt', $Rec)
Write-Output "PID=$($p.Id)"

$samples = @()
for ($i = 1; $i -le 24; $i++) {
    Start-Sleep -Seconds 5
    if ($p.HasExited) { Write-Output "EXITED at $(5*$i)s code=$($p.ExitCode)"; break }
    $p.Refresh()
    $cpu = [double]$p.TotalProcessorTime.TotalSeconds
    $ws  = [int]($p.WorkingSet64 / 1MB)
    $doc = if (Test-Path "$Ws\cert_doc.txt") { (Get-Item "$Ws\cert_doc.txt").Length } else { -1 }
    $rec = Test-Path $Rec
    $samples += [pscustomobject]@{ t = 5*$i; cpu = $cpu; threads = $p.Threads.Count; wsMB = $ws; doc = $doc; receipt = $rec }
    if ($rec) { Write-Output "RECEIPT at $(5*$i)s"; break }
}

Write-Output ''
Write-Output ' t(s)  cpu(s)  d_cpu  threads  wsMB  doc_bytes  receipt'
$prev = $null
foreach ($s in $samples) {
    $d = if ($null -eq $prev) { '-' } else { '{0:N2}' -f ($s.cpu - $prev) }
    Write-Output ("{0,5}  {1,6:N2}  {2,6}  {3,7}  {4,5}  {5,10}  {6}" -f $s.t,$s.cpu,$d,$s.threads,$s.wsMB,$s.doc,$s.receipt)
    $prev = $s.cpu
}

if ($samples.Count -ge 2) {
    $deltas = @()
    for ($i = 1; $i -lt $samples.Count; $i++) { $deltas += ($samples[$i].cpu - $samples[$i-1].cpu) }
    $avg = ($deltas | Measure-Object -Average).Average
    $max = ($deltas | Measure-Object -Maximum).Maximum
    Write-Output ''
    Write-Output "CPU_DELTA_PER_5S_AVG=$([math]::Round($avg,3))  MAX=$([math]::Round($max,3))"
    if ($avg -lt 0.05) {
        Write-Output 'CLASSIFICATION=BLOCKED  (CPU flat -> waiting on a resource, not spinning)'
        Write-Output 'PRIME_SUSPECTS=clipboard ownership (S11 OpenClipboard) | modal OpenDialog (S15) | mutex'
    } else {
        Write-Output 'CLASSIFICATION=SPINNING (CPU advancing -> busy loop)'
    }
}

Write-Output ''
if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(20000) | Out-Null }
Write-Output "KILLED_ONLY_THIS_PID=$(if (-not $p.HasExited) { 'NO' } else { 'YES' })"

Write-Output ''
Write-Output '--- workspace after the run ---'
if (Test-Path $Ws) { Get-ChildItem $Ws -Recurse | ForEach-Object { Write-Output ("  {0}  {1} bytes  {2:u}" -f $_.Name,$_.Length,$_.LastWriteTime) } }
Write-Output ''
Write-Output '--- clipboard state after the process is gone ---'
try {
    $t = Get-Clipboard -Raw -ErrorAction Stop
    Write-Output "CLIPBOARD_READABLE=YES  length=$($t.Length)"
} catch {
    Write-Output "CLIPBOARD_READABLE=NO  $($_.Exception.Message)"
}
