$p = Start-Process -FilePath 'F:\rawrxd\tmp_wv2_probe.exe' -NoNewWindow -PassThru -RedirectStandardOutput 'F:\rawrxd\tmp_probe_out.txt' -RedirectStandardError 'F:\rawrxd\tmp_probe_err.txt'
$exited = $p.WaitForExit(90000)
if (-not $exited) {
    $p.Kill()
    Write-Output 'TIMEOUT: killed after 90s'
} else {
    Write-Output ('EXIT CODE: ' + $p.ExitCode)
}
