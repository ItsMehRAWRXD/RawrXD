$env:_NO_DEBUG_HEAP=1
$exe = 'F:\~dev\rawrxd\win32ide_strict\build_v4\bin\Release\rawrxd_real_gguf_parity.exe'
$args = @('--model','D:\rawrxd\gemma3-1b-Q2_K.gguf','--steps','8','--receipt','F:\~dev\parity_receipt.txt')
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.Arguments = $args -join ' '
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
Write-Host ('EXIT_CODE=' + $proc.ExitCode)
if ($stdout) { Write-Host '--- STDOUT ---'; Write-Host $stdout }
if ($stderr) { Write-Host '--- STDERR ---'; Write-Host $stderr }
if (Test-Path 'F:\~dev\parity_receipt.txt') {
    Write-Host '--- RECEIPT ---'
    Get-Content 'F:\~dev\parity_receipt.txt' | ForEach-Object { Write-Host $_ }
} else {
    Write-Host 'NO RECEIPT'
}
