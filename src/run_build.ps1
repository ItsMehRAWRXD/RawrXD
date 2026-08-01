$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "C:\Windows\System32\cmd.exe"
$psi.Arguments = "/c d:\rawrxd-ci-bootstrap\src\build_full.bat"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$p = [System.Diagnostics.Process]::Start($psi)
$p.WaitForExit()
$stdout = $p.StandardOutput.ReadToEnd()
$stderr = $p.StandardError.ReadToEnd()
Write-Host $stdout
if ($stderr) { Write-Host "STDERR: $stderr" }
Write-Host "Exit code: $($p.ExitCode)"
