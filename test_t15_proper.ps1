# T15 proper test: start rawr, wait for prompt, then send edit command
$p = Start-Process -FilePath "F:\rawrxd\build_ide\bin-msvc\rawr.exe" -ArgumentList "run nemotron-3-nano:4b autonomous --approve-mutations --max-tokens 256" -PassThru -RedirectStandardOutput "F:\rawrxd\t15_stdout.txt" -WindowStyle Hidden

# Wait for model to load and prompt to appear
Start-Sleep -Seconds 15

# Check if still running
if ($p.HasExited) {
    "PROCESS EXITED EARLY"
    Get-Content "F:\rawrxd\t15_stdout.txt" | Select-Object -Last 20
} else {
    "PROCESS STILL RUNNING, sending commands..."
    $p.StandardInput.WriteLine("/tools run editFiles path=t15_test.txt oldString=T15_ORIGINAL newString=T15_EDITED_VIA_TOOL")
    Start-Sleep -Seconds 15
    $p.StandardInput.WriteLine("/quit")
    Start-Sleep -Seconds 5
    if ($p.HasExited -eq $false) { $p.Kill() }
}
"Done"
