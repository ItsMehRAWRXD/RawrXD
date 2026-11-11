$p = Start-Process -FilePath "F:\rawrxd\build_ide\bin-msvc\rawr.exe" -ArgumentList "run nemotron-3-nano:4b autonomous --approve-mutations --max-tokens 256 --cancel-after-ms 5000" -PassThru -RedirectStandardInput "F:\rawrxd\t15_stdin.txt" -RedirectStandardOutput "F:\rawrxd\t15_stdout.txt" -WindowStyle Hidden
Start-Sleep -Seconds 3
$p.StandardInput.WriteLine("/tools run editFiles path=t15_test.txt oldString=HELLO newString=EDITED_HELLO")
Start-Sleep -Seconds 5
$p.StandardInput.WriteLine("/quit")
Start-Sleep -Seconds 2
$p.Kill()
"Done"
