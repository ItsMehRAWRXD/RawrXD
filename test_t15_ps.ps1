$p = Start-Process -FilePath "F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe" -ArgumentList "run nemotron-3-nano:4b autonomous --approve-mutations --max-tokens 256 --cancel-after-ms 15000" -PassThru -RedirectStandardInput "F:\rawrxd\t15_stdin2.txt" -RedirectStandardOutput "F:\rawrxd\t15_stdout2.txt" -WindowStyle Hidden
Start-Sleep -Seconds 5
$p.StandardInput.WriteLine("/tools run editFiles path=t15_test.txt oldString=T15_ORIGINAL newString=T15_EDITED_VIA_TOOL")
Start-Sleep -Seconds 5
$p.StandardInput.WriteLine("/quit")
Start-Sleep -Seconds 2
$p.Kill()
"Done"
