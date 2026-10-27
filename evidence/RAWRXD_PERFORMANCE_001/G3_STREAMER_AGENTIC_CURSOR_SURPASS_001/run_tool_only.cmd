@echo off
setlocal
set GATE=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_STREAMER_AGENTIC_CURSOR_SURPASS_001
set EXE=C:\Users\Garrett\AppData\Local\Temp\RawrXD-Win32IDE.exe
set PORT=11455
set WD=G:\~dev\rawrxd
set MOTD=G:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc
set RULES=G:\~dev\.cursor\rules
set LOG=%GATE%\tool_only_run.log

echo START %DATE% %TIME% > "%LOG%"
taskkill /F /IM rawr.exe /T >> "%LOG%" 2>&1
taskkill /F /IM RawrXD-Win32IDE.exe /T >> "%LOG%" 2>&1
timeout /t 2 /nobreak >nul

echo EXE=%EXE%>> "%LOG%"
start /B "" "%EXE%" --headless --local --port %PORT% --bind 127.0.0.1 --working-dir "%WD%" > "%GATE%\server.out.txt" 2> "%GATE%\server.err.txt"

set READY=0
for /L %%i in (1,1,40) do (
  curl -s -o nul -w "%%{http_code}" http://127.0.0.1:%PORT%/health > "%GATE%\health.code.txt" 2>nul
  set /p CODE=<"%GATE%\health.code.txt"
  if "!CODE!"=="200" (
    set READY=1
    echo HEALTH_OK %%i>> "%LOG%"
    goto :ready
  )
  timeout /t 1 /nobreak >nul
)
echo NO_HEALTH>> "%LOG%"
goto :end

:ready
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$port=%PORT%; $gate='%GATE%'; $motd='%MOTD%'; $rules='%RULES%';" ^
  "function PT($t,$a){ $j=@{tool=$t;args=$a}|ConvertTo-Json -Compress -Depth 8; try{ $r=Invoke-WebRequest http://127.0.0.1:$port/api/tool -Method POST -Body ([Text.Encoding]::UTF8.GetBytes($j)) -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 45; 'STATUS='+$r.StatusCode+\"`n\"+$r.Content } catch { $resp=$_.Exception.Response; if($resp){ $sr=New-Object IO.StreamReader($resp.GetResponseStream()); $c=$sr.ReadToEnd(); $sr.Close(); 'STATUS='+[int]$resp.StatusCode+\"`n\"+$c } else { 'STATUS=-1`n'+$_.Exception.Message } } }" ^
  "function PJ($u,$b){ try{ $r=Invoke-WebRequest $u -Method POST -Body ([Text.Encoding]::UTF8.GetBytes($b)) -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 60; 'STATUS='+$r.StatusCode+\"`n\"+$r.Content } catch { $resp=$_.Exception.Response; if($resp){ $sr=New-Object IO.StreamReader($resp.GetResponseStream()); $c=$sr.ReadToEnd(); $sr.Close(); 'STATUS='+[int]$resp.StatusCode+\"`n\"+$c } else { 'STATUS=-1`n'+$_.Exception.Message } } }" ^
  "$pre=PT 'list_directory' @{path=$rules}; [IO.File]::WriteAllText(\"$gate\\pre_motd.txt\",$pre);" ^
  "$m1=PT 'read_motd' @{}; [IO.File]::WriteAllText(\"$gate\\motd_read_motd.txt\",$m1);" ^
  "$m2=PT 'read_file' @{path=$motd}; [IO.File]::WriteAllText(\"$gate\\motd_read.txt\",$m2);" ^
  "$post=PT 'list_directory' @{path=$rules}; [IO.File]::WriteAllText(\"$gate\\post_motd_list.txt\",$post);" ^
  "$cli=PT 'execute_command' @{command='echo TOOL_LOOP_OK'}; [IO.File]::WriteAllText(\"$gate\\post_motd_cli.txt\",$cli);" ^
  "$brief='Please continue ensuring that the streamer is complete and can run agentic. Smoke-only. PROMOTE=0 TIP_CLIMB=HOLD.';" ^
  "$sub=PJ \"http://127.0.0.1:$port/api/subagent\" ((@{task=$brief;context='continue-ensure'}|ConvertTo-Json -Compress));" ^
  "[IO.File]::WriteAllText(\"$gate\\subagent.txt\",$sub);" ^
  "$preOk=($pre -match 'STATUS=403'); $motdOk=((($m1 -match 'STATUS=200') -or ($m2 -match 'STATUS=200')) -and (($m1+$m2) -match 'PassiveRoleNotRoleplay')); $listOk=(($post -match 'STATUS=200') -and ($post -match 'StreamerAgenticContinueEnsure')); $cliOk=(($cli -match 'STATUS=200') -and ($cli -match 'TOOL_LOOP_OK')); $subOk=($sub -match 'STATUS=202');" ^
  "$line=\"RESULT pre=$preOk motd=$motdOk list=$listOk cli=$cliOk sub=$subOk\"; [IO.File]::AppendAllText(\"$gate\\tool_only_run.log\",$line+\"`n\"); Write-Output $line"

taskkill /F /IM RawrXD-Win32IDE.exe /T >> "%LOG%" 2>&1
echo DONE %DATE% %TIME%>> "%LOG%"
:end
endlocal
