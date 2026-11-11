@echo off
setlocal
rem print lines 410-432 of stdout via more skip
more +409 F:\rawrxd\tmp_remeasure_014\stdout.txt > F:\rawrxd\tmp_remeasure_014\tail_tmp.txt
set /a N=0
for /f "usebackq delims=" %%L in ("F:\rawrxd\tmp_remeasure_014\tail_tmp.txt") do (
  set /a N+=1
  call echo %%N%%:%%L
  call set CUR=%%N%%
  if %%N%% GEQ 25 goto :done
)
:done
endlocal
