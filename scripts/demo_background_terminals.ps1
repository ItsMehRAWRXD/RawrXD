# demo_background_terminals.ps1
$ErrorActionPreference = "Stop"
$bin = "G:\~dev\rawrxd\build-fd\bin"
$ctl = Join-Path $bin "rawr_termctl.exe"
& $ctl start demo -- cmd /c "echo HELLO_TERM& ping -n 2 127.0.0.1 >nul& echo BYE"
Start-Sleep -Milliseconds 500
& $ctl tail demo 200
& $ctl status demo
& $ctl stop demo
