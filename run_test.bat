@echo off
cd /d d:\RawrXD
powershell -ExecutionPolicy Bypass -Command "& { .\telemetry-integration-test-fixed.ps1 -MaxDurationMinutes 1 -MaxTargetTPS 50 -Verbose }" > d:\RawrXD\test_output.txt 2>&1
echo Test completed. Check d:\RawrXD\test_output.txt for results.
