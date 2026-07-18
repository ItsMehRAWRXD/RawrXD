@echo off
setlocal EnableDelayedExpansion

set "inputFile=val016_repair_orchestrator.cpp"
set "tempFile=val016_repair_orchestrator_temp.cpp"

if exist "%tempFile%" del "%tempFile%"

set "found=0"
for /f "delims=" %%a in ('type "%inputFile%"') do (
    set "line=%%a"
    set "newLine=!line:std::regex errorPattern(R"((.+?)\((\d+)(?:,(\d+))?\)\s*:\s*(error|warning)\s+([A-Z]\d+)\s*:\s*(.+?)$))");=std::regex errorPattern(R"~~~((.+?)\((\d+)(?:,(\d+))?\)\s*:\s*(error|warning)\s+([A-Z]\d+)\s*:\s*(.+?)$)~~~");!"
    echo !newLine!>>"%tempFile%"
)

move /y "%tempFile%" "%inputFile%"
echo Done
