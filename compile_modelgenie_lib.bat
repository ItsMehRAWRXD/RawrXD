@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /std:c++20 /O2 /W4 /EHsc /I "F:\rawrxd\src\deep2\modelgenie" /I "F:\rawrxd\src" /I "F:\rawrxd\include" /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" /c "F:\rawrxd\src\deep2\modelgenie\ModelGenomeReader.cpp" /Fo"F:\rawrxd\build-modelgenie-tools\ModelGenomeReader.obj" > "F:\rawrxd\evidence\modelgenome_reader_compile.log" 2>&1
echo Compile ModelGenomeReader EXIT=%ERRORLEVEL%
cl /std:c++20 /O2 /W4 /EHsc /I "F:\rawrxd\src\deep2\modelgenie" /I "F:\rawrxd\src" /I "F:\rawrxd\include" /c "F:\rawrxd\src\deep2\QuantParityRegistry.cpp" /Fo"F:\rawrxd\build-modelgenie-tools\QuantParityRegistry.obj" > "F:\rawrxd\evidence\quant_parity_registry_compile.log" 2>&1
echo Compile QuantParityRegistry EXIT=%ERRORLEVEL%
cl /std:c++20 /O2 /W4 /EHsc /I "F:\rawrxd\src\deep2\modelgenie" /I "F:\rawrxd\src" /I "F:\rawrxd\include" /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" /c "F:\rawrxd\src\deep2\modelgenie\HeaderEmitter.cpp" /Fo"F:\rawrxd\build-modelgenie-tools\HeaderEmitter.obj" > "F:\rawrxd\evidence\header_emitter_compile.log" 2>&1
echo Compile HeaderEmitter EXIT=%ERRORLEVEL%
cl /std:c++20 /O2 /W4 /EHsc /I "F:\rawrxd\src\deep2\modelgenie" /I "F:\rawrxd\src" /I "F:\rawrxd\include" /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" /c "F:\rawrxd\src\deep2\modelgenie\ModelGenomeValidator.cpp" /Fo"F:\rawrxd\build-modelgenie-tools\ModelGenomeValidator.obj" > "F:\rawrxd\evidence\modelgenome_validator_compile.log" 2>&1
echo Compile ModelGenomeValidator EXIT=%ERRORLEVEL%
cl /std:c++20 /O2 /W4 /EHsc /I "F:\rawrxd\src\deep2\modelgenie" /I "F:\rawrxd\src" /I "F:\rawrxd\include" /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" "F:\rawrxd\tools\rawrxd_modelgenie_header_export.cpp" "F:\rawrxd\build-modelgenie-tools\ModelGenomeReader.obj" "F:\rawrxd\build-modelgenie-tools\QuantParityRegistry.obj" "F:\rawrxd\build-modelgenie-tools\HeaderEmitter.obj" "F:\rawrxd\build-modelgenie-tools\ModelGenomeValidator.obj" /Fe"F:\rawrxd\build-modelgenie-tools\bin\rawrxd_modelgenie_header_export.exe" > "F:\rawrxd\evidence\header_export_link.log" 2>&1
echo Link header_export EXIT=%ERRORLEVEL%
