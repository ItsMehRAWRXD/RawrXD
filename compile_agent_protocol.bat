@echo off
cd /d F:\rawrxd\~dev
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo
cl /std:c++17 /O2 /arch:AVX512 /EHsc /I. /IF:\rawrxd\~dev\src /IF:\rawrxd\3rdparty\ggml\src /IF:\rawrxd\3rdparty\ggml\include tests\rawr_agent_protocol_selftest.cpp F:\rawrxd\~dev\src\rawr_agent.cpp /Fe:rawr_agent_protocol_selftest.exe 2>&1