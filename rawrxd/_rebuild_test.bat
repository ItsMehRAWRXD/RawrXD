@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d F:\~dev\rawrxd\build
cmake --build . --target test_generate_313_tokens --config Release
