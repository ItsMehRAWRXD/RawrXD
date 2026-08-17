@echo off
cd d:\src\build-unified-final
set GCC=C:\ProgramData\mingw64\mingw64\bin\g++.exe

echo Linking RawrXDUnified.exe...

%GCC% -static-libgcc -static-libstdc++ -Wl,--subsystem,console -o RawrXDUnified.exe main_unified.obj RawrXDHost.obj AIServiceAdapter.obj CompilerAgent.obj ContextEngine.obj Deep2Provider.obj Deep2Engine.obj Tokenizer.obj advanced_sampler.obj -lws2_32 -lwinmm

if errorlevel 1 (
    echo FAILED
    exit /b 1
)

echo SUCCESS!
dir RawrXDUnified.exe
