@echo off
cd /d d:\src\build-unified-final
set GCC=C:\ProgramData\mingw64\mingw64\bin\g++.exe

echo Linking RawrXDUnified.exe with all objects...

%GCC% -static-libgcc -static-libstdc++ -Wl,--subsystem,console -o RawrXDUnified.exe ^
    main_unified.obj ^
    RawrXDHost.obj ^
    AIServiceAdapter.obj ^
    CompilerAgent.obj ^
    ContextEngine.obj ^
    Deep2Provider.obj ^
    Deep2Engine.obj ^
    Deep2InferenceGateway.obj ^
    InferenceEngine.obj ^
    sampling.obj ^
    Tokenizer.obj ^
    advanced_sampler.obj ^
    -lws2_32 -lwinmm

if errorlevel 1 (
    echo FAILED
    exit /b 1
)

echo SUCCESS!
dir RawrXDUnified.exe
