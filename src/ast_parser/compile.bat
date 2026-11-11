@echo off
setlocal

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe" /c /O2 /EHsc /std:c++latest /I. ASTContextProvider.cpp /Fod:\rawrxd\build-ninja\src\ast_parser\ASTContextProvider.obj

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed
    exit /b 1
)

echo Compilation successful
endlocal