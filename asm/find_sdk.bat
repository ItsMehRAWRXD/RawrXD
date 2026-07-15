@echo off
echo Searching for Windows SDK...
if exist "C:\Program Files (x86)\Windows Kits\10\Include" (
    dir /b "C:\Program Files (x86)\Windows Kits\10\Include"
) else (
    echo Windows SDK not found at standard location
)

if exist "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC" (
    dir /b "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC"
)
