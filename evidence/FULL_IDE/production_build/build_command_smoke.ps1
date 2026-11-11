$ErrorActionPreference = 'Stop'
$taskRoot = 'F:\rawrxd'
$evidenceDir = Join-Path $taskRoot 'evidence\FULL_IDE\production_build'
$buildDir = Join-Path $evidenceDir 'build'
$objects = @(Get-ChildItem -LiteralPath (Join-Path $buildDir 'RawrXD-Win32IDE-Native.dir\Release') -Filter '*.obj' -File | Where-Object Name -ne 'main_win32.obj' | ForEach-Object { '"' + $_.FullName + '"' })
$libs = @('comctl32','comdlg32','shell32','user32','gdi32','ole32','oleaut32','uuid','advapi32','d3d11','dxgi','d3dcompiler','d2d1','dwrite','dxguid','dwmapi','dcomp','kernel32') | ForEach-Object { $_ + '.lib' }
foreach ($name in @('ggml','ggml-cpu','ggml-base')) { $libs += '"' + (Join-Path $buildDir "3rdparty\ggml\src\Release\$name.lib") + '"' }
$smokeExe = Join-Path $evidenceDir 'win32_command_dispatch_smoke.exe'
$smokeObj = Join-Path $evidenceDir 'win32_command_dispatch_smoke.obj'
$compile = 'cl /nologo /std:c++20 /EHsc /MD /O2 /DNOMINMAX /DHAVE_GGML=1 /D_WIN32_WINNT=0x0A00 /I"F:\rawrxd\src" /I"F:\rawrxd\src\win32app" /I"F:\rawrxd\include" /I"F:\rawrxd\3rdparty\ggml\include" /I"C:\VulkanSDK\1.4.357.0\include" /c "' + (Join-Path $evidenceDir 'win32_command_dispatch_smoke.cpp') + '" /Fo"' + $smokeObj + '"'
$link = 'link /nologo /SUBSYSTEM:CONSOLE /OUT:"' + $smokeExe + '" "' + $smokeObj + '" ' + ($objects -join ' ') + ' ' + ($libs -join ' ')
$batch = @('@echo off','call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"',$compile,'if errorlevel 1 exit /b 1',$link,'exit /b %errorlevel%')
$batch | Set-Content -LiteralPath (Join-Path $evidenceDir 'build_command_smoke.cmd') -Encoding ASCII
& (Join-Path $evidenceDir 'build_command_smoke.cmd') *> (Join-Path $evidenceDir 'command_smoke_build.log')
$code = $LASTEXITCODE
Get-Content (Join-Path $evidenceDir 'command_smoke_build.log') -Tail 25
Write-Output "SMOKE_BUILD_EXIT=$code"
exit $code
