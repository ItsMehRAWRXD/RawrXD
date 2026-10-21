@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set SRC=G:\wt_voxel
set OUT=G:\wt_voxel\build\voxel_direct
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelWorld.cpp" /Fo:"%OUT%\VoxelWorld.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelMesher.cpp" /Fo:"%OUT%\VoxelMesher.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelRenderer.cpp" /Fo:"%OUT%\VoxelRenderer.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelRasterizer.cpp" /Fo:"%OUT%\VoxelRasterizer.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\tools\voxel_render_certify.cpp" /Fo:"%OUT%\certify.obj" || exit /b 1
link /nologo /OUT:"%OUT%\voxel_render_certify.exe" ^
   "%OUT%\VoxelWorld.obj" "%OUT%\VoxelMesher.obj" "%OUT%\VoxelRenderer.obj" "%OUT%\VoxelRasterizer.obj" "%OUT%\certify.obj" ^
   d3d12.lib dxgi.lib d3dcompiler.lib user32.lib /MACHINE:X64 || exit /b 1
echo BUILD_OK
exit /b 0
