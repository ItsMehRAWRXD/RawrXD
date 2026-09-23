@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d f:\~dev\rawrxd
cl /std:c++17 /EHsc /I. /Isrc /Isrc\sunshine\core /Isrc\sunshine\neonsiege /O2 /W3 /Fe:bin\NeonSiege.exe ^
    src\sunshine\neonsiege\main_neonsiege.cpp ^
    src\sunshine\neonsiege\neonsiege_core.cpp ^
    src\sunshine\neonsiege\HUD.cpp ^
    src\sunshine\core\WindowWin32.cpp ^
    src\sunshine\core\RendererD3D11.cpp ^
    src\sunshine\core\Input.cpp ^
    src\sunshine\core\Timer.cpp ^
    src\sunshine\core\Camera.cpp ^
    src\sunshine\core\Primitives.cpp ^
    /link d3d11.lib dxgi.lib d3dcompiler.lib user32.lib gdi32.lib
