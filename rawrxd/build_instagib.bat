@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d f:\~dev\rawrxd
cl /std:c++17 /EHsc /I. /Isrc /Isrc\sunshine\core /Isrc\sunshine\instagib /O2 /W3 /Fe:bin\Instagib.exe ^
    src\sunshine\instagib\main_instagib.cpp ^
    src\sunshine\instagib\Game.cpp ^
    src\sunshine\instagib\Player.cpp ^
    src\sunshine\instagib\Bot.cpp ^
    src\sunshine\instagib\Weapon.cpp ^
    src\sunshine\instagib\HUD.cpp ^
    src\sunshine\instagib\Arena.cpp ^
    src\sunshine\core\WindowWin32.cpp ^
    src\sunshine\core\RendererD3D11.cpp ^
    src\sunshine\core\Input.cpp ^
    src\sunshine\core\Timer.cpp ^
    src\sunshine\core\Camera.cpp ^
    src\sunshine\core\Primitives.cpp ^
    /link d3d11.lib dxgi.lib d3dcompiler.lib user32.lib gdi32.lib
