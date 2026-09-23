# NEON SIEGE — source-only drop

Native Win32 + D3D11. No third-party libraries, no external engine, no runtime assets.

## Build

Open an **x64 Native Tools Command Prompt for Visual Studio** and run:

```bat
build_neon_siege.bat
```

Equivalent direct compile:

```bat
cl /nologo /std:c++17 /EHsc /O2 /DUNICODE /D_UNICODE NeonSiege.cpp /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib d3d11.lib dxgi.lib d3dcompiler.lib /OUT:NeonSiege.exe
```

Windows SDK / MSVC libraries used:
- user32
- gdi32
- d3d11
- dxgi
- d3dcompiler

No NuGet/vcpkg/SDL/GLFW/DirectXTK/Unity/Unreal/Phaser dependencies.

## Controls

- Enter: start
- W/A/S/D: move
- Mouse or Left/Right arrows: turn
- Left mouse or Space: fire
- R: restart after victory/game over
- Esc: quit

## Included gameplay

- Wave 1: grunts
- Wave 2: grunts + gunners
- Wave 3: grunts + gunners + tanks
- Wave 4: boss + grunts
- health/fire-rate/damage/speed/overdrive pickups
- score, kills, lives, health
- player death/respawn
- game-over/restart
- victory
- boss HP bar
- neon primitive arena/HUD
- deterministic LCG spawn/drop stream
- machine-readable telemetry
- automatic backbuffer BMP captures

## Evidence

At runtime the executable creates:

```text
evidence/
  gameplay_events.txt
  neon_siege_summary.txt
  certification.txt
  startup.bmp
  wave1.bmp
  wave3.bmp
  boss.bmp
  victory.bmp
```

`certification.txt` uses the `SUNSHINE_NEON_SIEGE_001` receipt shape.

## Sunshine integration

The game-specific pieces are intentionally isolated by function:
- `SpawnEnemy`
- `StartWave`
- `ResetGame`
- `SpawnPickup`
- `ApplyPickup`
- `DamagePlayer`
- `Fire`
- `Update`
- `AutoCaptures`
- `WriteSummary`

If Sunshine already owns the window, D3D11 device, swapchain, frame loop, input, or capture path, keep those Sunshine systems and transplant only the game-state/enemy/pickup/wave functions. The standalone renderer exists so this source can run without depending on hidden local engine files.
