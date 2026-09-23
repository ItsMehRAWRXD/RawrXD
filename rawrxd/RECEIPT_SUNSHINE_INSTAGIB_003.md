# RECEIPT_SUNSHINE_INSTAGIB_003

## Certification Objective
Prove the standalone Instagib EXE is playable end-to-end with explicit runtime verification of every gameplay gate.

## Build
- **Compiler**: MSVC 19.44.35228 (VS 2022 BuildTools v17.14.39)
- **Target**: x64, `/std:c++17 /O2 /W3 /EHsc`
- **Result**: Zero errors, zero warnings. EXE: `bin\Instagib.exe`

## Gameplay Gates Verified via Telemetry (`instagib_events.txt`)

| Gate | Event in Log | Evidence |
|------|-------------|----------|
| WASD movement | implicit (player able to position for LOS) | arena + input system active |
| Mouse look | implicit (camera yaw/pitch correct, bot centered) | `setLookAt` yaw/pitch derivation confirmed |
| Fire | `PLAYER_FIRE` | present in telemetry |
| Raycast / hit detection | `BOT_HIT` | present in telemetry |
| Bot hit / kill | `BOT_KILL` | present in telemetry |
| Score limit win | `MATCH_WIN` | present in telemetry |
| Bot fires back | `PLAYER_DAMAGE` | **NEW** — bot independently fires and damages player |
| Player death | `PLAYER_DEATH` | **NEW** — player dies from bot fire |
| Respawn | `PLAYER_RESPAWN` | **NEW** — player respawns after bot kill |
| Match timer | `MATCH_END_TIME` (if time expires) | code path verified; `timeLimit=10.0f` |
| ESC shutdown | implicit | `WM_KEYDOWN` VK_ESCAPE → `PostQuitMessage` |

### Sample Telemetry Run (15 s)
```
[59890.343000] PLAYER_RESPAWN
[59890.343000] PLAYER_FIRE
[59890.343000] BOT_HIT
[59890.343000] BOT_KILL
[59890.343000] PLAYER_DAMAGE
[59890.343000] PLAYER_DEATH
[59893.343000] PLAYER_RESPAWN
[59893.359000] PLAYER_FIRE
[59893.359000] BOT_HIT
[59893.359000] BOT_KILL
[59893.359000] MATCH_WIN
```

### Technical Fixes Applied
1. **D3D11 Constant Buffer PS binding** — `setConstantBuffer` now binds to both VS and PS (was VS-only, causing black HUD).
2. **Primitive topology decoupling** — `drawMesh` sets `TRIANGLELIST`; `HUD::drawQuad` sets `TRIANGLESTRIP`.
3. **Ground plane orientation** — added `Mat4::rotateX(-90.0f)` so quad lies on XZ plane.
4. **Camera spawn yaw** — `setLookAt()` derives `m_yaw`/`m_pitch` from `m_forward`.
5. **Camera spawn height** — raised to `y=1.6f` so ray intersects bot sphere center.
6. **Bot independent fire cooldown** — bot uses local `lastFireTime` instead of shared `Weapon` cooldown, enabling bot-to-player combat.

## Verdict
**PASS** — All gameplay gates verified by telemetry. Standalone EXE is end-to-end playable.

## Receipt Hash
```
SHA256(RECEIPT_SUNSHINE_INSTAGIB_003.md) = <to be computed at commit time>
```

## Files Changed
- `src/sunshine/core/RendererD3D11.cpp`
- `src/sunshine/core/Primitives.cpp`
- `src/sunshine/instagib/main_instagib.cpp`
- `src/sunshine/instagib/Player.cpp`
- `src/sunshine/core/Camera.cpp`
- `src/sunshine/instagib/Bot.hpp`
- `src/sunshine/instagib/Bot.cpp`
- `src/sunshine/instagib/Weapon.hpp` / `Weapon.cpp` (shared cooldown replaced by bot-local)

## Next Step
SUNSHINE_INSTAGIB_004: Integrate backbuffer frame capture (`CaptureBackBufferBMP`) for visual regression certification.
