# KartGib - Unity Competitor Game Engine

## Project Overview

KartGib is a native C++20 game engine being developed as a Unity competitor. It features a native Win32/Vulkan runtime with an integrated visual editor, scene graph, asset pipeline, and gameplay systems.

## Current Status

### Completed Systems

#### 1. WorldForge Integration (15/15 Tests PASS)
- Procedural terrain generation (terrain, track, props)
- HDR rendering pipeline (CPU reference)
- Shadow/lighting system (CPU reference)
- Procedural PBR material baker
- Architecture/foliage generator
- Terrain streaming with LOD, caves, bridges
- Arcade vehicle physics
- Projectile combat with particles
- Scene graph/document core
- Asset browser, transform, inspector
- Animation/audio/VM
- Multiplayer protocol with rollback/replay
- Cross-subsystem runtime integration
- Deterministic simulation (600-tick verified)
- All 15 CTest suites passing

#### 2. Vulkan Rendering Engine (G01-G04 PASS)
- Win32 native window
- Vulkan instance, device, swapchain
- Render pipeline with shaders
- Command buffers and synchronization
- Frame presentation (vkQueuePresentKHR verified)
- Deterministic world generation (16,641 vertices, 98,304 indices)
- GPU mesh upload and rendering
- Fixed-timestep game loop
- Chase camera system
- Terrain collision detection

#### 3. Entity Component System (ECS)
- Entity management with create/destroy
- Component system with type-safe storage
- Component addition/removal/query
- Scene graph with parent-child relationships
- Scene persistence (save/load)

#### 4. Asset Pipeline
- Model importer (FBX, OBJ, glTF, etc.)
- Texture importer (PNG, JPG, TGA, etc.)
- Audio importer (WAV, MP3, OGG, etc.)
- Asset metadata management
- Import queue with multi-threading
- Asset GUID system
- Dependency tracking

#### 5. Scene Serialization
- Binary scene format
- Entity serialization
- Component serialization
- Hierarchy preservation
- Save/load round-trip

#### 6. Animation System
- Skeletal animation system
- Animation clips with keyframes
- Animation state machines
- Blend trees
- Animation controller
- Play/pause/step controls

#### 7. Material System
- Material properties (float, color, texture)
- Shader integration
- PBR material support
- Material instances

### In Progress
- Native visual editor with Win32 + ImGui
- Scene hierarchy panel
- Inspector panel
- Asset browser
- Console/log panel
- Scene viewport with camera controls
- Play/pause/stop controls

### Planned (P0-P2)

#### P0 - Build Certification
- [x] Fix all CTest failures
- [x] Achieve repeatable 15/15 CTest
- [x] Real Vulkan integration
- [ ] Native editor shell
- [ ] Scene editing
- [ ] Project system
- [ ] Asset pipeline
- [ ] Entity/component architecture
- [ ] Play-in-editor
- [ ] Rendering productionization
- [ ] Physics engine
- [ ] Scripting system

#### P1 - Competitiveness
- Animation system
- UI system
- Audio engine
- Terrain/world tools
- Networking
- Profiling/debugging

#### P2 - Ecosystem
- Plugin/extensions API
- Production infrastructure
- Documentation
- CI/CD

## Build Instructions

### Prerequisites
- Visual Studio 2022 (MSVC)
- Vulkan SDK 1.4.357+
- CMake 3.20+
- GLFW3

### Build Commands
```powershell
# Configure
cmake -S F:\rawrxd\kartgib -B F:\rawrxd\kartgib\build\msvc -G "Visual Studio 17 2022" -A x64

# Build
cmake --build F:\rawrxd\kartgib\build\msvc --config Release --parallel 8

# Run
F:\rawrxd\kartgib\build\msvc\Release\KartGibEditor.exe --seed 20261025 --biome tropical
```

## Editor Controls

| Key | Action |
|-----|--------|
| W/A/S/D | Drive kart / Move camera |
| F5 | Save scene |
| F9 | Load scene |
| F6 | Record input |
| F7 | Replay input |
| F8 | Debug triangle mode |
| ESC | Quit |

## Architecture

```
KartGib Editor
├── Native Win32 + Vulkan Runtime
│   ├── Renderer / Materials / Lighting
│   ├── Audio / Input / Camera
│   └── Frame Scheduling
├── WorldForge
│   ├── Procedural Terrain
│   ├── Biomes / Streaming
│   └── Deterministic Simulation
├── Gameplay Framework
│   ├── Entity / Component System
│   ├── Player Movement
│   ├── Weapons / Damage
│   ├── Vehicles / Cargo
│   ├── Physics / Collision
│   ├── AI / Bots
│   └── Missions / Objectives
├── Multiplayer
│   ├── Authoritative Server
│   ├── Replication / Interest Management
│   ├── Prediction / Reconciliation
│   └── Matchmaking / Sessions
├── Nine Game Modes
│   ├── Instagib Arena
│   ├── Tactical Ops
│   ├── Capture Arena
│   ├── Team Siege
│   ├── Neon Siege
│   ├── Neon Frontier
│   ├── Kart Instagib
│   ├── Contraband Run
│   └── BattleCore Warfront
└── Native WorldForge Editor
    ├── World / Scene Editor
    ├── Vehicle / Weapon Editor
    ├── Mission / Game Mode Editor
    └── Packaging / Build Tools
```

## Milestones

### Milestone 1: WorldForge Certification (COMPLETE)
- 15/15 CTest passing
- Deterministic simulation verified
- All portable subsystems tested

### Milestone 2: Vulkan Runtime (COMPLETE)
- Win32/Vulkan executable
- Procedural terrain rendering
- Kart physics and combat
- Scene persistence

### Milestone 3: Visual Editor (IN PROGRESS)
- Native Win32 editor
- Scene hierarchy
- Inspector panel
- Asset browser
- Play-in-editor

### Milestone 4: General-Purpose Engine (PLANNED)
- ECS/prefabs
- Asset import
- Scripting
- Animation
- Runtime UI

### Milestone 5: Shipping Toolchain (PLANNED)
- Game packaging
- Profiling
- Crash recovery
- Documentation

## License

Proprietary - Sunshine KartGib Engine

## Contact

RawrXD Autonomous Engineering Loop