# KartGib WorldForge — Native C++20 procedural world compiler

An independent, **buildable source drop** for Sunshine KartGib. No third-party runtime libraries. Standard C++20 only. Does **not** replace KartGib's existing Vulkan renderer or claim to implement a Unity-equivalent editor.

## Build on Windows (MSVC)

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\kartgib-worldforge.exe --seed 20261025 --biome tropical --out generated\sunshine
```

Also builds on Linux/macOS with CMake and a C++20 compiler for automated tests.

## Output

- `world.obj`: procedural terrain, road mesh, and low-detail placeholder environmental geometry (OBJ + normals).
- `heightmap.pgm`: 8-bit grayscale heightmap for visual inspection or ingestion.
- `world.json`: reproducible seed, biome, generation metrics and artifact names.

## Implemented

- Deterministic, seeded multioctave 2D noise terrain.
- Four biome height presets: tropical, gothic, voxel, floating (floating currently a height-style preset, **not** true suspended islands).
- Closed analytic spline-like periodic race track with varying radius, sampled to mesh.
- Per-vertex terrain normals, road normals, deterministic prop placement, simple box-based placeholders.
- Track-proximity prop exclusion.
- OBJ, PGM and JSON outputs, input validation and regression tests.

## Not implemented / integration needed

- Runtime Vulkan renderer, HDR, bloom, shadows, PBR material textures, water, fog, vegetation geometry, castles, detailed kart meshes, collision, vehicle physics, multiplayer, gameplay UI, in-editor manipulation, undo/redo, asset importers, hot reload, LOD/streaming, or AI generation.
- Track is closed by a periodic formula but **not yet validated** for curvature, grade, collisions, bridge clearance, or playability. The reported zero closure residual means mathematical periodicity, not a physical road-certification pass.
- Terrain and road can intersect because road clearance is sampled at track centers; add swept road-clearance and embankment/bridge generation before gameplay use.
- OBJ is for offline interchange; KartGib should eventually consume binary packed meshes and instance buffers.

## Integration plan for existing G:\\VSC0de KartGib

Keep KartGib intact. Compile `src/worldforge.cpp` into a separate static library, include `src/worldforge.hpp`, convert `kg::Mesh` vertices/indices to KartGib's existing Vulkan mesh upload format, and keep the current GameWorld/BVH implementation. Do not overwrite existing `src/track`, `src/renderer`, or shaders. Use this CLI first as an offline asset generator, then wire its `generate()` API behind a developer menu. Build and verify a clean branch before merging.

## Roadmap to the reference-image quality

1. HDR offscreen render target, exposure and bloom, ACES tone mapping.
2. Directional shadow maps, cascades, GPU profiling and LOD.
3. Material graph + generated tileable PBR texture sets.
4. Erosion terrain, biome masks, road cuts, water and atmospheric sky.
5. Grammar-based castles, trees, rocks, bridges, railings, modular karts.
6. Visual world editor, property inspector, asset browser, scene serialization, undo/redo.
7. Deterministic gameplay certification, AI/physics, networking and automated visual regression.

This is **phase 1 of a custom engine**, not the entire engine.


## Drop 03 — HDR foundation

See `DROP03.md`. Includes CPU golden reference and GLSL shaders. Build `worldforge-render-tests`; optionally `worldforge-shaders` if glslc is installed. **Not yet wired to KartGib Vulkan runtime.**


## Drop 04
See [DROP04.md](DROP04.md) for shadow and advanced lighting reference source and integration boundaries.

## Drop 05 — Procedural PBR materials
See `DROP05.md`. Adds `worldforge-materials` library, `worldforge-material-bake` CLI and `worldforge-materials-tests` (CTest). CPU-side deterministic material baking; Vulkan runtime integration pending.


## Drop 06 — Atmosphere
See `DROP06.md`. Build target `worldforge-sky-bake` exports a procedural sky PPM.


## Drop 07
See [DROP07.md](DROP07.md) for procedural foliage/architecture mesh generation, OBJ and placement manifest exports.

## Drop 08 — Terrain Streaming and World LOD

See [DROP08.md](DROP08.md) for the 15 new capabilities, CLI, tests, and integration boundaries. `worldforge-streaming-cli` generates a reproducible JSON chunk manifest. This package is not yet wired into KartGib's Vulkan runtime.

## Drop 09 — Vehicle simulation
See `DROP09.md`. Builds `worldforge-vehicle`, `worldforge-vehicle-tests`, and `worldforge-vehicle-cli` as a standalone deterministic arcade-vehicle reference.


## Drop 10
See [DROP10.md](DROP10.md) for combat source, tests, and integration limitations.


Drop 11: native scene document core; see DROP11.md.


## Drop 12
See [DROP12.md](DROP12.md) for native editor tools, asset browser and tests.
