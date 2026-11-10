# KartGib WorldForge — Drop 08 of 15

## Terrain streaming, caves, bridges, and world LOD

This additive native C++20 source drop adds 15 entry-point capabilities:

1. 64-bit deterministic seed hashing (`mix64`)
2. World-position to signed chunk-key mapping (`keyAt`)
3. Seeded multi-octave terrain height sampling (`heightAt`)
4. Procedural cave scalar field (`caveField`)
5. Cave solid/void classification (`caveSolid`)
6. Indexed terrain chunk mesh generation with vertex normals (`buildTerrainChunk`)
7. Cave occupancy-mask generation (`buildCaveMask`)
8. Deterministic chunk geometry fingerprinting (`fingerprint`)
9. Distance-based mesh LOD selection (`lodForDistance`)
10. Camera-centered desired chunk set (`desiredChunks`)
11. Circle/AABB chunk visibility rejection (`intersectsViewRadius`)
12. Parametric bridge deck mesh generation (`buildBridge`)
13. Fail-fast streaming configuration validation (`validConfig`)
14. Bounded resident chunk cache, active set, deterministic LRU eviction (`ChunkStreamer`)
15. Structured chunk manifest export (`exportChunkManifest`)

### Build and test

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\worldforge-streaming-cli.exe --seed 20261025 --x 0 --z 0 --radius 2 --out generated\streaming\chunks.json
```

### Integration boundary

This is a standalone **CPU chunk generation/streaming reference**, not a GPU terrain streamer. Cave masks are occupancy samples, not excavated manifold cave meshes. Bridges are simple deck meshes, not structural collision geometry. Existing KartGib renderer integration, asynchronous generation, memory-budget accounting, crack-free mixed-LOD seams, terrain material blending, GPU uploads, and gameplay collision remain unimplemented. The chunk cache uses deterministic synchronous generation; for production, move generation off the render thread and use explicit lifetime synchronization.

### Acceptance

The streaming regression suite checks signed chunk coordinates, deterministic geometry, matching neighboring edges at the same LOD, mesh indexing, cache hits, bounded eviction, manifest output, cave classification, and bridge topology.
