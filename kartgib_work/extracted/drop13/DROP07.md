# Drop 07 / 15 — Procedural Vegetation, Buildings and Architecture

Cumulative Drops 01–07. Native C++20, no new runtime dependencies.

## Fifteen capabilities
1. Seeded asset hashing
2. Deterministic random values
3. Parametric box meshes
4. Parametric cylinder meshes
5. Parametric cone meshes
6. Procedural broadleaf trees
7. Procedural palms
8. Procedural rocks
9. Procedural houses
10. Procedural towers
11. Procedural bridges
12. Procedural arches
13. Procedural fences
14. Asset mesh bounds, translation and indexed mesh composition
15. Biome-dependent deterministic prop catalogs, OBJ export and JSON placement manifests

## Build and run
```sh
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/worldforge-assets-cli --seed 20261025 --biome tropical --count 300 --out generated/assets
```

## Integration boundaries
These are intentionally simple procedural prototype meshes, not film-quality authored assets. OBJ export includes base meshes; the placement manifest carries instance transforms and must be consumed by the existing KartGib renderer or an offline baking step. Terrain height snapping, collision and gameplay registration, UV atlases, LOD mesh generation, foliage wind, GPU upload and Vulkan draw integration are NOT included. No live KartGib integration is claimed.
