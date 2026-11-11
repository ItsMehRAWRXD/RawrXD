# Drop 05 / 15 — Procedural PBR Materials and Textures

Additive to Drops 01–04. Native C++20, no third-party runtime dependencies.

## Fifteen new material functions
1. Deterministic 2D integer hash
2. Smooth value noise
3. Fractal Brownian motion
4. Voronoi cellular noise
5. Smoothstep shaping
6. Fifteen PBR surface presets
7. Asphalt grain
8. Dashed road marking mask
9. Alternating kerb stripes
10. Stone mortar mask
11. Terrain height/slope blend weight
12. Metallic edge wear
13. Height-to-tangent-normal conversion
14. Deterministic four-map material baking (albedo, normal, ORM, emissive)
15. PPM albedo export

Surfaces: asphalt, line, kerb, stone, rock, sand, grass, snow, painted metal, bare metal, neon, dirt, foliage, water, glass.

## Commands
`cmake -S . -B build && cmake --build build --parallel && ctest --test-dir build --output-on-failure`

`./build/worldforge-material-bake asphalt asphalt.ppm 20261025 512`

## Integration boundary
The generated PBR texture arrays are CPU-side references; no Vulkan descriptor/image upload, texture compression, mipmaps, bindless materials, editor integration, or physically correct transparency/refraction is claimed. PPM writes only the albedo map; normal/ORM/emissive remain accessible through the C++ `TextureSet` API. Material sampling and color-space conversions must be adapted to the existing KartGib shader and asset pipeline. Procedural water/glass presets are *not* complete water/glass renderers.
