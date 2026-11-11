# Drop 06 / 15 — Atmospheric Sky, Clouds, Fog, and Water

Additive to Drops 01–05. Native C++20, no third-party runtime dependencies.

## Fifteen reference functions
1. Saturation clamp
2. Vector normalization
3. Vector dot product
4. Deterministic 3D hash
5. Smooth 3D value noise
6. 3D fractal Brownian motion
7. Procedural sky color
8. Sun disc radiance mask
9. Layered cloud density
10. Cloud shadow attenuation
11. Exponential fog transmittance
12. Fog color compositing
13. Multi-wave water displacement
14. Analytic finite-difference water normal
15. Deterministic sky image generation

## Added source and shaders
`src/atmosphere/atmosphere.hpp`, `.cpp`, `atmosphere_cli.cpp`, `tests/atmosphere_tests.cpp`, `shaders/atmosphere_sky.frag`, `shaders/atmosphere_fog.glsl`, `shaders/water_surface.frag`.

## Commands
`cmake -S . -B build && cmake --build build --parallel && ctest --test-dir build --output-on-failure`

`./build/worldforge-sky-bake sky.ppm 20261025 960 540`

## Integration boundary
These are deterministic CPU reference routines, a sky fragment shader, a reusable fog helper, and an illustrative water shader. They are NOT yet connected to the KartGib Vulkan render passes. No raymarched volumetric clouds, atmospheric multiple scattering, screen-space water reflection, refraction, cloud shadow-map GPU pass, GPU water mesh displacement, or physical water simulation is claimed. Integration requires shader bindings, pipeline creation, depth sampling, GPU resources, and scene scheduling.
