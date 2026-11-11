# KartGib WorldForge — Drop 09 of 15

## Deterministic arcade vehicle physics foundation

Adds 15 functional entry points to the cumulative native C++20 package:

1. `clamp` — scalar saturation
2. `valid` — vehicle configuration validation
3. `sanitize` — bounded controls and nonfinite input protection
4. `forward` — vehicle forward basis
5. `right` — vehicle lateral basis
6. `stoppingDistance` — friction-adjusted braking estimate
7. `steeringYawRate` — bicycle-model steering response
8. `suspensionForce` — spring/damper reference
9. `sphereAabb` — sphere vs axis-aligned obstacle contact
10. `resolveContact` — positional separation and horizontal velocity attenuation
11. `wheelPose` — basic wheel transform and spin approximation
12. `step` — fixed-step arcade dynamics, traction, braking, drag, boost, suspension, and ground contact
13. `simulate` — deterministic input replay
14. `fingerprint` — deterministic state hash
15. `worldforge-vehicle-cli` — telemetry CSV simulation and reproducible output

### Build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\worldforge-vehicle-cli.exe --ticks 600 --out generated\vehicle.csv
```

The CLI's output directory must exist before running.

### Integration boundaries

This is a portable CPU reference for arcade kinematics, **not a production rigid-body physics engine**. It has no continuous collision detection, contact manifold solver, tire slip curves, terrain triangle-mesh collision, vehicle-to-vehicle dynamics, netcode, or live KartGib Vulkan integration. The suspension reference uses a single vertical spring, not four independent wheel raycasts. The `wheelPose` steering angle is a placeholder pending a stored steering state. Numerical determinism is guaranteed for repeated runs on the same build/platform and inputs, not cross-compiler bit-identical lockstep. Use a fixed simulation tick and retain authoritative collision/physics verification before multiplayer admission.
