# Drop 15 — Cross-subsystem integration and release audit

This delivery wires the standalone vehicle physics, combat, and editor scene graph into a fixed-step integration runner with repeatable command replay. It does not wire the real Win32/Vulkan game executable, WinSock multiplayer, GPU render graph, or interactive editor.

15 integration/release deliverables: (1) integration CMake library; (2) integrated runtime lifecycle; (3) deterministic reset; (4) fixed 60Hz tick; (5) vehicle command dispatch; (6) projectile spawn from vehicle pose; (7) projectile advancement; (8) particle advancement; (9) combat target initialization; (10) scene kart transform synchronization; (11) target visibility synchronization; (12) combined per-frame fingerprints; (13) command replay; (14) scene export; (15) integrated CLI and CTest regression.

## Remaining release blockers
- Real Windows/MSVC compilation and Vulkan runtime integration
- Render graph and GPU upload path for procedural assets, shadows, HDR, atmosphere, particles
- Interactive native Win32 editor controls, viewports, gizmos
- WinSock networking, authentication, anti-cheat and hostile-input fuzzing
- Terrain-aware vehicle physics, world collisions, streaming scene synchronization
- Performance, long-running soak, security, packaging and installer certification

Passing portable CTest suites does not imply Unity feature parity or production certification.
