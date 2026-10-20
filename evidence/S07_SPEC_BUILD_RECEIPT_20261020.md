# S07 build receipt — 2026-10-20

- CMake configure: exit `0` (`Visual Studio 17 2022`, `x64`)
- Target build: `cmake --build build --target deep2_spec_bench --config Release --parallel 2`
- Build exit: `0`
- Link fix: `src/utils/input_sanitizer.cpp` is now included in the `deep2_spec_bench` source list in `CMakeLists.txt`.
- Executable SHA-256: `96906CA228A21947B844F41978E7A8386955952CB1000946161E6B714881ACD8`
- Usage probe: executable returned its usage text with exit `2` when invoked without required `--model`, confirming the binary is runnable.
