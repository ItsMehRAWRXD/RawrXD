# Drop 13 of 15 — Animation, Audio and Scripting

Portable C++20, no additional runtime dependencies.

15 feature groups: (1) keyframe track validation, (2) linear vector interpolation, (3) looping timeline, (4) pose keyframe sampling, (5) pose blending, (6) ADSR envelope, (7) four waveform oscillators, (8) offline note synthesis, (9) audio mixing, (10) one-pole low-pass, (11) feedback delay, (12) PCM16 WAV writer, (13) strict bounded script compiler, (14) time-sliced deterministic VM with event emission, (15) state fingerprinting.

The scripting language supports set/add/mul/wait/emit/jlt/stop and 16 numeric registers. It does not access files, networking, OS APIs, or the game world. Instruction budgets prevent infinite loops per tick. The VM is not a general purpose programming language.

Audio is offline WAV synthesis; no real-time audio device integration. Animation is reference math, not skeletal skinning or editor playback. No Win32/Vulkan runtime integration is claimed.

Build: `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure`
Demo: `./build/worldforge-gameplay-cli demo.wav`
