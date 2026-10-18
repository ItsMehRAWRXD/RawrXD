#pragma once
#include <cstdint>

namespace Deep2 {

enum class B36WaveMode : uint8_t { WAVE_32=32, WAVE_64=64 };

struct B36WaveDotShape {
    uint32_t rows = 0;
    uint32_t cols = 0;
    B36WaveMode wave = B36WaveMode::WAVE_64;
    uint32_t bitsPerWeight = 4;
    uint32_t block = 32;
};

struct B36WaveDotPlan {
    uint32_t waveWidth = 64;
    uint32_t lanesPerWave = 64;
    uint32_t dotOpsPerLane = 8;
    uint32_t accumulatorsPerWave = 4;
    uint32_t rowsPerWavePass = 4;
    bool waveDotInstruction = true;
    bool crosslaneReduce = true;
    bool registerBlocking = true;
    bool noScalarFallback = true;
};

class B36WaveDot {
public:
    static B36WaveDotPlan make(const B36WaveDotShape&) noexcept;
    static uint64_t packedBytes(const B36WaveDotShape&) noexcept;
    static double dotOpsPerCycle(const B36WaveDotShape&) noexcept;
};

} // namespace Deep2