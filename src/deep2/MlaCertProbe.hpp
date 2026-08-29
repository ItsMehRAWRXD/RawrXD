#pragma once
/*
===============================================================================
 MLA-CERT-001 probe — fixed-size digest frames only
===============================================================================
 Observes MLA load/forward gates. Does not implement MLA attention.
 Incomplete forward remains fail-closed. STREAMER untouched.
 ATTN/SSM evidence directories remain frozen.
===============================================================================
*/
#include <cstdint>
#include <vector>

namespace Deep2 {
namespace MlaCert {

enum class Stage : std::uint8_t {
    Detected = 1,
    EnteredBlocked = 2,
    Qa = 3,
    Kva = 4,
    Qb = 5,
    Kvb = 6,
    Rope = 7,
    AttnOut = 8,
    OProj = 9,
    SeqStep = 10
};

struct Frame {
    Stage stage = Stage::Detected;
    std::uint32_t layer = 0;
    std::uint32_t position = 0;
    std::uint32_t count = 0;
    std::uint32_t nonfinite = 0;
    double min = 0.0;
    double max = 0.0;
    double l2 = 0.0;
    double sum = 0.0;
    double sumAbs = 0.0;
    double aux = 0.0;
    std::uint64_t fnv = 0;
};

void enable(bool on);
bool enabled();
void clear();
void resetSeq();
std::uint32_t bumpSeq();
std::vector<Frame> snapshot();
void record(Stage stage, std::uint32_t layer, std::uint32_t position,
            const float* data, std::size_t n, double aux = 0.0);
const char* stageName(Stage s);

} // namespace MlaCert
} // namespace Deep2
