#pragma once
/*
===============================================================================
 SSM-CERT-001 probe — fixed-size digest frames only (no float buffer copies)
===============================================================================
 Observes the existing experimental computeSSM path. Does not change math.
 When disabled, record*() are no-ops. STREAMER sequencing untouched.
 ATTN-CERT evidence directory must remain frozen.
===============================================================================
*/
#include <cstdint>
#include <vector>

namespace Deep2 {
namespace SsmCert {

enum class Stage : std::uint8_t {
    Alpha = 1,
    Beta = 2,
    Conv = 3,
    StatePre = 4,
    StatePost = 5,
    Norm = 6,
    Out = 7,
    SeqStep = 8
};

struct Frame {
    Stage stage = Stage::Alpha;
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
std::uint32_t seqStep();
std::uint32_t bumpSeq();
std::vector<Frame> snapshot();
void record(Stage stage, std::uint32_t layer, std::uint32_t position,
            const float* data, std::size_t n, double aux = 0.0);
const char* stageName(Stage s);

} // namespace SsmCert
} // namespace Deep2
