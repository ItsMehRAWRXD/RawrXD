#pragma once
/*
===============================================================================
 ATTN-CERT-001 probe — fixed-size digest frames only (no float buffer copies)
===============================================================================
 Does not change generation math. When disabled, record*() are no-ops.
 STREAMER sequencing is intentionally untouched.
 Never re-enable deep2cert_bridge::stage() here (known stack overrun).
===============================================================================
*/
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace AttnCert {

enum class Stage : std::uint8_t {
    AttnNorm = 1,
    QProj = 2,
    KProj = 3,
    VProj = 4,
    RopeQ = 5,
    RopeK = 6,
    KvWrite = 7,
    PreSoftmax = 8,
    Softmax = 9,
    AttnOut = 10,
    OProj = 11,
    ResidualHint = 12,
    KvLength = 13
};

// Fixed-size digest — never embeds the activation buffer.
struct Frame {
    Stage stage = Stage::QProj;
    std::uint32_t layer = 0;
    std::uint32_t position = 0;
    std::uint32_t count = 0;
    std::uint32_t nonfinite = 0;
    double min = 0.0;
    double max = 0.0;
    double l2 = 0.0;
    double sum = 0.0;
    double sumAbs = 0.0;
    double aux = 0.0; // softmax sum, kv length, rope mark, etc.
    std::uint64_t fnv = 0;
};

void enable(bool on);          // does NOT clear frames
bool enabled();
void clear();
std::vector<Frame> snapshot();
void record(Stage stage, std::uint32_t layer, std::uint32_t position,
            const float* data, std::size_t n, double aux = 0.0);
const char* stageName(Stage s);

} // namespace AttnCert
} // namespace Deep2
