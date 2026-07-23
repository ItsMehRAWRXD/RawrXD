#pragma once
#include "ReverseTypes.hpp"

namespace rxd::reverse {

class ReverseEngine {
public:
    explicit ReverseEngine(const ReverseModel& model);

    Reconstruction Reconstruct(const uint8_t* data, size_t size);
    std::vector<Match> Scan(const uint8_t* data, size_t size);

private:
    ReverseModel model_;

    double ScoreMatch(const Pattern& pat, const uint8_t* data, size_t offset, size_t size);
    bool VerifyMaskedMatch(const Pattern& pat, const uint8_t* data, size_t offset, size_t size);

    // SIMD scan dispatchers
    std::vector<Match> ScanScalar(const uint8_t* data, size_t size);
#if defined(__AVX2__)
    std::vector<Match> ScanAVX2(const uint8_t* data, size_t size);
#endif
#if defined(__AVX512F__) && defined(__AVX512BW__)
    std::vector<Match> ScanAVX512(const uint8_t* data, size_t size);
#endif
};

} // namespace rxd::reverse
