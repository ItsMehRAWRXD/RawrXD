#pragma once
#include <vector>
#include <cstdint>

namespace RawrXD::Runtime {

extern "C" float Vector_ComputeSimilarity(const float* q, const float* t);
extern "C" float Vector_CosineSimilarity(const float* a, const float* b, uint32_t dims);

class RawrXDVectorIndex {
public:
    static RawrXDVectorIndex& instance();
    float computeSimilarity(const std::vector<float>& query, const std::vector<float>& target);
};

} // namespace RawrXD::Runtime
