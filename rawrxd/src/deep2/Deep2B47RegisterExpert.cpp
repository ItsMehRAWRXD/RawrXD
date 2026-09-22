#include "Deep2B47RegisterExpert.hpp"
#include <algorithm>

namespace Deep2 {

B47RegisterExpertPlan B47RegisterExpert::make(uint32_t intermediate,
                                              std::vector<uint32_t> experts,
                                              std::vector<uint32_t> devices,
                                              uint32_t maxConcurrent) noexcept {
    B47RegisterExpertPlan p{};
    p.concurrentExperts = std::max(1u, std::min(maxConcurrent,
                               static_cast<uint32_t>(experts.size())));
    p.rowsPerSlice = intermediate >= 32768 ? 2048u :
                     (intermediate >= 16384 ? 1024u : 512u);

    for (size_t i=0; i<experts.size(); ++i) {
        const uint32_t dev = i < devices.size() ? devices[i] : 0u;
        for (uint32_t rb=0; rb<intermediate; rb += p.rowsPerSlice) {
            const uint32_t re = std::min(intermediate, rb + p.rowsPerSlice);
            p.slices.push_back({experts[i], dev, rb, re, true, 0.0});
        }
    }
    return p;
}

uint64_t B47RegisterExpert::avoidedIntermediateBytes(uint32_t activeExperts,
                                                     uint32_t intermediate,
                                                     uint32_t scalarBytes) noexcept {
    // gate, up, activation, product written/read = eight scalar streams.
    return uint64_t(activeExperts) * uint64_t(intermediate) *
           uint64_t(scalarBytes) * 8ull;
}

}
