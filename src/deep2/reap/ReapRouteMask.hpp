#pragma once
// Must be applied BEFORE top-k. No silent rerouting of already selected experts.
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
namespace Deep2::ReapRom {
inline void MaskUnretained(std::vector<float>& logits,
                           const std::vector<uint8_t>& retained,
                           uint32_t topK) {
    if(logits.empty() || logits.size()!=retained.size() || topK==0)
        throw std::invalid_argument("invalid REAP router mask");
    // Validate all input before mutation; failed masks leave logits untouched.
    uint32_t available=0;
    for(size_t i=0;i<logits.size();++i) {
        if(!std::isfinite(logits[i])) throw std::invalid_argument("nonfinite router logits");
        if(retained[i]) ++available;
    }
    if(available<topK) throw std::invalid_argument("insufficient retained experts");
    for(size_t i=0;i<logits.size();++i)
        if(!retained[i]) logits[i]=-std::numeric_limits<float>::infinity();
}
inline bool RouteIsRetained(const std::vector<uint32_t>& selected,
                            const std::vector<uint8_t>& retained) noexcept {
    for(uint32_t id:selected)
        if(id>=retained.size() || !retained[id]) return false;
    return true;
}
} // namespace Deep2::ReapRom
