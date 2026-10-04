// LoomPromotion.cpp — RAWRXD_KERNEL_LOOM_LIVE_GEMV_BG8_001
//
// Derived values only. Every function here computes something from its inputs;
// none of them can be assigned a favourable value from outside.
#include "LoomPromotion.hpp"

namespace rawrxd::deep2::loom {

const char* ownershipName(Ownership o) {
    switch (o) {
        case Ownership::Bypass:      return "Bypass";
        case Ownership::Delegated:   return "Delegated";
        case Ownership::Owned:       return "Owned";
        case Ownership::Conditional: return "Conditional";
        case Ownership::Unknown:     return "Unknown";
    }
    return "Unknown";
}

namespace {
void mix(std::uint64_t& h, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        h ^= static_cast<std::uint8_t>(v >> (i * 8));
        h *= 1099511628211ull;
    }
}
void mixStr(std::uint64_t& h, const std::string& s) noexcept {
    mix(h, s.size());
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
}
} // namespace

std::uint64_t ExecutableIdentity::hash() const noexcept {
    std::uint64_t h = 14695981039346656037ull;
    mix(h, genomeHash);
    mix(h, materializerHash);
    mixStr(h, compilerId);
    mixStr(h, compilerFlags);
    mixStr(h, targetIsa);
    mix(h, generatedSourceHash);
    mix(h, binaryHash);
    return h;
}

std::uint64_t TrafficContract::bandwidthCeilingTps() const noexcept {
    if (physicalFreshBytesPerToken == 0) return 0;
    return sustainedBandwidthBytesPerSec / physicalFreshBytesPerToken;
}

std::uint64_t TrafficContract::minTrafficCollapse() const noexcept {
    if (physicalFreshBytesPerToken == 0) return 0;
    return logicalWeightBytes / physicalFreshBytesPerToken;
}

} // namespace rawrxd::deep2::loom
