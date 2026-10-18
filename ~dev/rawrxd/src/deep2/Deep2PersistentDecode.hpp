#pragma once
#include "Deep2RooflineCommon.hpp"
#include <unordered_set>

namespace Deep2::Roofline {

class PersistentDecode {
public:
    void beginModel(u64 modelGeneration) noexcept;
    void beginToken(u64 tokenIndex) noexcept;
    void noteDescriptorBuild() noexcept;
    void noteWeightUpload(u64 stableWeightId) noexcept;
    void noteForward(unsigned gpu) noexcept;
    void endToken() noexcept;

    u64 steadyDescriptorRebuilds() const noexcept { return steadyDescriptorRebuilds_; }
    u64 steadyWeightReuploads() const noexcept { return steadyWeightReuploads_; }
    u64 forwardCount(unsigned gpu) const noexcept { return gpu < 2 ? forwards_[gpu] : 0; }
    bool tokenOpen() const noexcept { return tokenOpen_; }

private:
    u64 generation_ = 0;
    u64 token_ = 0;
    bool tokenOpen_ = false;
    u64 steadyDescriptorRebuilds_ = 0;
    u64 steadyWeightReuploads_ = 0;
    u64 forwards_[2]{};
    std::unordered_set<u64> uploadedWeights_;
};

} // namespace Deep2::Roofline
