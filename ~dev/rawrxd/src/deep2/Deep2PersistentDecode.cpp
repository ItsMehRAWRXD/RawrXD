#include "Deep2PersistentDecode.hpp"

namespace Deep2::Roofline {

void PersistentDecode::beginModel(u64 modelGeneration) noexcept {
    generation_ = modelGeneration;
    token_ = 0;
    tokenOpen_ = false;
    steadyDescriptorRebuilds_ = 0;
    steadyWeightReuploads_ = 0;
    forwards_[0] = forwards_[1] = 0;
    uploadedWeights_.clear();
}

void PersistentDecode::beginToken(u64 tokenIndex) noexcept {
    token_ = tokenIndex;
    tokenOpen_ = true;
}

void PersistentDecode::noteDescriptorBuild() noexcept {
    // Token 0 is warmup / first materialization. Later rebuilds are steady-state cost.
    if (tokenOpen_ && token_ > 0) ++steadyDescriptorRebuilds_;
}

void PersistentDecode::noteWeightUpload(u64 stableWeightId) noexcept {
    const auto inserted = uploadedWeights_.insert(stableWeightId).second;
    if (!inserted && tokenOpen_ && token_ > 0) ++steadyWeightReuploads_;
}

void PersistentDecode::noteForward(unsigned gpu) noexcept {
    if (gpu < 2) ++forwards_[gpu];
}

void PersistentDecode::endToken() noexcept { tokenOpen_ = false; }

} // namespace Deep2::Roofline
