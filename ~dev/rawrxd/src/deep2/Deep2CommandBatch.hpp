#pragma once
#include "Deep2RooflineCommon.hpp"
#include <vector>

namespace Deep2::Roofline {

enum class KernelKind : u32 {
    RmsNormResidual,
    Qkv,
    Rope,
    Attention,
    OProj,
    MoeRouter,
    MoeGateUp,
    SiluMul,
    MoeDown,
    FinalNorm,
    LmHead
};

struct KernelOp {
    KernelKind kind{};
    u32 gpu = 0;
    u32 layer = 0;
    u32 rowBegin = 0;
    u32 rowCount = 0;
    u64 bytes = 0;
    u64 opaque0 = 0;
    u64 opaque1 = 0;
};

class CommandBatch {
public:
    void clear() { ops_.clear(); }
    void push(const KernelOp& op) { ops_.push_back(op); }
    const std::vector<KernelOp>& ops() const noexcept { return ops_; }
    u64 bytes() const noexcept;
    u32 gpuOps(unsigned gpu) const noexcept;
private:
    std::vector<KernelOp> ops_;
};

struct BackendOps {
    void* user = nullptr;
    bool (*prefetchExpert)(void*, unsigned gpu, u32 layer, u32 expert, u64 bytes) = nullptr;
    bool (*submitBatch)(void*, unsigned gpu, const KernelOp*, std::size_t) = nullptr;
    bool (*waitGpu)(void*, unsigned gpu) = nullptr;
};

} // namespace Deep2::Roofline
