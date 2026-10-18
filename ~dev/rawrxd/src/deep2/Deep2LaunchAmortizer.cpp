#include "Deep2LaunchAmortizer.hpp"

namespace Deep2 {

std::vector<LaunchBatch> LaunchAmortizer::build(bool useMLA, bool useMoE) noexcept {
    std::vector<LaunchBatch> out;
    LaunchBatch attn;
    attn.ops = { DecodeOp::RMSNorm, DecodeOp::QKV, DecodeOp::RoPE,
                 DecodeOp::Attention, DecodeOp::OProj, DecodeOp::Residual };
    out.push_back(std::move(attn));

    LaunchBatch ffn;
    ffn.ops.push_back(DecodeOp::FFNNorm);
    ffn.ops.push_back(DecodeOp::GateUp);
    ffn.ops.push_back(DecodeOp::ActivationMul);
    ffn.ops.push_back(DecodeOp::DownProj);
    if (useMoE) ffn.ops.push_back(DecodeOp::ExpertCombine);
    ffn.ops.push_back(DecodeOp::Residual);
    out.push_back(std::move(ffn));

    (void)useMLA; // MLA uses the same batch boundary; backend chooses fused kernel.
    return out;
}

} // namespace Deep2
