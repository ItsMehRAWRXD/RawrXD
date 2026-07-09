#include "seg_executor.hpp"

// Include your actual backend header
// #include "../runtime/streaming_multi_layer_backend.hpp"

namespace seg {

void Executor::Run(const Graph& graph, uint32_t token_id, uint32_t position) {
    auto logitsBuf = m_mem.Get(MemoryRegion::kLogits);
    float* logits = static_cast<float*>(logitsBuf.ptr);

    // For now: delegate to backend's full forward pass.
    // m_backend.ExecuteToken(token_id, position, logits);

    // Later: map individual NodeKind to MASM kernels / sub-ops.
}

} // namespace seg
