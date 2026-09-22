#pragma once
#include "InferenceAdapter.hpp"

namespace rawrxd::swarm48 {

// Implement this adapter in RawrXD by forwarding into the existing Deep2 model
// residency and batched decode authority. It deliberately contains no duplicate
// GGUF loader, Vulkan allocator, tokenizer, or scheduler.
//
// Required mapping:
//   load_shared(req)  -> existing Deep2/ModelRegistry resident model acquisition
//   unload_shared(h)  -> existing Deep2 residency release
//   decode_batch(...) -> existing continuous batch / StreamRouter / decode entrypoint
//
// Resident weights are immutable and shared; session KV handles remain per-agent.
class Deep2BridgeContract : public IInferenceAdapter {
public:
    ~Deep2BridgeContract() override = default;
};

} // namespace rawrxd::swarm48
