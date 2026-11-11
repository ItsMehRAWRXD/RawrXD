// ShardRouterIntegration.cpp
// Integrates GGUFShardRouter + lanes + residency cache for Kimi K2 streaming
#include "GGUFShardRouter.hpp"
#include "GGUFShardRouter_lanes.hpp"
#include "TensorResidencyCache.hpp"

namespace RawrXD {

// Explicit template instantiations for common router types
// This ensures the header-only templates are compiled and validated

template class gguf_shard_lanes::ParallelTensorStream<GGUFShardRouter>;

} // namespace RawrXD
