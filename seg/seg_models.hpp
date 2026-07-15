#pragma once
#include "seg_graph.hpp"

namespace seg {

struct LlamaGraphConfig {
    uint32_t num_layers;
};

Graph BuildLlamaForwardGraph(const LlamaGraphConfig& cfg);

} // namespace seg
