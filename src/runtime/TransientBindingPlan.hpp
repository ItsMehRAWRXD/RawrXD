#pragma once
// TransientBindingPlan — branch delta over sealed base; loser drops delta only.
#include <cstdint>

namespace rawrxd::runtime {

struct TransientBindingPlan {
    uint64_t base_graph_hash = 0;
    uint64_t base_model_hash = 0;
    uint64_t binding_generation = 0;
    uint64_t candidate_id = 0;
    bool active = false;
    bool valid = false;

    // Candidate may consume sealed authority; may not rewrite it.
    bool Attach(uint64_t model, uint64_t graph, uint64_t id) {
        if (active && (model != base_model_hash || graph != base_graph_hash))
            return false;
        base_model_hash = model;
        base_graph_hash = graph;
        candidate_id = id;
        ++binding_generation;
        active = true;
        valid = true;
        return true;
    }

    void DropLoserDelta() {
        // Keep base hashes; discard candidate identity only.
        candidate_id = 0;
        valid = false;
        active = false;
    }

    bool CommitWinner() const {
        return active && valid && candidate_id != 0;
    }
};

} // namespace rawrxd::runtime
