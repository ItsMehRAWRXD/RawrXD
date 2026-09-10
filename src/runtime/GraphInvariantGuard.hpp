#pragma once
// GraphInvariantGuard — authority stays fixed; candidates stay transient.
#include <cstdint>
#include "CandidateBindingPolicy.hpp"
#include "ReadbackBoundaryPolicy.hpp"

namespace rawrxd::runtime {

struct GraphInvariantGuard {
    uint64_t model_hash = 0;
    uint64_t graph_hash = 0;
    bool sealed = false;

    bool Seal(uint64_t model, uint64_t graph) {
        if (sealed) return model == model_hash && graph == graph_hash;
        model_hash = model;
        graph_hash = graph;
        sealed = true;
        return true;
    }

    bool SameAuthority(uint64_t model, uint64_t graph) const {
        return sealed && model == model_hash && graph == graph_hash;
    }

    // Candidate may consume sealed authority; may not rewrite it.
    bool AcceptCandidate(uint64_t model, uint64_t graph,
                         const CandidateBindingPolicy& pol) const {
        if (!SameAuthority(model, graph)) return false;
        return pol.fixed_graph && pol.canonical_model_bytes
            && pol.transient_bindings_only;
    }

    bool AcceptReadback(const ReadbackRequest& req) const {
        return ReadbackBoundaryPolicy::IsProductPathLegal(
            ReadbackBoundaryPolicy::Decide(req));
    }
};

} // namespace rawrxd::runtime
