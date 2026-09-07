// RKCGapEngine.cpp — only operate on UNKNOWN required keys
#include "RKCGapEngine.hpp"
#include "RKCRecipes.hpp"

namespace RawrXD {
namespace RKC {

GapResult ResolveGaps(World& world, const CompiledGoal& goal) {
    ApplyRecipes(world, Deep2RecipePack());
    // Second pass: memory_plan depends on gpu_fit
    ApplyRecipes(world, Deep2RecipePack());

    GapResult out;
    out.proof.goal = goal.goalKey;
    out.proof.task = goal.task;
    out.proof.constraints = goal.constraints;

    for (const auto& key : goal.requiredKeys) {
        const auto* a = world.get(key);
        if (!a) {
            KnowledgeAtom miss;
            miss.key = key;
            miss.value = "";
            miss.state = EpistemicState::Unknown;
            miss.source = "compile";
            out.proof.missing.push_back(miss);

            // Synthesize candidates only — never promote to REAL
            if (key == "edge_request_to_worker") {
                out.proof.syntheticCandidates.push_back(
                    "UI → Request → Engine.Cancel → Worker.Stop");
                out.proof.syntheticCandidates.push_back("UI → Worker.Stop");
                out.proof.syntheticCandidates.push_back("UI → global_abort");
            }
            continue;
        }

        if (a->kind == AtomKind::Negative || IsNegativeKnowledge(a->state)) {
            out.proof.negative.push_back(*a);
            continue;
        }

        if (a->state == EpistemicState::Unknown ||
            a->state == EpistemicState::Invalid) {
            out.proof.missing.push_back(*a);
            continue;
        }

        out.proof.known.push_back(*a);
    }

    // Also surface non-required negatives that matter (dedupe by key)
    for (const auto& kv : world.atoms()) {
        if (kv.second.kind != AtomKind::Negative) continue;
        bool seen = false;
        for (const auto& n : out.proof.negative)
            if (n.key == kv.first) { seen = true; break; }
        if (!seen) out.proof.negative.push_back(kv.second);
    }
    return out;
}

} // namespace RKC
} // namespace RawrXD
