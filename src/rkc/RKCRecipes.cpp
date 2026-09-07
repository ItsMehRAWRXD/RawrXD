// RKCRecipes.cpp — model_complete / local_generation_proven / gpu_fit
#include "RKCRecipes.hpp"
#include "RKCValidator.hpp"
#include <cstdlib>

namespace RawrXD {
namespace RKC {
namespace {

bool ready(const World& w, const std::string& key) {
    const auto* a = w.get(key);
    if (!a) return false;
    return a->state == EpistemicState::Real || a->state == EpistemicState::Derived;
}

std::string val(const World& w, const std::string& key, const char* def = "0") {
    const auto* a = w.get(key);
    return a ? a->value : def;
}

uint64_t u64(const World& w, const std::string& key) {
    return std::strtoull(val(w, key, "0").c_str(), nullptr, 10);
}

void putDerived(World& w, const std::string& key, const std::string& value,
                const std::vector<std::string>& parents, const std::string& src) {
    KnowledgeAtom a;
    a.key = key;
    a.value = value;
    a.state = EpistemicState::Derived;
    a.parents = parents;
    a.source = src;
    w.putAtom(a);
}

} // namespace

std::vector<Recipe> Deep2RecipePack() {
    return {
        {"model_complete", "model_complete",
         {"model_exists", "all_required_shards_exist", "model_format_supported"}},
        {"local_generation_proven", "local_generation_proven",
         {"live_generation_path_exists", "no_remote_dependency", "remote_calls"}},
        {"gpu_fit", "gpu_fit",
         {"gpu.memory", "weights_window", "kv_budget", "forward_arena",
          "safety_margin"}},
        {"memory_plan_exists", "memory_plan_exists",
         {"gpu_fit"}},
    };
}

void ApplyRecipes(World& world, const std::vector<Recipe>& recipes) {
    for (const auto& r : recipes) {
        bool all = true;
        for (const auto& k : r.needKeys) {
            if (!ready(world, k)) {
                all = false;
                break;
            }
        }
        if (!all) continue;

        if (r.id == "model_complete") {
            const bool ok = val(world, "model_exists") == "1" &&
                            val(world, "all_required_shards_exist") == "1" &&
                            val(world, "model_format_supported") == "1";
            putDerived(world, r.producesKey, ok ? "1" : "0", r.needKeys, r.id);
        } else if (r.id == "local_generation_proven") {
            // Path exists locally and remote_calls==0; vacuum/tramp may be 0 until generate.
            const bool path = val(world, "live_generation_path_exists") == "1" ||
                              val(world, "compute_backend_exists") == "1";
            const bool remoteOk = val(world, "remote_calls") == "0";
            putDerived(world, r.producesKey, (path && remoteOk) ? "1" : "0",
                       r.needKeys, r.id);
        } else if (r.id == "gpu_fit") {
            const uint64_t avail = u64(world, "gpu.memory");
            const uint64_t need = u64(world, "weights_window") + u64(world, "kv_budget") +
                                  u64(world, "forward_arena") + u64(world, "safety_margin");
            // If VRAM unknown (0) but backend exists, leave UNKNOWN for gap engine.
            if (avail == 0 && u64(world, "weights_window") == 0) {
                KnowledgeAtom a;
                a.key = r.producesKey;
                a.value = "unknown";
                a.state = EpistemicState::Unknown;
                a.source = r.id;
                world.putAtom(a);
            } else {
                putDerived(world, r.producesKey, (avail >= need) ? "1" : "0",
                           r.needKeys, r.id);
            }
        } else if (r.id == "memory_plan_exists") {
            const auto* gf = world.get("gpu_fit");
            if (gf && (gf->state == EpistemicState::Derived ||
                       gf->state == EpistemicState::Real))
                putDerived(world, r.producesKey, gf->value == "1" ? "1" : "0",
                           r.needKeys, r.id);
        }
    }
}

} // namespace RKC
} // namespace RawrXD
