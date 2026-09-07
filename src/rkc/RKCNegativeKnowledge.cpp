// RKCNegativeKnowledge.cpp — absence probes (never inferred success)
#include "RKCNegativeKnowledge.hpp"
#include "RKCCodeWorld.hpp"
#include "deep2/Deep2LivePath.hpp"
#include <filesystem>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;
namespace RawrXD {
namespace RKC {
namespace {

void PutNeg(World& w, const std::string& key, EpistemicState st,
            const std::string& val, const std::string& src) {
    KnowledgeAtom a;
    a.key = key; a.value = val; a.state = st;
    a.kind = AtomKind::Negative; a.source = src;
    w.putAtom(a);
}

void PutReal(World& w, const std::string& key, const std::string& val,
             const std::string& src) {
    KnowledgeAtom a;
    a.key = key; a.value = val; a.state = EpistemicState::Real;
    a.kind = AtomKind::Fact; a.source = src;
    w.putAtom(a);
}

} // namespace

AbsenceStats TallyAbsence(const World& world) {
    AbsenceStats st{};
    bool saw[6] = {};
    for (const auto& kv : world.atoms()) {
        if (!IsNegativeKnowledge(kv.second.state)) continue;
        ++st.atoms;
        switch (kv.second.state) {
        case EpistemicState::NotPresent: ++st.notPresent; saw[0] = true; break;
        case EpistemicState::NotReachable: ++st.notReachable; saw[1] = true; break;
        case EpistemicState::NotObserved: ++st.notObserved; saw[2] = true; break;
        case EpistemicState::NotSupported: ++st.notSupported; saw[3] = true; break;
        case EpistemicState::NotConnected: ++st.notConnected; saw[4] = true; break;
        case EpistemicState::NotActive: ++st.notActive; saw[5] = true; break;
        default: break;
        }
    }
    for (bool b : saw) if (b) ++st.kindsPresent;
    return st;
}

AbsenceStats ObserveAbsenceCatalog(World& world, const WorldObserveConfig& cfg,
                                   const std::string& repoRoot) {
    // 1) Missing model path / shards
    if (cfg.modelPath.empty()) {
        PutNeg(world, "model_exists", EpistemicState::NotPresent, "0", "fs");
        PutNeg(world, "all_required_shards_exist", EpistemicState::NotObserved,
               "unknown", "fs");
    } else {
        std::error_code ec;
        if (!fs::exists(cfg.modelPath, ec)) {
            PutNeg(world, "model_exists", EpistemicState::NotPresent, "0", "fs");
            PutNeg(world, "all_required_shards_exist", EpistemicState::NotPresent,
                   "0", "fs");
        }
    }
    // Deliberate missing shard witness path
    {
        const std::string ghost = repoRoot + "/__missing_k2_shards__";
        if (!fs::exists(ghost)) {
            PutNeg(world, "ghost_shard_tree_exists", EpistemicState::NotPresent,
                   "0", "fs");
        }
    }

    // 2) atiadlxx — ADL thermal helper (optional on non-AMD)
#ifdef _WIN32
    HMODULE adl = LoadLibraryA("atiadlxx.dll");
    if (!adl) {
        PutNeg(world, "atiadlxx_available", EpistemicState::NotPresent, "0",
               "dll");
        PutNeg(world, "atiadlxx_supported", EpistemicState::NotSupported, "0",
               "dll");
    } else {
        PutReal(world, "atiadlxx_available", "1", "dll");
        FreeLibrary(adl);
    }
#else
    PutNeg(world, "atiadlxx_available", EpistemicState::NotSupported, "0", "dll");
#endif

    // 3) NVMe reverse source — absent until armed with a real path
    {
        const auto& c = Deep2::LivePath_Counters();
        if (c.nvmeAbsence || !Deep2::LivePath_Active()) {
            PutNeg(world, "nvme_reverse_source", EpistemicState::NotObserved,
                   "0", "nvme");
        }
        if (!Deep2::LivePath_MechOn(Deep2::LP_MECH_STREAM)) {
            PutNeg(world, "nvme_stream_mech", EpistemicState::NotActive, "0",
                   "nvme");
        }
    }

    // 4) Host fallback path — policy: not a success substitute
    PutNeg(world, "host_fallback_as_success", EpistemicState::NotSupported, "0",
           "policy");
    PutReal(world, "host_fallback_absent", "1", "policy");

    // 5) Remote endpoint disconnected (sovereign local)
    PutNeg(world, "remote_generation_endpoint", EpistemicState::NotConnected,
           "0", "policy");

    // 6) Ollama :11434 (may be NotReachable)
    WorldObserveConfig net = cfg;
    net.probeOllama11434 = true;
    world.observeNegative(net);

    // 7) Symbol not reachable from generate
    if (!repoRoot.empty()) {
        (void)ObserveCodeWorld(world, repoRoot);
        if (const auto* a =
                world.get("symbol_reachable_from_generate.FakeRemoteInfer")) {
            if (a->state != EpistemicState::NotReachable)
                PutNeg(world, "symbol_reachable_from_generate.FakeRemoteInfer",
                       EpistemicState::NotReachable, "0", "code_world");
        }
        if (const auto* d = world.get("symbol_defined.FakeRemoteInfer")) {
            if (d->state != EpistemicState::NotPresent)
                PutNeg(world, "symbol_defined.FakeRemoteInfer",
                       EpistemicState::NotPresent, "0", "code_world");
        }
    }

    // Live path not active at catalog time
    if (!Deep2::LivePath_Active()) {
        PutNeg(world, "live_path_active", EpistemicState::NotActive, "0",
               "live_path");
    }

    return TallyAbsence(world);
}

} // namespace RKC
} // namespace RawrXD
