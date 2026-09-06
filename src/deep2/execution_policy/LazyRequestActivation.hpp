// ============================================================================
// LazyRequestActivation.hpp — zero startup load; activate on first request
//
// LOAD_ON_FIRST_REQUEST = -1  (explicit sentinel, NOT a timer trick)
// IDE START → register descriptor only → READY
// SEND REQUEST → REQUEST_GATE → ActivateForRequest → generate
// ============================================================================
#pragma once

#include "LazyRegionMaterialize.hpp"
#include "ReverseLoadLifecycle.hpp"
#include "NuColdHotpatch.hpp"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

namespace Deep2 {
namespace Exec {

enum class LoadTrigger : int8_t {
    Startup = 0,
    Selection = 1,
    FirstRequest = -1, // LOAD_ON_FIRST_REQUEST
    Manual = 2
};

constexpr int LOAD_ON_FIRST_REQUEST = -1;

enum class ModelRuntimeState : uint8_t {
    Unloaded = 0,
    DescriptorOnly, // IDE-ready: no GGUF parse / weights / GPU
    Loading,
    ShellReady,           // lightweight shell, regions missing
    PartiallyMaterialized,
    Ready
};

struct ModelDescriptor {
    ModelFingerprint fingerprint;
    std::string path;
    uint32_t nLayers = 0;
    LoadTrigger loadTrigger = LoadTrigger::FirstRequest;
    int loadDelayMs = LOAD_ON_FIRST_REQUEST; // -1 ⇒ first request owns activation
    bool startupLoad = false;
    bool preload = false;
    bool keepResidentAfterFirstRequest = true;

    std::atomic<ModelRuntimeState> state{ModelRuntimeState::Unloaded};
    std::mutex activationMutex;
};

inline bool IsFirstRequestTrigger(const ModelDescriptor& d) {
    return d.loadTrigger == LoadTrigger::FirstRequest ||
           d.loadDelayMs == LOAD_ON_FIRST_REQUEST || !d.startupLoad;
}

// IDE startup: register descriptor only — NO parse / allocate / upload.
inline void RegisterDescriptorAtStartup(ModelDescriptor& d) {
    if (d.startupLoad || d.preload ||
        d.loadTrigger == LoadTrigger::Startup) {
        // Explicit opt-in to eager path — caller must Materialize separately.
        return;
    }
    d.state.store(ModelRuntimeState::DescriptorOnly);
}

struct ActivateStatus {
    bool ok = false;
    LoadClass loadClass = LoadClass::L0_TrueCold;
    ModelRuntimeState state = ModelRuntimeState::Unloaded;
    uint64_t generation = 0;
    std::string detail;
};

// Idempotent + concurrency-safe. Paid on first request, not IDE start.
inline ActivateStatus ActivateForRequest(ModelDescriptor& model,
                                         ModelImageRegistry& reg,
                                         RealtimeEngine& engine,
                                         LazyModelShell& shell) {
    ActivateStatus st;
    ModelRuntimeState cur = model.state.load();
    if (cur == ModelRuntimeState::Ready ||
        cur == ModelRuntimeState::PartiallyMaterialized ||
        cur == ModelRuntimeState::ShellReady) {
        st.ok = true;
        st.state = cur;
        st.loadClass = LoadClass::L3_Hot;
        st.generation = engine.AcquireState().generation();
        st.detail = "ALREADY_ACTIVE";
        return st;
    }

    std::unique_lock lock(model.activationMutex);
    cur = model.state.load();
    if (cur == ModelRuntimeState::Ready ||
        cur == ModelRuntimeState::ShellReady ||
        cur == ModelRuntimeState::PartiallyMaterialized) {
        st.ok = true;
        st.state = cur;
        st.loadClass = LoadClass::L3_Hot;
        st.generation = engine.AcquireState().generation();
        st.detail = "ALREADY_ACTIVE_AFTER_WAIT";
        return st;
    }

    model.state.store(ModelRuntimeState::Loading);

    HotPatchFlags none{};
    RuntimeOverlay ov;
    AcquireResult acq =
        AcquireModel(reg, model.fingerprint, model.path, ov, none);
    if (!acq.ok) {
        model.state.store(ModelRuntimeState::Unloaded);
        st.detail = acq.detail;
        return st;
    }
    st.loadClass = acq.loadClass;

    // Shell only — full weight materialization deferred to region hotpatches.
    if (shell.layerCount == 0) {
        InitUntouchedShell(shell, model.fingerprint,
                           model.nLayers ? model.nLayers : 4);
    }
    if (!shell.tokenizer)
        shell.tokenizer = MaterializeShellRegion(RegionKind::Tokenizer);
    if (!shell.embedding)
        shell.embedding = MaterializeShellRegion(RegionKind::Embedding);

    // Publish shell into realtime as generation advance (L3/L0→overlay).
    HotPatchRequest req;
    req.flags = {};
    req.candidate.expectedSchemaHash = engine.kernel().schemaHash;
    req.candidate.expectedAuthorityHash = engine.kernel().authorityHash;
    req.candidate.source = "first_request_activate";
    req.candidate.state.policySha = model.fingerprint;
    req.candidate.state.timing.baselineDecodeMs = 250.0;
    req.candidate.state.timing.targetDecodeMs = 100.0;
    HotPatchResult hp = ControllerHotPatch(engine, req);
    if (hp.status != HotPatchStatus::Applied &&
        hp.status != HotPatchStatus::ColdPathRequired) {
        // Seed empty engine if no prior image: CommitRealtimeState directly.
        RealtimeStateSnapshot snap = req.candidate;
        CommitResult c = engine.CommitRealtimeState(snap);
        if (!c.ok) {
            model.state.store(ModelRuntimeState::Unloaded);
            st.detail = c.detail;
            return st;
        }
        st.generation = c.newGeneration;
    } else if (hp.status == HotPatchStatus::Applied) {
        st.generation = hp.generation;
    } else {
        CommitResult c = engine.CommitRealtimeState(req.candidate);
        if (!c.ok) {
            model.state.store(ModelRuntimeState::Unloaded);
            st.detail = c.detail;
            return st;
        }
        st.generation = c.newGeneration;
    }

    model.state.store(ModelRuntimeState::ShellReady);
    st.ok = true;
    st.state = ModelRuntimeState::ShellReady;
    st.detail = "SHELL_READY_ON_FIRST_REQUEST " +
                std::string(LoadClassName(st.loadClass));
    return st;
}

// Request gate: activate if needed, then caller runs inference.
template <typename GenerateFn>
auto SendRequestGate(ModelDescriptor& model, ModelImageRegistry& reg,
                     RealtimeEngine& engine, LazyModelShell& shell,
                     GenerateFn&& generate) -> decltype(generate()) {
    using ResultT = decltype(generate());
    if (IsFirstRequestTrigger(model) ||
        model.state.load() == ModelRuntimeState::DescriptorOnly ||
        model.state.load() == ModelRuntimeState::Unloaded) {
        ActivateStatus a = ActivateForRequest(model, reg, engine, shell);
        if (!a.ok) {
            ResultT fail{};
            return fail;
        }
    }
    return generate();
}

} // namespace Exec
} // namespace Deep2
