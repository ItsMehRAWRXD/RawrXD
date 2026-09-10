#pragma once
/* RxRunStateHooks — C++ hooks for ProductRun boundary. ≤99. */
#include "RxRunStateOverwatch.hpp"

namespace rxow {

inline void OnArmed(uint32_t layers, uint32_t tensors) noexcept {
    State& s = Ow();
    s.stage = Stage::Armed;
    s.layers = layers;
    s.tensors = tensors;
    s.br = BreakReason::None;
    CopyStr(s.note, sizeof(s.note), "model_armed");
    Emit(stderr);
}

inline void OnPrepared(uint32_t graphNodes, uint32_t layers,
                       uint32_t tensors) noexcept {
    State& s = Ow();
    s.graphNodes = graphNodes;
    s.layers = layers;
    s.tensors = tensors;
    if (layers == 0 && tensors == 0) {
        s.stage = Stage::Armed;
        s.br = BreakReason::NotPrepared;
        CopyStr(s.note, sizeof(s.note), "graph_empty");
        Emit(stderr);
        return;
    }
    if (graphNodes == 0) {
        s.stage = Stage::Armed;
        s.br = BreakReason::GraphEmpty;
        CopyStr(s.note, sizeof(s.note), "graph_nodes_0");
        Emit(stderr);
        return;
    }
    s.stage = Stage::Prepared;
    s.br = BreakReason::None;
    CopyStr(s.note, sizeof(s.note), "prepared");
    Emit(stderr);
}

inline void OnProductRunRequested() noexcept {
    State& s = Ow();
    if (s.stage < Stage::Prepared) {
        if (s.br == BreakReason::None) s.br = BreakReason::NotPrepared;
        CopyStr(s.note, sizeof(s.note), "product_run_before_prepared");
        Emit(stderr);
        return;
    }
    s.stage = Stage::ProductRunReq;
    CopyStr(s.note, sizeof(s.note), "product_run_requested");
    Emit(stderr);
}

inline void OnGenerateEntered() noexcept {
    State& s = Ow();
    s.stage = Stage::GenerateEntered;
    CopyStr(s.note, sizeof(s.note), "generate_entered");
    Emit(stderr);
}

inline void OnDecodeStep0() noexcept {
    State& s = Ow();
    s.stage = Stage::DecodeStep0;
    s.decodeSteps = 1;
    CopyStr(s.note, sizeof(s.note), "decode_step0");
    Emit(stderr);
}

/* Call when RXEV prints NO_RUN_STATE (HostArmed=0). */
inline void OnTeardownNoRunState() noexcept {
    State& s = Ow();
    if (s.br == BreakReason::NotPrepared || s.br == BreakReason::GraphEmpty) {
        CopyStr(s.note, sizeof(s.note), "norun_after_not_prepared");
        Emit(stderr);
        return;
    }
    /* Successful decode already observed — EV512 unarmed surface is not owner. */
    if (s.stage >= Stage::DecodeStep0 && s.decodeSteps > 0) {
        s.br = BreakReason::None;
        CopyStr(s.note, sizeof(s.note), "norun_surface_after_decode0_ok");
        Emit(stderr);
        return;
    }
    if (s.layers > 0 && s.tensors > 0 && s.stage < Stage::DecodeStep0) {
        s.br = BreakReason::DispatchGate;
        CopyStr(s.note, sizeof(s.note), "dispatch_gate_owner");
        Emit(stderr);
        return;
    }
    s.br = BreakReason::NoRunState;
    CopyStr(s.note, sizeof(s.note), "norun_unclassified");
    Emit(stderr);
}

inline void OnOpenFailed(const char* why) noexcept {
    State& s = Ow();
    s.br = BreakReason::OpenFailed;
    CopyStr(s.note, sizeof(s.note), why ? why : "open_failed");
    Emit(stderr);
}

} // namespace rxow
