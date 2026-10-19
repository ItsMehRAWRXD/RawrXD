#pragma once
/* RxRunStateOverwatch — armed→prepared→ProductRun→generate→decode0. ≤99. */
#include "RxNoDeps.hpp"

namespace rxow {

enum class Stage : uint32_t {
    None = 0,
    Armed = 1,
    Prepared = 2,
    ProductRunReq = 3,
    GenerateEntered = 4,
    DecodeStep0 = 5
};

enum class BreakReason : uint32_t {
    None = 0,
    NotPrepared = 1,     /* BR_NOT_PREPARED */
    GraphEmpty = 2,      /* graph_empty companion */
    DispatchGate = 3,    /* layers/tensors ok but never ran */
    NoRunState = 4,      /* RXEV HostArmed=0 teardown */
    OpenFailed = 5
};

struct State {
    Stage stage = Stage::None;
    BreakReason br = BreakReason::None;
    uint32_t layers = 0;
    uint32_t tensors = 0;
    uint32_t graphNodes = 0;
    uint32_t decodeSteps = 0;
    char note[96]{};
};

inline State& Ow() noexcept {
    static State s{};
    return s;
}

inline void Reset() noexcept {
    State& s = Ow();
    Zmem(&s, sizeof(s));
}

inline const char* StageName(Stage st) noexcept {
    switch (st) {
    case Stage::Armed: return "ARMED";
    case Stage::Prepared: return "PREPARED";
    case Stage::ProductRunReq: return "PRODUCT_RUN_REQ";
    case Stage::GenerateEntered: return "GENERATE_ENTERED";
    case Stage::DecodeStep0: return "DECODE_STEP0";
    default: return "NONE";
    }
}

inline const char* BreakName(BreakReason b) noexcept {
    switch (b) {
    case BreakReason::NotPrepared: return "BR_NOT_PREPARED";
    case BreakReason::GraphEmpty: return "BR_GRAPH_EMPTY";
    case BreakReason::DispatchGate: return "BR_DISPATCH_GATE";
    case BreakReason::NoRunState: return "BR_NO_RUN_STATE";
    case BreakReason::OpenFailed: return "BR_OPEN_FAILED";
    default: return "BR_NONE";
    }
}

inline void Emit(FILE* f) noexcept {
    if (!f) f = stderr;
    const State& s = Ow();
    std::fprintf(f,
                 "RXOW stage=%s br=%s layers=%u tensors=%u graph=%u decode0=%u "
                 "note=%s\n",
                 StageName(s.stage), BreakName(s.br), s.layers, s.tensors,
                 s.graphNodes, s.decodeSteps, s.note[0] ? s.note : "-");
    std::fflush(f);
}

} // namespace rxow
