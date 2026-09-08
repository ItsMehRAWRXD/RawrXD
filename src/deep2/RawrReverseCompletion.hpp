// RawrReverseCompletion.hpp — STREAM_BACKWARDS completion receipts.
#pragma once
#include "RawrNeed.hpp"
#include <cstdio>
#include <cstring>

namespace Deep2 {

enum class NeedState : uint8_t {
    Satisfied = 0,
    Missing = 1,
    Running = 2,
    Failed = 3
};

enum class StreamStatus : uint8_t {
    Ready = 0,
    Running = 1,
    Blocked = 2,
    Failed = 3,
    Complete = 4,
    Void = 5
};

struct CompletionNeed {
    const char* name;
    NeedState state;
    const char* owner;
    const char* nextAction;
};

struct CompletionPlan {
    bool complete = false;
    StreamStatus status = StreamStatus::Blocked;
    const char* blockedAt = nullptr;
    const char* blockedOwner = nullptr;
    const char* nextAction = nullptr;
    CompletionNeed needs[16]{};
    int needCount = 0;
};

struct RuntimeReceipts {
    bool modelIndexed = false;
    bool tensorMapComplete = false;
    bool hybridLayerRoute = false;
    bool choreographyReady = false;
    bool spaceSufficient = false;
    bool kvHotsetReady = false;
    bool weightWindowReady = false;
    bool hostQ8GemvSafe = true;
    bool generateStreamEntered = false;
    bool firstTokenCallback = false;
    bool runVoid = false;
    const char* voidReason = nullptr;
    const char* tensorMapOwner = "architecture mapper";
    const char* tensorMapAction = "bind required architecture tensors";
    const char* q8Owner = "quant GEMV";
    const char* q8Action = "certify host Q8_0 LinearW for model family";
};

inline const char* StreamStatusString(StreamStatus s) {
    switch (s) {
    case StreamStatus::Ready: return "READY";
    case StreamStatus::Running: return "RUNNING";
    case StreamStatus::Blocked: return "BLOCKED";
    case StreamStatus::Failed: return "FAILED";
    case StreamStatus::Complete: return "COMPLETE";
    case StreamStatus::Void: return "VOID";
    }
    return "BLOCKED";
}

inline void PushNeed(CompletionPlan& p, const char* name, bool ok,
                     const char* owner, const char* action) {
    if (p.needCount >= 16) return;
    CompletionNeed& n = p.needs[p.needCount++];
    n.name = name;
    n.state = ok ? NeedState::Satisfied : NeedState::Missing;
    n.owner = owner;
    n.nextAction = action;
    if (!ok && !p.blockedAt) {
        p.blockedAt = name;
        p.blockedOwner = owner;
        p.nextAction = action;
    }
}

inline CompletionPlan ReverseGenerationCompletion(const RuntimeReceipts& st) {
    CompletionPlan p{};
    if (st.runVoid) {
        p.status = StreamStatus::Void;
        p.blockedAt = "RUN_VOID";
        p.blockedOwner = "env";
        p.nextAction = st.voidReason ? st.voidReason : "clear contaminating env";
        PushNeed(p, "RUN_VOID", false, "env", p.nextAction);
        return p;
    }
    PushNeed(p, "MODEL_INDEXED", st.modelIndexed, "loader/index",
             "open GGUF/shards and build tensor index");
    PushNeed(p, "TENSOR_MAP_COMPLETE", st.tensorMapComplete, st.tensorMapOwner,
             st.tensorMapAction);
    PushNeed(p, "HYBRID_LAYER_ROUTE", st.hybridLayerRoute, "layer classifier",
             "route SSM/attention/FFN layers by tensor presence");
    PushNeed(p, "CHOREOGRAPHY_READY", st.choreographyReady, "scoreboard",
             "build dependency and last-use graph");
    PushNeed(p, "SPACE_SUFFICIENT", st.spaceSufficient, "residency",
             "evict/reclaim until next step fits");
    PushNeed(p, "KV_HOTSET_READY", st.kvHotsetReady, "KV pager",
             "allocate/map required hot KV pages");
    PushNeed(p, "WEIGHT_WINDOW_READY", st.weightWindowReady, "weight lease",
             "lease current quantized weight window");
    PushNeed(p, "HOST_Q8_GEMV_SAFE", st.hostQ8GemvSafe, st.q8Owner, st.q8Action);
    p.complete = (p.blockedAt == nullptr);
    p.status = p.complete ? StreamStatus::Ready : StreamStatus::Blocked;
    if (p.complete) p.nextAction = "CALL_GENERATE_STREAM";
    return p;
}

inline void EmitCompletionPlan(FILE* f, const char* goal, const CompletionPlan& p) {
    if (!f) return;
    std::fprintf(f, "REVERSE_COMPLETION_BEGIN\nGOAL=%s\n", goal ? goal : "GENERATION_COMPLETE");
    std::fprintf(f, "STREAM_STATUS=%s\n", StreamStatusString(p.status));
    std::fprintf(f, "TIMER_BASED_START=0\nWOULD_START_STATUS=0\n");
    std::fprintf(f, "REVERSE_COMPLETION_PLAN=1\n");
    for (int i = 0; i < p.needCount; ++i) {
        const CompletionNeed& n = p.needs[i];
        std::fprintf(f, "%s=%d\n", n.name, n.state == NeedState::Satisfied ? 1 : 0);
    }
    if (p.blockedAt) {
        std::fprintf(f, "BLOCKED_AT=%s\nBLOCKED_OWNER=%s\nNEXT_ACTION=%s\n",
                     p.blockedAt, p.blockedOwner ? p.blockedOwner : "unknown",
                     p.nextAction ? p.nextAction : "diagnose");
        std::fprintf(f, "BLOCKER_OWNER_EMITTED=1\nNEXT_ACTION_EMITTED=1\n");
    } else {
        std::fprintf(f, "READY_REASON=ALL_COMPLETION_NEEDS_SATISFIED\n");
        std::fprintf(f, "NEXT_ACTION=%s\nREADY_WORK_ONLY=1\n",
                     p.nextAction ? p.nextAction : "CALL_GENERATE_STREAM");
    }
    std::fprintf(f, "REVERSE_COMPLETION_END\n");
    std::fflush(f);
}

// Wall budget as anonymous capacity (have=allowed, need=actual).
inline void EmitWallBudgetNeed(FILE* f, uint64_t allowedNs, uint64_t actualNs,
                               uint64_t tokens) {
    if (!f) return;
    const RawrNeed n = WallBudgetNeed(allowedNs, actualNs);
    const uint64_t miss = rawrMissing(n);
    std::fprintf(f,
                 "SAT=%d DELTA_NS=%llu HAVE_NS=%llu NEED_NS=%llu TOKENS=%llu\n"
                 "TPS_DERIVED_ONLY=1\n",
                 rawrSatisfied(n) == RawrState::Satisfied ? 1 : 0,
                 (unsigned long long)miss, (unsigned long long)n.have,
                 (unsigned long long)n.need, (unsigned long long)tokens);
    std::fflush(f);
}

} // namespace Deep2
