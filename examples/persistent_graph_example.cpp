#include "../src/runtime/PersistentGraphState.hpp"
#include <cstdio>

using namespace rawrxd::runtime;

static PersistentValue MakeU32(
    uint64_t id, uint32_t value, uint32_t minv, uint32_t maxv, uint32_t flags) {
    PersistentValue p{};
    p.id = id;
    p.type = ValueType::U32;
    p.flags = flags;
    p.value.u32 = p.default_value.u32 = value;
    p.min_value.u32 = minv;
    p.max_value.u32 = maxv;
    return p;
}

static PersistentValue MakeF32(
    uint64_t id, float value, float minv, float maxv, uint32_t flags) {
    PersistentValue p{};
    p.id = id;
    p.type = ValueType::F32;
    p.flags = flags;
    p.value.f32 = p.default_value.f32 = value;
    p.min_value.f32 = minv;
    p.max_value.f32 = maxv;
    return p;
}

static PersistentValue MakeU64(
    uint64_t id, uint64_t value, uint64_t minv, uint64_t maxv, uint32_t flags) {
    PersistentValue p{};
    p.id = id;
    p.type = ValueType::U64;
    p.flags = flags;
    p.value.u64 = p.default_value.u64 = value;
    p.min_value.u64 = minv;
    p.max_value.u64 = maxv;
    return p;
}

int wmain() {
    // Minimal fixed causal graph:
    // INPUT -> NORM -> {Q,K,V} -> ATTENTION -> OPROJ -> RESIDUAL -> LOGITS -> SAMPLE -> EMIT
    GraphNode nodes[] = {
        {1, MathOp::Input,     0xFFFF, 0,0, 0,0,0},
        {2, MathOp::Norm,      0,      0,0, 0,0,0},
        {3, MathOp::Q,         0,      0,0, 0,0,0},
        {4, MathOp::K,         0,      0,0, 0,0,0},
        {5, MathOp::V,         0,      0,0, 0,0,0},
        {6, MathOp::Attention, 0,      0,0, 0,0,0},
        {7, MathOp::OProj,     0,      0,0, 0,0,0},
        {8, MathOp::Residual,  0,      0,0, 0,0,0},
        {9, MathOp::Logits,    0xFFFF, 0,0, 0,0,0},
        {10,MathOp::Sample,    0xFFFF, 0,0, 0,0,0},
        {11,MathOp::Emit,      0xFFFF, 0,0, 0,0,0}
    };

    GraphDependency deps[] = {
        {0,1},
        {1,2}, {1,3}, {1,4},
        {2,5}, {3,5}, {4,5},
        {5,6},
        {6,7},
        {7,8},
        {8,9},
        {9,10},
        {10,11}
    };

    PersistentValue values[] = {
        MakeU32(StateId::TokenStep(), 0, 0, 0xffffffffu,
            Value_Persistent | Value_PerToken),
        MakeU32(StateId::Position(), 0, 0, 0xffffffffu,
            Value_Persistent | Value_PerToken),
        MakeU64(StateId::KvWriteCursor(), 0, 0, ~0ull,
            Value_Persistent | Value_PerToken),
        MakeU32(StateId::MaxTokens(), 256, 1, 1048576,
            Value_Persistent | Value_Configurable | Value_PerSequence),
        MakeF32(StateId::Temperature(), 0.8f, 0.0f, 4.0f,
            Value_Persistent | Value_Configurable | Value_PerSequence),
        MakeU32(StateId::TopK(), 40, 0, 1000000,
            Value_Persistent | Value_Configurable | Value_PerSequence),
        MakeF32(StateId::TopP(), 0.95f, 0.0f, 1.0f,
            Value_Persistent | Value_Configurable | Value_PerSequence),
        MakeU64(StateId::RngState(), 1, 0, ~0ull,
            Value_Persistent | Value_PerToken),
        MakeU32(StateId::ActiveQRows(), 64, 32, 128,
            Value_Persistent | Value_Configurable | Value_PerSequence),
        MakeU32(StateId::ActiveQaRows(), 64, 32, 128,
            Value_Persistent | Value_Configurable | Value_PerSequence),
        MakeU32(StateId::ActiveQkvRows(), 64, 64, 128,
            Value_Persistent | Value_Configurable | Value_PerSequence)
    };

    PersistentGraphState state;
    if (!state.Build(nodes, _countof(nodes), deps, _countof(deps),
                     values, _countof(values))) {
        std::puts("BUILD=FAIL");
        return 1;
    }

    if (!state.ApplyConfigFile(L"decode_state.cfg"))
        std::puts("CONFIG=PARTIAL_OR_MISSING");

    // Decode loop mutates values, not graph topology.
    uint32_t maxTokens = 0;
    state.GetU32(StateId::MaxTokens(), &maxTokens);

    for (uint32_t i = 0; i < maxTokens; ++i) {
        state.SetU32(StateId::TokenStep(), i);
        state.SetU32(StateId::Position(), i);

        uint64_t kv = 0;
        state.GetU64(StateId::KvWriteCursor(), &kv);
        state.SetU64(StateId::KvWriteCursor(), kv + 1);

        // Execute immutable graph here.
        // Only persistent values and tensor contents change.
    }

    state.SaveSnapshot(L"decode_state.rxpgs");
    state.DumpDecoded(L"decode_state.tsv");

    std::printf("GRAPH_HASH=%llu\n",
        static_cast<unsigned long long>(state.GraphHash()));
    std::printf("STATE_GENERATION=%llu\n",
        static_cast<unsigned long long>(state.Generation()));
    return 0;
}
