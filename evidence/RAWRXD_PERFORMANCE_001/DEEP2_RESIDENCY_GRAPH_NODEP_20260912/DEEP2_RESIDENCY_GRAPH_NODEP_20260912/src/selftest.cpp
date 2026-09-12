#include "d2_residency_graph.h"
#include <cstdio>
#include <cstring>

using namespace d2rg;

struct FakeBackend {
    std::uint64_t loads = 0;
    std::uint64_t evicts = 0;
    std::uint64_t dispatches = 0;
    std::uint64_t syncs = 0;
    bool saw_packed_q2k = false;
    bool saw_lm_reduce = false;
};

static bool load_exact(void* u, const TensorDesc* t, Tier dst,
                       std::uint64_t off, PackedView* out) noexcept {
    auto* f = static_cast<FakeBackend*>(u);
    ++f->loads;
    if (!t || !out || (dst != Tier::GPU0 && dst != Tier::GPU1)) return false;
    out->tensor_id = t->id;
    out->tier = dst;
    out->codec = t->codec;
    out->device_offset = off;
    out->bytes = t->bytes;
    out->flags = t->flags;
    if (t->codec == Codec::Q2_K && (t->flags & TF_PACKED_NATIVE)) f->saw_packed_q2k = true;
    return true;
}

static bool evict(void* u, const PackedView*) noexcept {
    ++static_cast<FakeBackend*>(u)->evicts;
    return true;
}

static bool dispatch(void* u, const NodeDesc* n,
                     const PackedView* const* in, std::uint32_t count,
                     PackedView*, TokenContext* tc) noexcept {
    auto* f = static_cast<FakeBackend*>(u);
    ++f->dispatches;
    if (!n || !tc) return false;
    for (std::uint32_t i = 0; i < count; ++i) if (!in[i]) return false;
    if (n->op == Op::LM_HEAD_TILED_REDUCE) {
        f->saw_lm_reduce = true;
        tc->output_token = 4242;
    }
    return true;
}

static bool token_sync(void* u, TokenContext*) noexcept {
    ++static_cast<FakeBackend*>(u)->syncs;
    return true;
}

static TensorDesc tensor(std::uint32_t id, Codec c, std::uint64_t bytes,
                         std::uint32_t flags, std::uint64_t off) {
    TensorDesc t{};
    t.id = id;
    t.codec = c;
    t.bytes = bytes;
    t.flags = flags;
    t.shard_id = 0;
    t.file_offset = off;
    t.dim0 = 4096;
    t.dim1 = 4096;
    return t;
}

static NodeDesc node(std::uint32_t id, Op op,
                     std::uint32_t a, std::uint32_t b,
                     std::uint32_t out) {
    NodeDesc n{};
    n.id = id;
    n.op = op;
    n.output = out;
    if (a != 0xffffffffu) n.inputs[n.input_count++] = a;
    if (b != 0xffffffffu) n.inputs[n.input_count++] = b;
    return n;
}

int main() {
    ResidencyGraph g;
    Capacity cap{};
    cap.gpu0_bytes = 32ull << 30;
    cap.gpu1_bytes = 16ull << 30;
    cap.reserve_gpu0_bytes = 2ull << 30;
    cap.reserve_gpu1_bytes = 1ull << 30;
    if (!g.set_capacity(cap)) return 10;

    FakeBackend fb{};
    Backend b{};
    b.user = &fb;
    b.load_exact = &load_exact;
    b.evict = &evict;
    b.dispatch = &dispatch;
    b.token_sync = &token_sync;
    if (!g.bind_backend(b)) return 11;

    const std::uint32_t W = TF_WEIGHT | TF_EXACT_RANGE | TF_PACKED_NATIVE |
                            TF_ALLOW_EVICT | TF_PREFER_GPU0;
    const std::uint32_t WP = TF_WEIGHT | TF_EXACT_RANGE | TF_PACKED_NATIVE |
                             TF_PINNED | TF_PREFER_GPU0;
    const std::uint32_t A = TF_ACTIVATION | TF_ALLOW_EVICT | TF_PREFER_GPU0;
    const std::uint32_t K = TF_KV | TF_PINNED | TF_PREFER_GPU0;

    // Small synthetic geometry; behavior is what is under test.
    if (!g.add_tensor(tensor(1, Codec::Q2_K, 64ull<<20, WP, 0x00000000))) return 12; // embd
    if (!g.add_tensor(tensor(2, Codec::Q2_K, 96ull<<20, W,  0x10000000))) return 13; // qkv
    if (!g.add_tensor(tensor(3, Codec::Q2_K, 64ull<<20, W,  0x20000000))) return 14; // out
    if (!g.add_tensor(tensor(4, Codec::Q2_K, 96ull<<20, W,  0x30000000))) return 15; // ffn up
    if (!g.add_tensor(tensor(5, Codec::Q2_K, 64ull<<20, W,  0x40000000))) return 16; // ffn down
    if (!g.add_tensor(tensor(6, Codec::Q2_K, 96ull<<20, W,  0x50000000))) return 17; // lm head
    if (!g.add_tensor(tensor(20, Codec::F16, 32ull<<20, K, 0))) return 18;            // KV
    if (!g.add_tensor(tensor(30, Codec::F16, 4ull<<20, A, 0))) return 19;
    if (!g.add_tensor(tensor(31, Codec::F16, 4ull<<20, A, 0))) return 20;
    if (!g.add_tensor(tensor(32, Codec::F16, 4ull<<20, A, 0))) return 21;
    if (!g.add_tensor(tensor(33, Codec::F16, 4ull<<20, A, 0))) return 22;

    if (!g.add_node(node(100, Op::EMBEDDING, 1, 0xffffffffu, 30))) return 30;
    if (!g.add_node(node(101, Op::QKV_PACKED_GEMV, 30, 2, 31))) return 31;
    if (!g.add_node(node(102, Op::ROPE_KV_APPEND, 31, 20, 32))) return 32;
    if (!g.add_node(node(103, Op::ATTENTION, 32, 20, 33))) return 33;
    if (!g.add_node(node(104, Op::OUT_PACKED_GEMV, 33, 3, 30))) return 34;
    if (!g.add_node(node(105, Op::FFN_GATE_UP_PACKED, 30, 4, 31))) return 35;
    if (!g.add_node(node(106, Op::FFN_DOWN_PACKED, 31, 5, 30))) return 36;
    if (!g.add_node(node(107, Op::LM_HEAD_TILED_REDUCE, 30, 6, 33))) return 37;
    if (!g.add_node(node(108, Op::SAMPLE_COMMIT, 33, 0xffffffffu, 32))) return 38;

    if (!g.compile()) {
        std::puts("COMPILE=FAIL");
        return 40;
    }

    const CompileStats& cs = g.compile_stats();
    std::printf("COMPILE=PASS\n");
    std::printf("TENSORS=%u\n", cs.tensor_count);
    std::printf("NODES=%u\n", cs.node_count);
    std::printf("ACTIONS=%u\n", cs.action_count);
    std::printf("ZERO_TOKEN_HEAP=%d\n", cs.zero_token_heap ? 1 : 0);
    std::printf("EXACT_RANGE_ONLY=%d\n", cs.exact_range_only ? 1 : 0);
    std::printf("PINNED_GPU0_BYTES=%llu\n",
                (unsigned long long)cs.pinned_gpu0_bytes);

    for (std::uint32_t i = 0; i < 4; ++i) {
        TokenContext tc{};
        tc.token_index = i;
        tc.position = i;
        tc.input_token = 100 + (std::int32_t)i;
        if (!g.run_token(&tc)) {
            std::printf("RUN_TOKEN_%u=FAIL\n", i);
            return 50;
        }
        if (tc.output_token != 4242) return 51;
    }

    const RunStats& rs = g.run_stats();
    std::printf("RUN=PASS\n");
    std::printf("TOKENS=%llu\n", (unsigned long long)rs.tokens);
    std::printf("DISPATCHES=%llu\n", (unsigned long long)rs.dispatches);
    std::printf("LOAD_EXACT_CALLS=%llu\n", (unsigned long long)rs.load_exact_calls);
    std::printf("EVICTIONS=%llu\n", (unsigned long long)rs.evictions);
    std::printf("TOKEN_SYNCS=%llu\n", (unsigned long long)rs.token_syncs);
    std::printf("PER_TOKEN_HEAP_ALLOCATIONS=%llu\n",
                (unsigned long long)rs.per_token_heap_allocations);
    std::printf("PACKED_Q2K_SEEN=%d\n", fb.saw_packed_q2k ? 1 : 0);
    std::printf("LM_HEAD_DEVICE_REDUCE_SEEN=%d\n", fb.saw_lm_reduce ? 1 : 0);

    if (!cs.zero_token_heap || !cs.exact_range_only) return 60;
    if (!fb.saw_packed_q2k || !fb.saw_lm_reduce) return 61;
    if (rs.tokens != 4 || rs.token_syncs != 4 || rs.per_token_heap_allocations != 0) return 62;

    std::puts("DEEP2_RESIDENCY_GRAPH_SELFTEST=PASS");
    return 0;
}
