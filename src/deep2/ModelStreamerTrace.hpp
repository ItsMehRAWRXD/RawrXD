#pragma once
/* ModelStreamerTrace — hot path write-only; join+dump after generation. */
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace Deep2 {
namespace ModelStreamerTrace {

enum class Stage : uint32_t {
    MODEL_READ = 1, MAP = 2, STREAMER = 3, QKV_READBACK = 4, QKV = 5,
    ATTENTION = 6, O_PROJ = 7, FFN = 8, LOGITS = 9, WAIT = 10,
    SAMPLE = 11, EMIT = 12, TOKEN_WALL = 13
};
enum class Event : uint32_t { BEGIN = 1, END = 2 };

#pragma pack(push, 1)
struct HotPathEvent {
    uint64_t qpc_ns;
    uint64_t ticket;
    uint32_t binding_id;
    uint32_t token_step;
    uint32_t layer;
    uint32_t event;
};
struct BindingEntry {
    uint32_t binding_id;
    uint32_t stage;
    uint64_t tensor_id;
    uint32_t model_file_id;
    uint32_t kernel_id;
    uint64_t file_offset;
    uint64_t bytes;
    uint32_t device_id;
    uint32_t _pad;
};
#pragma pack(pop)

inline constexpr uint32_t kCapacity = 1u << 16;
inline constexpr uint32_t kBindCap = 4096u;

struct Ring {
    HotPathEvent slots[kCapacity];
    std::atomic<uint32_t> write{0};
    std::atomic<uint32_t> dropped{0};
};
struct BindingTable {
    BindingEntry rows[kBindCap];
    uint32_t count{0};
};

inline Ring& GetRing() { static Ring r{}; return r; }
inline BindingTable& GetBindings() { static BindingTable t{}; return t; }

inline uint64_t QpcNs() {
    static LARGE_INTEGER f{};
    static int init = 0;
    if (!init) { QueryPerformanceFrequency(&f); init = 1; }
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000000ull) / (uint64_t)f.QuadPart);
}

inline void SealBinding(const BindingEntry& e) {
    BindingTable& t = GetBindings();
    if (t.count >= kBindCap) return;
    t.rows[t.count++] = e;
}

inline HotPathEvent* Claim() {
    Ring& r = GetRing();
    const uint32_t i = r.write.fetch_add(1, std::memory_order_relaxed);
    if (i >= kCapacity) {
        r.dropped.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    return &r.slots[i];
}

inline void Begin(uint64_t ticket, uint32_t binding_id, uint32_t step,
                  uint32_t layer) {
    HotPathEvent* rec = Claim();
    if (!rec) return;
    rec->qpc_ns = QpcNs();
    rec->ticket = ticket;
    rec->binding_id = binding_id;
    rec->token_step = step;
    rec->layer = layer;
    rec->event = (uint32_t)Event::BEGIN;
}

inline void End(uint64_t ticket, uint32_t binding_id, uint32_t step,
                uint32_t layer) {
    HotPathEvent* rec = Claim();
    if (!rec) return;
    rec->qpc_ns = QpcNs();
    rec->ticket = ticket;
    rec->binding_id = binding_id;
    rec->token_step = step;
    rec->layer = layer;
    rec->event = (uint32_t)Event::END;
}

} // namespace ModelStreamerTrace
} // namespace Deep2

#include "ModelStreamerTrace_dump.hpp"
