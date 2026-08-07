// ============================================================================
// StreamRouter.cpp — Non-inline implementation + MASM dispatch
// ============================================================================

#include "StreamRouter.hpp"
#include <cstring>
#include <windows.h>

namespace Deep2 {

bool StreamRouter::Initialize(const StreamConfig& cfg) {
    cfg_ = cfg;
    hop_cache_.Build(this);
    telemetry_ = Telemetry{};
    return true;
}

size_t StreamRouter::RouteTokenBatch8(const uint32_t* stream_ids,
                                       const uint32_t* tokens,
                                       uint64_t base_cycle) noexcept {
    const StreamLoc* locs[8];
    hop_cache_.ResolveBatch8(stream_ids, locs);

    size_t routed = 0;
    for (int i = 0; i < 8; ++i) {
        if (locs[i] == nullptr) continue;

        StreamLoc* loc = const_cast<StreamLoc*>(locs[i]);
        uint32_t head = loc->buffer_head;
        uint32_t next = (head + 1) & loc->buffer_cap;

        if (next == loc->buffer_tail) {
            telemetry_.tokens_dropped++;
            continue;
        }

        uint64_t hash = XXHash64Token(tokens[i]);
        journal_.Record(base_cycle + i, stream_ids[i], loc->token_count,
                        hash, head, loc->buffer_tail);

        uint32_t* buf = static_cast<uint32_t*>(loc->buffer_base);
        buf[head] = tokens[i];
        loc->buffer_head = next;
        loc->token_count++;
        routed++;
    }

    telemetry_.tokens_routed += routed;
    return routed;
}

bool StreamRouter::RewindStream(uint32_t stream_id, uint64_t target_cycle) noexcept {
    const StreamLoc* loc = hop_cache_.Resolve(stream_id);
    if (loc == nullptr) return false;

    RewindEntry entries[64];
    size_t count = 64;
    uint64_t found_cycle = journal_.RewindTo(target_cycle, entries, &count);
    if (found_cycle == 0 || count == 0) return false;

    // Apply rewind: restore buffer state from journal entries in reverse
    StreamLoc* mutable_loc = const_cast<StreamLoc*>(loc);
    for (size_t i = 0; i < count; ++i) {
        if (entries[i].stream_id != stream_id) continue;
        mutable_loc->buffer_head = entries[i].prev_head;
        mutable_loc->buffer_tail = entries[i].prev_tail;
        mutable_loc->token_count = entries[i].token_idx;
    }

    telemetry_.rewind_ops++;
    return true;
}

} // namespace Deep2
