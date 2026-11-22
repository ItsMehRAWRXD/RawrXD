#pragma once
#include <cstdint>

namespace Deep2 { namespace Transfer {

enum class Stage { Complete, Idle, Begin, Record, Submit };

inline bool RangeFits(uint64_t size, uint64_t offset, uint64_t bytes) noexcept {
    return bytes != 0 && offset <= size && bytes <= size - offset;
}

inline const char* StageName(Stage stage) noexcept {
    switch (stage) {
    case Stage::Complete: return "ok";
    case Stage::Idle: return "queue_idle";
    case Stage::Begin: return "begin_command";
    case Stage::Record: return "record_copy";
    case Stage::Submit: return "transfer_wait";
    }
    return "unknown";
}

// Idle preflight precedes command acquisition. Begin owns cleanup on failure;
// discard owns an acquired, never-submitted command after a recording failure.
// Once submit is invoked, that callback owns the command and must enforce the
// submission completion contract. Never discard an unresolved submission here.
template<class Idle, class Begin, class Record, class Submit, class Discard>
Stage Execute(Idle&& idle, Begin&& begin, Record&& record,
              Submit&& submit, Discard&& discard) {
    if (!idle()) return Stage::Idle;
    if (!begin()) return Stage::Begin;
    if (!record()) {
        discard();
        return Stage::Record;
    }
    return submit() ? Stage::Complete : Stage::Submit;
}

} } // namespace Deep2::Transfer
