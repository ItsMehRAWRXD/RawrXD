#pragma once
/* ExchangeMirror — reverse-discover host/device exchanges not in D2H mirror. */
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace Deep2 {
namespace ExchangeMirror {

enum class Dir : uint8_t { H2D = 1, D2H = 2, D2D = 3, HOST_MEM = 4 };
enum class Kind : uint8_t { Weight = 0, Activation = 1, Other = 2 };

#pragma pack(push, 1)
struct Rec {
    uint64_t bytes;
    uint32_t ops;
    uint16_t dir;
    uint16_t kind;
    char tag[48];
};
#pragma pack(pop)

inline constexpr uint32_t kCap = 256;
struct Store {
    Rec slots[kCap];
    std::atomic<uint32_t> n{0};
};
inline Store& S() { static Store s{}; return s; }

inline void Reset() {
    Store& s = S();
    s.n.store(0, std::memory_order_relaxed);
    std::memset(s.slots, 0, sizeof(s.slots));
}

inline void Note(Dir d, Kind k, uint64_t bytes, const char* tag) {
    if (!bytes || !tag) return;
    Store& s = S();
    const uint32_t i = s.n.fetch_add(1, std::memory_order_relaxed);
    if (i >= kCap) return;
    Rec& r = s.slots[i];
    r.bytes = bytes;
    r.ops = 1;
    r.dir = (uint16_t)d;
    r.kind = (uint16_t)k;
    std::snprintf(r.tag, sizeof(r.tag), "%s", tag);
}

/* Aggregate duplicate tags for compact emit. */
inline void NoteAgg(Dir d, Kind k, uint64_t bytes, const char* tag) {
    if (!bytes || !tag) return;
    Store& s = S();
    const uint32_t n = s.n.load(std::memory_order_relaxed);
    const uint32_t lim = n < kCap ? n : kCap;
    for (uint32_t i = 0; i < lim; ++i) {
        if (std::strncmp(s.slots[i].tag, tag, sizeof(s.slots[i].tag)) == 0 &&
            s.slots[i].dir == (uint16_t)d) {
            s.slots[i].bytes += bytes;
            s.slots[i].ops += 1;
            return;
        }
    }
    Note(d, k, bytes, tag);
}

inline const char* DirName(uint16_t d) {
    switch ((Dir)d) {
    case Dir::H2D: return "H2D";
    case Dir::D2H: return "D2H";
    case Dir::D2D: return "D2D";
    case Dir::HOST_MEM: return "HOST_MEM";
    default: return "UNK";
    }
}
inline const char* KindName(uint16_t k) {
    switch ((Kind)k) {
    case Kind::Weight: return "WEIGHT";
    case Kind::Activation: return "ACT";
    default: return "OTHER";
    }
}

/* Sealed D2H_CLASSIFICATION_001 mirror keys (product). */
inline bool InD2hMirror(const char* tag) {
    if (!tag) return false;
    /* Known mirrored product exchanges */
    if (std::strstr(tag, "q_b")) return true;
    if (std::strstr(tag, "hidden_h2d")) return true;
    if (std::strstr(tag, "qa_deleted")) return true;
    if (std::strstr(tag, "logits")) return true;
    if (std::strstr(tag, "o_proj")) return true;
    return false;
}

inline void Emit(FILE* f) {
    if (!f) f = stdout;
    Store& s = S();
    const uint32_t n = s.n.load(std::memory_order_relaxed);
    const uint32_t lim = n < kCap ? n : kCap;
    uint32_t miss = 0, hit = 0;
    fprintf(f, "EXCHANGE_MIRROR_REVERSE=1\n");
    fprintf(f, "EXCHANGE_SLOT_COUNT=%u\n", lim);
    fprintf(f, "EXCHANGE_OVERFLOW=%u\n", n > kCap ? 1u : 0u);
    for (uint32_t i = 0; i < lim; ++i) {
        const Rec& r = s.slots[i];
        const int mir = InD2hMirror(r.tag) ? 1 : 0;
        if (mir) ++hit; else ++miss;
        fprintf(f,
            "EXCHANGE_OBJ id=%u dir=%s kind=%s bytes=%llu ops=%u tag=%s "
            "IN_D2H_MIRROR=%d NOT_IN_MIRROR=%d\n",
            i, DirName(r.dir), KindName(r.kind),
            (unsigned long long)r.bytes, r.ops, r.tag, mir, mir ? 0 : 1);
    }
    fprintf(f, "EXCHANGE_IN_MIRROR=%u\n", hit);
    fprintf(f, "EXCHANGE_NOT_IN_MIRROR=%u\n", miss);
    fflush(f);
}

} // namespace ExchangeMirror
} // namespace Deep2
