#pragma once
// ============================================================================
// DecodeLoopAttribution.hpp
// Source-only Deep2 decode-loop attribution and single-token detok carry.
//
// Goal:
//   TOKENS_DECODED should describe real tokenizer work, not cumulative history
//   replay. Generated/committed token authority stays in the caller.
//
// Drop-in:
//   src/deep2/lavapath/DecodeLoopAttribution.hpp
//   include from src/deep2/Deep2Engine.cpp near Batch007Emit.hpp.
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <chrono>

namespace rawr::decode_loop {

using Clock = std::chrono::high_resolution_clock;

inline uint64_t NsSince(Clock::time_point t0) noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - t0).count());
}

struct Acc {
    uint64_t tokensRequested = 0;
    uint64_t tokensCommitted = 0;
    uint64_t tokenizerSingleCalls = 0;
    uint64_t tokenizerSequenceCalls = 0;
    uint64_t tokenIdsDecoded = 0;
    uint64_t detokNs = 0;
    uint64_t callbackNs = 0;
    uint64_t rawBytes = 0;
    uint64_t emittedBytes = 0;
    uint64_t utf8PendingBytes = 0;
    uint64_t utf8Errors = 0;
};

inline Acc& A() noexcept {
    static Acc a;
    return a;
}

inline void Reset(uint64_t requested = 0) noexcept {
    A() = Acc{};
    A().tokensRequested = requested;
}

inline bool Utf8Need(unsigned char c, size_t& need) noexcept {
    if (c < 0x80) { need = 1; return true; }
    if ((c & 0xE0) == 0xC0) { need = 2; return true; }
    if ((c & 0xF0) == 0xE0) { need = 3; return true; }
    if ((c & 0xF8) == 0xF0) { need = 4; return true; }
    return false;
}

inline size_t ValidUtf8PrefixLen(const std::string& s, bool& valid) noexcept {
    valid = true;
    size_t i = 0;
    while (i < s.size()) {
        size_t need = 1;
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (!Utf8Need(c, need)) { valid = false; return i; }
        if (i + need > s.size()) return i;
        for (size_t k = 1; k < need; ++k) {
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) {
                valid = false;
                return i;
            }
        }
        i += need;
    }
    return i;
}

struct Utf8Carry {
    std::string pending;

    std::string feed(const std::string& raw) {
        Acc& a = A();
        a.rawBytes += raw.size();
        pending += raw;

        bool valid = true;
        const size_t emitLen = ValidUtf8PrefixLen(pending, valid);
        if (!valid) {
            // Fail-soft for stream display: emit raw pending and mark it. This
            // preserves visible output but makes the UTF-8 problem auditable.
            a.utf8Errors++;
            std::string out = pending;
            pending.clear();
            a.emittedBytes += out.size();
            a.utf8PendingBytes = 0;
            return out;
        }

        std::string out = pending.substr(0, emitLen);
        pending.erase(0, emitLen);
        a.emittedBytes += out.size();
        a.utf8PendingBytes = pending.size();
        return out;
    }

    std::string flush() {
        Acc& a = A();
        if (pending.empty()) return {};
        a.utf8PendingBytes = pending.size();
        // Do not invent a token commit for incomplete trailing bytes. Caller may
        // include this in final text only when explicitly choosing fail-soft text.
        return {};
    }
};

template <class TokenizerT>
inline std::string DecodeOne(TokenizerT* tokenizer, int tokenId, Utf8Carry& carry) {
    auto t0 = Clock::now();
    std::string raw;
    if (tokenizer) raw = tokenizer->Decode(tokenId);
    const uint64_t ns = NsSince(t0);

    Acc& a = A();
    a.tokenizerSingleCalls++;
    a.tokenIdsDecoded += 1;
    a.detokNs += ns;
    return carry.feed(raw);
}

inline void NoteSequenceDecode(uint64_t ids, uint64_t ns) noexcept {
    Acc& a = A();
    a.tokenizerSequenceCalls++;
    a.tokenIdsDecoded += ids;
    a.detokNs += ns;
}

inline void NoteCommit() noexcept {
    A().tokensCommitted++;
}

inline void NoteCallbackNs(uint64_t ns) noexcept {
    A().callbackNs += ns;
}

inline void Emit(FILE* f = stderr) noexcept {
    if (!f) return;
    const Acc& a = A();
    std::fprintf(f,
        "DECODE_LOOP_ATTRIBUTION_BEGIN=1\n"
        "TOKENS_REQUESTED=%llu\n"
        "TOKENS_COMMITTED=%llu\n"
        "TOKENS_DECODED=%llu\n"
        "TOKENIZER_SINGLE_CALLS=%llu\n"
        "TOKENIZER_SEQUENCE_CALLS=%llu\n"
        "DETOK_WALL_NS=%llu\n"
        "CALLBACK_WALL_NS=%llu\n"
        "DETOK_RAW_BYTES=%llu\n"
        "DETOK_EMITTED_BYTES=%llu\n"
        "DETOK_UTF8_PENDING_BYTES=%llu\n"
        "DETOK_UTF8_ERRORS=%llu\n"
        "DECODE_REPLAY_FACTOR=%.6f\n"
        "DECODE_LOOP_ATTRIBUTION_END=1\n",
        (unsigned long long)a.tokensRequested,
        (unsigned long long)a.tokensCommitted,
        (unsigned long long)a.tokenIdsDecoded,
        (unsigned long long)a.tokenizerSingleCalls,
        (unsigned long long)a.tokenizerSequenceCalls,
        (unsigned long long)a.detokNs,
        (unsigned long long)a.callbackNs,
        (unsigned long long)a.rawBytes,
        (unsigned long long)a.emittedBytes,
        (unsigned long long)a.utf8PendingBytes,
        (unsigned long long)a.utf8Errors,
        a.tokensCommitted ?
            (double)a.tokenIdsDecoded / (double)a.tokensCommitted : 0.0);
    std::fflush(f);
}

} // namespace rawr::decode_loop
