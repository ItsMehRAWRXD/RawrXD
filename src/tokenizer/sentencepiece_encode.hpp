// ============================================================================
// sentencepiece_encode.hpp
// Canonical llama.cpp SPM encode (TOKENIZER-PARITY-002c single authority)
//   1) caller supplies already-normalized text (▁ metaspace, dummy prefix)
//   2) UTF-8 codepoint split
//   3) score-ordered bigram merges (tie: leftmost)
//   4) resegment + byte-fallback
// ============================================================================
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <queue>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace RawrXD {
namespace Spm {

inline size_t utf8CodepointLen(unsigned char c) noexcept {
    if ((c & 0x80) == 0) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

inline std::string normalizeMetaspace(std::string_view text) {
    static const char kUsp[] = "\xE2\x96\x81"; // U+2581
    std::string normalized;
    normalized.reserve(text.size() + 3);
    if (!text.empty()) {
        normalized.append(kUsp, 3);
    }
    for (char c : text) {
        if (c == ' ') {
            normalized.append(kUsp, 3);
        } else {
            normalized.push_back(c);
        }
    }
    return normalized;
}

// GPT-2 / Llama-3 BPE: full reversible byte-to-Unicode mapping (all 256 bytes).
// Matches bytes_to_unicode() (HF) and unicode_byte_to_utf8_map() (llama.cpp):
//   - bytes 0x21-0x7E, 0xA1-0xAC, 0xAE-0xFF map to their own codepoint;
//   - the remaining 68 bytes map to 0x100..0x143 (so space 0x20 -> U+0120 'Ġ',
//     newline 0x0A -> U+010A 'Ċ', tab 0x09 -> U+0109 'ĉ').
// The output is a UTF-8 string of the mapped codepoints (each codepoint is
// < 0x800, so 1- or 2-byte UTF-8). No leading dummy prefix.
inline std::string normalizeGpt2(std::string_view text) {
    static const std::array<uint32_t, 256> kByteToCpt = [] {
        std::array<uint32_t, 256> m{};
        std::array<bool, 256> identity{};
        for (int ch = 0x21; ch <= 0x7E; ++ch) identity[ch] = true;
        for (int ch = 0xA1; ch <= 0xAC; ++ch) identity[ch] = true;
        for (int ch = 0xAE; ch <= 0xFF; ++ch) identity[ch] = true;
        uint32_t n = 0;
        for (int b = 0; b < 256; ++b)
            m[static_cast<size_t>(b)] =
                identity[static_cast<size_t>(b)] ? static_cast<uint32_t>(b)
                                                 : (256u + n++);
        return m;
    }();
    std::string normalized;
    normalized.reserve(text.size() * 2);
    for (unsigned char c : text) {
        const uint32_t cp = kByteToCpt[c];
        if (cp < 0x80) {
            normalized.push_back(static_cast<char>(cp));
        } else {
            normalized.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            normalized.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return normalized;
}

struct Symbol {
    std::string text;
    int prev = -1;
    int next = -1;
    bool alive = true;
};

struct Bigram {
    int left = 0;
    int right = 0;
    float score = 0.0f;
    size_t size = 0;
};

struct BigramCompare {
    bool operator()(const Bigram& l, const Bigram& r) const {
        // Max-heap: higher score first; tie → smaller left index
        return (l.score < r.score) ||
               (l.score == r.score && l.left > r.left);
    }
};

// Merge-rank table for GPT-2 style byte-level BPE vocabs (llama.cpp
// llm_tokenizer_bpe). Maps "left right" -> rank in tokenizer.ggml.merges,
// where the space separator cannot collide with piece text: byte-level BPE
// encodes raw bytes through normalizeGpt2(), so a piece never contains 0x20.
//
// Rank semantics mirror llama.cpp: the pair with the LOWEST rank merges first,
// ties broken by the smaller (leftmost) symbol index.
using MergeRanks = std::unordered_map<std::string, int>;

// Byte-level BPE piece for one raw byte (the same mapping normalizeGpt2()
// applies). Used to fill the byte fallback so an unmergeable character emits
// its real byte token ("Ġ") instead of unk.
inline std::string gpt2ByteEncode(unsigned char b) {
    static const std::array<uint32_t, 256> kByteToCpt = [] {
        std::array<uint32_t, 256> m{};
        std::array<bool, 256> identity{};
        for (int ch = 0x21; ch <= 0x7E; ++ch) identity[ch] = true;
        for (int ch = 0xA1; ch <= 0xAC; ++ch) identity[ch] = true;
        for (int ch = 0xAE; ch <= 0xFF; ++ch) identity[ch] = true;
        uint32_t n = 0;
        for (int b = 0; b < 256; ++b)
            m[static_cast<size_t>(b)] =
                identity[static_cast<size_t>(b)] ? static_cast<uint32_t>(b)
                                                 : (256u + n++);
        return m;
    }();
    const uint32_t cp = kByteToCpt[b];
    std::string out;
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return out;
}

struct RankedBigram {
    int left = 0;
    int right = 0;
    int rank = 0;
    size_t size = 0;
};

struct RankedBigramCompare {
    bool operator()(const RankedBigram& l, const RankedBigram& r) const {
        // Min-heap via priority_queue ordering: lowest rank first, then
        // leftmost (llama.cpp llm_bigram_bpe::comparator).
        return (l.rank > r.rank) ||
               (l.rank == r.rank && l.left > r.left);
    }
};

// Encode pre-normalized SentencePiece text into token IDs.
// scores may be null → treated as 0 (TinyLlama GGUF ships all-zero scores).
inline bool encodeNormalized(
    std::string_view normalized,
    const std::unordered_map<std::string, int>& vocab,
    const std::array<int, 256>& byteFallback,
    const float* scores, // nullable; length == vocab universe
    int unkId,
    std::vector<int>& output)
{
    output.clear();
    if (normalized.empty()) {
        return true;
    }

    std::vector<Symbol> symbols;
    symbols.reserve(normalized.size());

    size_t offs = 0;
    int index = 0;
    while (offs < normalized.size()) {
        const size_t len = std::min(
            utf8CodepointLen(
                static_cast<unsigned char>(normalized[offs])),
            normalized.size() - offs);
        Symbol sym;
        sym.text.assign(normalized.data() + offs, len);
        sym.prev = index - 1;
        sym.next = (offs + len >= normalized.size()) ? -1 : index + 1;
        symbols.push_back(std::move(sym));
        offs += len;
        ++index;
    }

    std::priority_queue<Bigram, std::vector<Bigram>, BigramCompare> work;
    std::map<std::string, std::pair<std::string, std::string>> revMerge;

    auto tryAddBigram = [&](int left, int right) {
        if (left < 0 || right < 0) return;
        if (!symbols[static_cast<size_t>(left)].alive ||
            !symbols[static_cast<size_t>(right)].alive) {
            return;
        }
        const std::string text =
            symbols[static_cast<size_t>(left)].text +
            symbols[static_cast<size_t>(right)].text;
        auto it = vocab.find(text);
        if (it == vocab.end()) return;

        Bigram bigram;
        bigram.left = left;
        bigram.right = right;
        bigram.size = symbols[static_cast<size_t>(left)].text.size() +
                      symbols[static_cast<size_t>(right)].text.size();
        if (scores) {
            bigram.score = scores[it->second];
        } else {
            bigram.score = 0.0f;
        }
        work.push(bigram);
        revMerge[text] = {
            symbols[static_cast<size_t>(left)].text,
            symbols[static_cast<size_t>(right)].text};
    };

    for (int i = 1; i < static_cast<int>(symbols.size()); ++i) {
        tryAddBigram(i - 1, i);
    }

    while (!work.empty()) {
        const Bigram bigram = work.top();
        work.pop();

        Symbol& leftSym = symbols[static_cast<size_t>(bigram.left)];
        Symbol& rightSym = symbols[static_cast<size_t>(bigram.right)];

        if (!leftSym.alive || !rightSym.alive ||
            leftSym.text.size() + rightSym.text.size() != bigram.size) {
            continue;
        }

        leftSym.text += rightSym.text;
        rightSym.alive = false;
        leftSym.next = rightSym.next;
        if (rightSym.next >= 0) {
            symbols[static_cast<size_t>(rightSym.next)].prev = bigram.left;
        }

        tryAddBigram(leftSym.prev, bigram.left);
        tryAddBigram(bigram.left, leftSym.next);
    }

    auto resegment = [&](auto&& self, const std::string& text) -> void {
        auto it = vocab.find(text);
        if (it != vocab.end()) {
            output.push_back(it->second);
            return;
        }
        auto rm = revMerge.find(text);
        if (rm != revMerge.end()) {
            self(self, rm->second.first);
            self(self, rm->second.second);
            return;
        }
        for (unsigned char c : text) {
            if (byteFallback[c] >= 0) {
                output.push_back(byteFallback[c]);
            } else {
                output.push_back(unkId);
            }
        }
    };

    int i = 0;
    while (i < static_cast<int>(symbols.size()) &&
           !symbols[static_cast<size_t>(i)].alive) {
        ++i;
    }
    while (i >= 0 && i < static_cast<int>(symbols.size())) {
        resegment(resegment, symbols[static_cast<size_t>(i)].text);
        i = symbols[static_cast<size_t>(i)].next;
    }

    return true;
}

// Encode WITHOUT prepending the metaspace marker. Used by vocabs that ship no
// metaspace marker at all (DeepSeek-V2-Lite, tokenizer.ggml.pre=deepseek-llm),
// where normalizing "Human" to "\xE2\x96\x81Human" would split every word.
inline bool encodeNoMetaspace(
    std::string_view text,
    const std::unordered_map<std::string, int>& vocab,
    const std::array<int, 256>& byteFallback,
    const float* scores,
    int unkId,
    std::vector<int>& output)
{
    return encodeNormalized(text, vocab, byteFallback, scores, unkId, output);
}

inline bool encode(
    std::string_view text,
    const std::unordered_map<std::string, int>& vocab,
    const std::array<int, 256>& byteFallback,
    const float* scores,
    int unkId,
    std::vector<int>& output)
{
    const std::string normalized = normalizeMetaspace(text);
    return encodeNormalized(
        normalized, vocab, byteFallback, scores, unkId, output);
}

inline bool encodeGpt2(
    std::string_view text,
    const std::unordered_map<std::string, int>& vocab,
    const std::array<int, 256>& byteFallback,
    const float* scores,
    int unkId,
    std::vector<int>& output)
{
    const std::string normalized = normalizeGpt2(text);
    return encodeNormalized(
        normalized, vocab, byteFallback, scores, unkId, output);
}

// Encode pre-normalized byte-level BPE text using merge ranks instead of token
// scores. This is the GPT-2 / DeepSeek path: llama.cpp looks the (left, right)
// pair up in bpe_ranks and merges the lowest rank first, tying leftmost. A pair
// is only mergeable when it appears in the merges list, so the concatenation
// need not be probed against the vocab at merge time.
inline bool encodeBpeRanked(
    std::string_view normalized,
    const std::unordered_map<std::string, int>& vocab,
    const std::array<int, 256>& byteFallback,
    const MergeRanks& ranks,
    int unkId,
    std::vector<int>& output)
{
    output.clear();
    if (normalized.empty()) {
        return true;
    }

    std::vector<Symbol> symbols;
    symbols.reserve(normalized.size());

    size_t offs = 0;
    int index = 0;
    while (offs < normalized.size()) {
        const size_t len = std::min(
            utf8CodepointLen(
                static_cast<unsigned char>(normalized[offs])),
            normalized.size() - offs);
        Symbol sym;
        sym.text.assign(normalized.data() + offs, len);
        sym.prev = index - 1;
        sym.next = (offs + len >= normalized.size()) ? -1 : index + 1;
        symbols.push_back(std::move(sym));
        offs += len;
        ++index;
    }

    std::priority_queue<RankedBigram, std::vector<RankedBigram>,
                        RankedBigramCompare>
        work;

    auto tryAddBigram = [&](int left, int right) {
        if (left < 0 || right < 0) return;
        if (!symbols[static_cast<size_t>(left)].alive ||
            !symbols[static_cast<size_t>(right)].alive) {
            return;
        }
        auto it = ranks.find(symbols[static_cast<size_t>(left)].text + " " +
                             symbols[static_cast<size_t>(right)].text);
        if (it == ranks.end()) return;

        RankedBigram bigram;
        bigram.left = left;
        bigram.right = right;
        bigram.rank = it->second;
        bigram.size = symbols[static_cast<size_t>(left)].text.size() +
                      symbols[static_cast<size_t>(right)].text.size();
        work.push(bigram);
    };

    for (int i = 1; i < static_cast<int>(symbols.size()); ++i) {
        tryAddBigram(i - 1, i);
    }

    while (!work.empty()) {
        const RankedBigram bigram = work.top();
        work.pop();

        Symbol& leftSym = symbols[static_cast<size_t>(bigram.left)];
        Symbol& rightSym = symbols[static_cast<size_t>(bigram.right)];

        if (!leftSym.alive || !rightSym.alive ||
            leftSym.text.size() + rightSym.text.size() != bigram.size) {
            continue;
        }

        leftSym.text += rightSym.text;
        rightSym.alive = false;
        leftSym.next = rightSym.next;
        if (rightSym.next >= 0) {
            symbols[static_cast<size_t>(rightSym.next)].prev = bigram.left;
        }

        tryAddBigram(leftSym.prev, bigram.left);
        tryAddBigram(bigram.left, leftSym.next);
    }

    // Emit: exact vocab hit, else per-byte fallback (llama.cpp BPE final pass).
    int i = 0;
    while (i >= 0 && i < static_cast<int>(symbols.size())) {
        const std::string& text = symbols[static_cast<size_t>(i)].text;
        auto it = vocab.find(text);
        if (it != vocab.end()) {
            output.push_back(it->second);
        } else {
            for (unsigned char c : text) {
                output.push_back(
                    byteFallback[static_cast<size_t>(c)] >= 0
                        ? byteFallback[static_cast<size_t>(c)]
                        : unkId);
            }
        }
        i = symbols[static_cast<size_t>(i)].next;
    }

    return true;
}

inline bool encodeGpt2Bpe(
    std::string_view text,
    const std::unordered_map<std::string, int>& vocab,
    const std::array<int, 256>& byteFallback,
    const MergeRanks& ranks,
    int unkId,
    std::vector<int>& output)
{
    const std::string normalized = normalizeGpt2(text);
    return encodeBpeRanked(
        normalized, vocab, byteFallback, ranks, unkId, output);
}

} // namespace Spm
} // namespace RawrXD
