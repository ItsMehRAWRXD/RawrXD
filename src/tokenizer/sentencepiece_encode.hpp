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

} // namespace Spm
} // namespace RawrXD
