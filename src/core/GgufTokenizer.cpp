#include "GgufTokenizer.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>

namespace Deep2Rom::Inference {

namespace {

constexpr uint32_t kGgufMagic = 0x46554747u;  // "GGUF"

// Sentinel for "this model has no token of that kind".
constexpr uint32_t kNoToken = 0xFFFFFFFFu;

// GGUF metadata value types.
enum GgufType {
    GGUF_TYPE_UINT8   = 0,
    GGUF_TYPE_INT8    = 1,
    GGUF_TYPE_UINT16  = 2,
    GGUF_TYPE_INT16   = 3,
    GGUF_TYPE_UINT32  = 4,
    GGUF_TYPE_INT32   = 5,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL    = 7,
    GGUF_TYPE_STRING  = 8,
    GGUF_TYPE_ARRAY   = 9,
    GGUF_TYPE_UINT64  = 10,
    GGUF_TYPE_INT64   = 11,
    GGUF_TYPE_FLOAT64 = 12,
};

// Length in bytes of a UTF-8 sequence given its first byte.
size_t utf8Len(uint8_t b) {
    static const size_t lookup[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3, 4};
    return lookup[b >> 4];
}

// Bytes that the GPT-2 byte-to-unicode mapping relocates to U+0100 and up,
// listed in ascending byte order.
constexpr uint8_t kRelocatedBytes[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
    0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
    0x9E, 0x9F, 0xA0, 0xAD,
};

// Read a UTF-8 codepoint at `off`, advancing `off` past it.
uint32_t nextCodepoint(const std::string& s, size_t& off) {
    if (off >= s.size()) return 0;
    uint8_t b = static_cast<uint8_t>(s[off]);
    size_t len = utf8Len(b);
    if (off + len > s.size()) len = 1;
    uint32_t cp = b;
    switch (len) {
        case 2: cp = ((b & 0x1Fu) << 6) | (static_cast<uint8_t>(s[off + 1]) & 0x3Fu); break;
        case 3: cp = ((b & 0x0Fu) << 12) | ((static_cast<uint8_t>(s[off + 1]) & 0x3Fu) << 6)
                     | (static_cast<uint8_t>(s[off + 2]) & 0x3Fu); break;
        case 4: cp = ((b & 0x07u) << 18) | ((static_cast<uint8_t>(s[off + 1]) & 0x3Fu) << 12)
                     | ((static_cast<uint8_t>(s[off + 2]) & 0x3Fu) << 6)
                     | (static_cast<uint8_t>(s[off + 3]) & 0x3Fu); break;
        default: break;
    }
    off += len;
    return cp;
}

enum class CharClass { Letter, Number, Other, Space };

// Is the codepoint in a CJK / Hangul ideograph block? These are split as
// their own class by the DeepSeek and Llama-3 pre-tokenizers.
bool isCjkCodepoint(uint32_t cp) {
    return (cp >= 0x4E00 && cp <= 0x9FFF) ||   // CJK unified ideographs
           (cp >= 0x3400 && cp <= 0x4DBF) ||   // CJK extension A
           (cp >= 0xF900 && cp <= 0xFAFF) ||   // CJK compatibility ideographs
           (cp >= 0xAC00 && cp <= 0xD7AF) ||   // Hangul syllables
           (cp >= 0x20000 && cp <= 0x2A6DF);  // CJK extension B
}

// Classify a codepoint for the BPE pre-tokenizer.
//
// NOTE: this is an ASCII-exact approximation of the Unicode property classes
// \p{L} and \p{N} that the GPT-2 pre-tokenizer uses. Every codepoint above
// U+007F is treated as a letter apart from CJK ideographs, which get their
// own class. That is exact for Latin-1 and correct for the ASCII prompts the
// IDE issues.
CharClass classify(uint32_t cp) {
    if (cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r' || cp == '\v' || cp == '\f')
        return CharClass::Space;
    if (cp >= '0' && cp <= '9') return CharClass::Number;
    if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z')) return CharClass::Letter;
    if (cp >= 0x80u) return isCjkCodepoint(cp) ? CharClass::Other : CharClass::Letter;
    return CharClass::Other;
}

// Split text into GPT-2 pre-tokenizer fragments:
//
//   's|'t|'re|'ve|'m|'ll|'d
//   ?\p{L}+
//   ?\p{N}+
//   ?[^\s\p{L}\p{N}]+
//   \s+(?!\S)
//   \s+
std::vector<std::string> gpt2Pretokenize(const std::string& text) {
    static const char* kContractions[] = {"s", "t", "re", "ve", "m", "ll", "d"};

    std::vector<std::string> out;
    size_t i = 0;
    const size_t n = text.size();

    while (i < n) {
        // Rule 1: contractions.
        if (text[i] == '\'') {
            bool matched = false;
            for (const char* suffix : kContractions) {
                size_t len = std::strlen(suffix);
                if (i + 1 + len <= n) {
                    bool same = true;
                    for (size_t k = 0; k < len; ++k) {
                        char a = text[i + 1 + k];
                        char b = suffix[k];
                        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
                        if (a != b) { same = false; break; }
                    }
                    if (same) {
                        out.push_back(text.substr(i, 1 + len));
                        i += 1 + len;
                        matched = true;
                        break;
                    }
                }
            }
            if (matched) continue;
        }

        // Rules 2-4: optional single leading space followed by a run of one class.
        {
            size_t start = i;
            if (text[i] == ' ' && i + 1 < n) {
                size_t probe = i + 1;
                uint32_t cp = nextCodepoint(text, probe);
                if (classify(cp) != CharClass::Space) {
                    // The optional space joins the run that follows it.
                    CharClass cls = classify(cp);
                    size_t r = i + 1;
                    while (r < n) {
                        size_t p = r;
                        uint32_t c = nextCodepoint(text, p);
                        if (classify(c) != cls) break;
                        r = p;
                    }
                    out.push_back(text.substr(start, r - start));
                    i = r;
                    continue;
                }
            }

            // No leading space: the run starts at the current position.
            {
                size_t p = i;
                uint32_t cp = nextCodepoint(text, p);
                CharClass cls = classify(cp);
                if (cls != CharClass::Space) {
                    size_t r = i;
                    while (r < n) {
                        size_t pp = r;
                        uint32_t c = nextCodepoint(text, pp);
                        if (classify(c) != cls) break;
                        r = pp;
                    }
                    out.push_back(text.substr(i, r - i));
                    i = r;
                    continue;
                }
            }
        }

        // Rules 5-6: whitespace runs. `\s+(?!\S)` peels off all but the final
        // whitespace character when the run is followed by a non-space, so the
        // last space can still be attached to the word that follows.
        {
            size_t j = i;
            while (j < n) {
                size_t p = j;
                uint32_t cp = nextCodepoint(text, p);
                if (classify(cp) != CharClass::Space) break;
                j = p;
            }
            if (j > i && j < n && (j - i) > 1) {
                out.push_back(text.substr(i, (j - i) - 1));
                i = j - 1;
            } else {
                out.push_back(text.substr(i, j - i));
                i = j;
            }
        }
    }
    return out;
}

// DeepSeek / Llama-3 pre-tokenizer.
//
// The pre-tokenizer is a sequence of regex "Split" stages, each applied to the
// pieces left by the previous one. A stage isolates the text matching its
// pattern; the text between matches survives as separate pieces and is passed
// on to the next stage.
//
//   0. [\r\n]              newlines are isolated
//   1. \s? [letters]+      any single whitespace may prefix a word
//   2. \s? [punct]+        any single whitespace may prefix punctuation
//   3. \s+$                trailing whitespace
//   4. [CJK]+
//   5. \p{N}+
//
// The Unicode letter/punctuation classes are approximated by the ASCII-exact
// classifier above, which matches on Latin text.
enum class SplitPattern {
    Newline,
    Letter,
    Punct,
    TrailingSpace,
    Cjk,
    Number,
};

struct SplitPiece {
    std::string text;
    bool isMatch = false;
};

// Length of the pattern match at `pos`, or 0 when the pattern does not match.
size_t matchAt(const std::string& s, size_t pos, SplitPattern pattern) {
    const size_t n = s.size();
    if (pos >= n) return 0;

    auto cpAt = [&](size_t p, size_t& next) {
        next = p;
        return nextCodepoint(s, next);
    };

    switch (pattern) {
        case SplitPattern::Newline: {
            size_t p = pos;
            uint32_t cp = cpAt(pos, p);
            return (cp == '\r' || cp == '\n') ? (p - pos) : 0;
        }
        case SplitPattern::Letter:
        case SplitPattern::Punct: {
            const CharClass want =
                (pattern == SplitPattern::Letter) ? CharClass::Letter : CharClass::Other;
            const size_t start = pos;
            size_t p = pos;
            uint32_t cp = cpAt(pos, p);
            if (classify(cp) == CharClass::Space && p < n) {
                // An optional single whitespace may prefix the run.
                size_t q = p;
                uint32_t cp2 = cpAt(p, q);
                if (classify(cp2) != want) return 0;
                pos = p;
            }
            if (pos >= n) return 0;
            size_t r = pos;
            while (r < n) {
                size_t rr = r;
                uint32_t c = cpAt(r, rr);
                if (classify(c) != want) break;
                r = rr;
            }
            // The match includes the optional whitespace prefix.
            return (r > pos) ? (r - start) : 0;
        }
        case SplitPattern::TrailingSpace: {
            // \s+$ : the match is the trailing whitespace run, so it only
            // starts at the first character of that run.
            size_t r = n;
            while (r > 0) {
                size_t rr = r - 1;
                while (rr > 0 && ((static_cast<uint8_t>(s[rr]) & 0xC0) == 0x80)) --rr;
                size_t q = rr;
                uint32_t cp = cpAt(rr, q);
                if (classify(cp) != CharClass::Space) break;
                r = rr;
            }
            if (r == n || r != pos) return 0;
            return n - pos;
        }
        case SplitPattern::Cjk: {
            size_t r = pos;
            while (r < n) {
                size_t rr = r;
                uint32_t cp = cpAt(r, rr);
                if (!isCjkCodepoint(cp)) break;
                r = rr;
            }
            return (r > pos) ? (r - pos) : 0;
        }
        case SplitPattern::Number: {
            size_t r = pos;
            while (r < n) {
                size_t rr = r;
                uint32_t cp = cpAt(r, rr);
                if (classify(cp) != CharClass::Number) break;
                r = rr;
            }
            return (r > pos) ? (r - pos) : 0;
        }
    }
    return 0;
}

// Split `text` by one pattern stage, returning the alternating
// non-match / match pieces.
std::vector<SplitPiece> splitByPattern(const std::string& text, SplitPattern pattern) {
    std::vector<SplitPiece> out;
    size_t pos = 0;
    const size_t n = text.size();
    while (pos < n) {
        const size_t len = matchAt(text, pos, pattern);
        if (len == 0) {
            pos = nextCodepoint(text, pos);
            continue;
        }
        // Emit the non-match text preceding this match.
        // (Handled by the caller walking the pieces.)
        SplitPiece p;
        p.text = text.substr(pos, len);
        p.isMatch = true;
        out.push_back(std::move(p));
        pos += len;
    }
    return out;
}

// Recursive application of the split stages: a matched piece is final, an
// unmatched run continues to the next stage.
void applySplitStages(const std::string& text, size_t stageIndex,
                      const std::vector<SplitPattern>& stages,
                      std::vector<std::string>& out) {
    if (text.empty()) return;
    if (stageIndex >= stages.size()) {
        out.push_back(text);
        return;
    }
    const SplitPattern pattern = stages[stageIndex];

    size_t pos = 0;
    const size_t n = text.size();
    size_t segStart = 0;
    while (pos < n) {
        const size_t len = matchAt(text, pos, pattern);
        if (len == 0) {
            pos = nextCodepoint(text, pos);
            continue;
        }
        // The text between the previous match and this one is unmatched.
        applySplitStages(text.substr(segStart, pos - segStart), stageIndex + 1, stages, out);
        out.push_back(text.substr(pos, len));
        pos += len;
        segStart = pos;
    }
    applySplitStages(text.substr(segStart), stageIndex + 1, stages, out);
}

std::vector<std::string> deepseekPretokenize(const std::string& text) {
    static const std::vector<SplitPattern> kStages = {
        SplitPattern::Newline,
        SplitPattern::Letter,
        SplitPattern::Punct,
        SplitPattern::TrailingSpace,
        SplitPattern::Cjk,
        SplitPattern::Number,
    };
    std::vector<std::string> out;
    applySplitStages(text, 0, kStages, out);
    return out;
}

// One symbol in the SPM merge chain.
struct SpmSymbol {
    int prev = -1;
    int next = -1;
    size_t off = 0;  // byte offset into the escaped text
    size_t n = 0;    // byte length
};

// One candidate merge. Ordered by score (highest first), then by position
// (leftmost first) - matches llama.cpp's llm_bigram_spm comparator.
struct SpmBigram {
    int left = 0;
    int right = 0;
    float score = 0.0f;
    size_t size = 0;
};

struct SpmBigramGreater {
    bool operator()(const SpmBigram& l, const SpmBigram& r) const {
        return (l.score < r.score) || (l.score == r.score && l.left > r.left);
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

bool GgufTokenizer::loadFromGGUF(const std::string& ggufPath) {
    std::ifstream f(ggufPath, std::ios::binary);
    if (!f) {
        std::cerr << "[GgufTokenizer] Cannot open GGUF: " << ggufPath << std::endl;
        return false;
    }

    uint32_t magic = 0, version = 0;
    f.read(reinterpret_cast<char*>(&magic), 4);
    f.read(reinterpret_cast<char*>(&version), 4);
    if (magic != kGgufMagic) {
        std::cerr << "[GgufTokenizer] Invalid GGUF magic" << std::endl;
        return false;
    }

    uint64_t tensorCount = 0, kvCount = 0;
    f.read(reinterpret_cast<char*>(&tensorCount), 8);
    f.read(reinterpret_cast<char*>(&kvCount), 8);
    (void)tensorCount;

    auto readStr = [&](std::string& out) -> bool {
        uint64_t len = 0;
        f.read(reinterpret_cast<char*>(&len), 8);
        if (!f || len > (1u << 22)) return false;
        out.resize(static_cast<size_t>(len));
        f.read(out.data(), static_cast<std::streamsize>(len));
        return static_cast<bool>(f);
    };
    auto skipValue = [&](uint32_t type) -> bool {
        if (type <= 7) {
            static const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
            f.seekg(sz[type & 7], std::ios::cur);
            return static_cast<bool>(f);
        }
        if (type == 8) { std::string s; return readStr(s); }
        if (type == 9) {
            uint32_t at = 0;
            uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            if (at == 8) {
                for (uint64_t i = 0; i < al; ++i) { std::string s; if (!readStr(s)) return false; }
            } else {
                static const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
                f.seekg(static_cast<std::streamoff>(al * sz[at & 7]), std::ios::cur);
            }
            return static_cast<bool>(f);
        }
        if (type == 10 || type == 11 || type == 12) {
            f.seekg(8, std::ios::cur);
            return static_cast<bool>(f);
        }
        return false;
    };

    std::string modelType;
    std::string preType;
    bool haveMerges = false;
    bool haveScores = false;
    bool haveTokenTypes = false;

    for (uint64_t i = 0; i < kvCount; ++i) {
        std::string key;
        if (!readStr(key)) { std::cerr << "[GgufTokenizer] Truncated metadata" << std::endl; return false; }
        uint32_t type = 0;
        f.read(reinterpret_cast<char*>(&type), 4);
        if (!f) { std::cerr << "[GgufTokenizer] Truncated metadata" << std::endl; return false; }

        if (key == "tokenizer.ggml.tokens") {
            uint32_t at = 0; uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            if (at != 8) { std::cerr << "[GgufTokenizer] tokens is not a string array" << std::endl; return false; }
            m_vocab.reserve(static_cast<size_t>(al));
            for (uint64_t j = 0; j < al; ++j) {
                std::string t;
                if (!readStr(t)) { std::cerr << "[GgufTokenizer] Truncated token list" << std::endl; return false; }
                m_vocab.push_back(std::move(t));
            }
        } else if (key == "tokenizer.ggml.scores") {
            uint32_t at = 0; uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            if (at != 6) { std::cerr << "[GgufTokenizer] scores is not a float array" << std::endl; return false; }
            m_scores.reserve(static_cast<size_t>(al));
            for (uint64_t j = 0; j < al; ++j) {
                float v = 0.0f;
                f.read(reinterpret_cast<char*>(&v), 4);
                m_scores.push_back(v);
            }
            haveScores = true;
        } else if (key == "tokenizer.ggml.token_type") {
            uint32_t at = 0; uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            if (at != 5) { std::cerr << "[GgufTokenizer] token_type is not a uint32 array" << std::endl; return false; }
            m_tokenTypes.reserve(static_cast<size_t>(al));
            for (uint64_t j = 0; j < al; ++j) {
                uint32_t v = 0;
                f.read(reinterpret_cast<char*>(&v), 4);
                m_tokenTypes.push_back(v);
            }
            haveTokenTypes = true;
        } else if (key == "tokenizer.ggml.merges") {
            uint32_t at = 0; uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            if (at != 8) { std::cerr << "[GgufTokenizer] merges is not a string array" << std::endl; return false; }
            m_merges.reserve(static_cast<size_t>(al));
            for (uint64_t j = 0; j < al; ++j) {
                std::string rule;
                if (!readStr(rule)) { std::cerr << "[GgufTokenizer] Truncated merge list" << std::endl; return false; }
                // llama.cpp splits on the first space starting at index 1 so a
                // leading space in the left-hand token is preserved.
                size_t pos = rule.find(' ', 1);
                if (pos == std::string::npos) {
                    m_merges.emplace_back(rule, std::string());
                } else {
                    m_merges.emplace_back(rule.substr(0, pos), rule.substr(pos + 1));
                }
            }
            haveMerges = true;
        } else if (key == "tokenizer.ggml.bos_token_id") {
            f.read(reinterpret_cast<char*>(&m_bosId), 4);
        } else if (key == "tokenizer.ggml.eos_token_id") {
            f.read(reinterpret_cast<char*>(&m_eosId), 4);
        } else if (key == "tokenizer.ggml.unknown_token_id") {
            uint32_t v = 0;
            f.read(reinterpret_cast<char*>(&v), 4);
            // A stored -1 (0xFFFFFFFF) means the model has no unknown token.
            m_unkId = (v == 0xFFFFFFFFu) ? kNoToken : v;
        } else if (key == "tokenizer.ggml.padding_token_id") {
            f.read(reinterpret_cast<char*>(&m_padId), 4);
        } else if (key == "tokenizer.ggml.model") {
            readStr(modelType);
        } else if (key == "tokenizer.ggml.pre") {
            readStr(preType);
        } else if (!skipValue(type)) {
            std::cerr << "[GgufTokenizer] Failed to skip metadata value for " << key << std::endl;
            return false;
        }
    }

    if (m_vocab.empty()) {
        std::cerr << "[GgufTokenizer] Missing tokenizer.ggml.tokens" << std::endl;
        return false;
    }

    // Tokenizer family. SPM models ("llama") carry no merge table; BPE models
    // ("gpt2") do.
    if (modelType == "llama") {
        m_type = GgufTokenizerType::Spm;
        m_addSpacePrefix = true;
    } else if (modelType == "gpt2") {
        m_type = GgufTokenizerType::Bpe;
        m_addSpacePrefix = false;
    } else if (haveMerges) {
        m_type = GgufTokenizerType::Bpe;
        m_addSpacePrefix = false;
    } else {
        m_type = GgufTokenizerType::Spm;
        m_addSpacePrefix = true;
    }

    m_tokenToId.clear();
    m_tokenToId.reserve(m_vocab.size() * 2);
    for (uint32_t i = 0; i < m_vocab.size(); ++i) {
        m_tokenToId.emplace(m_vocab[i], i);
    }

    // Merge ranks. The rank is the position of the rule in the GGUF merge
    // array; lower rank merges first.
    m_mergeRanks.clear();
    m_mergeRanks.reserve(m_merges.size() * 2);
    for (size_t rank = 0; rank < m_merges.size(); ++rank) {
        auto lit = m_tokenToId.find(m_merges[rank].first);
        auto rit = m_tokenToId.find(m_merges[rank].second);
        if (lit == m_tokenToId.end() || rit == m_tokenToId.end()) continue;
        uint64_t key = (static_cast<uint64_t>(lit->second) << 32) | rit->second;
        m_mergeRanks.emplace(key, static_cast<uint32_t>(rank));
    }

    if (!haveScores && m_type == GgufTokenizerType::Spm) {
        std::cerr << "[GgufTokenizer] SPM tokenizer without tokenizer.ggml.scores" << std::endl;
        return false;
    }
    (void)haveTokenTypes;

    m_preType = preType.empty() ? std::string("default") : preType;

    m_ready = true;
    std::cerr << "[GgufTokenizer] Loaded " << m_vocab.size() << " tokens, "
              << m_merges.size() << " merges, model=" << (modelType.empty() ? "?" : modelType)
              << " (" << (m_type == GgufTokenizerType::Spm ? "spm" : "bpe") << ")"
              << " pre=" << m_preType
              << " bos=" << m_bosId << " eos=" << m_eosId << " unk=" << m_unkId << std::endl;
    return true;
}

// Select the pre-tokenizer flavour declared by tokenizer.ggml.pre.
std::vector<std::string> GgufTokenizer::pretokenize(const std::string& text) const {
    if (m_preType == "deepseek-llm" || m_preType == "llama3" || m_preType == "deepseek2") {
        return deepseekPretokenize(text);
    }
    return gpt2Pretokenize(text);
}

// ---------------------------------------------------------------------------
// Byte <-> unicode (GPT-2 "bytes to unicode" mapping)
// ---------------------------------------------------------------------------

uint32_t GgufTokenizer::byteToCodepoint(uint8_t byte) {
    if (byte >= 0x21 && byte <= 0x7E) return byte;
    if (byte >= 0xA1 && byte <= 0xAC) return byte;
    if (byte >= 0xAE && byte <= 0xFF) return byte;
    // Remaining bytes are numbered in ascending order starting at U+0100.
    for (uint32_t i = 0; i < sizeof(kRelocatedBytes); ++i) {
        if (kRelocatedBytes[i] == byte) return 256u + i;
    }
    return byte;
}

std::string GgufTokenizer::codepointToUtf8(uint32_t cp) {
    std::string out;
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return out;
}

uint32_t GgufTokenizer::byteToToken(uint8_t byte) const {
    static const char* kHex = "0123456789ABCDEF";
    char buf[7] = {'<', '0', 'x', kHex[byte >> 4], kHex[byte & 15], '>', 0};
    auto it = m_tokenToId.find(std::string(buf));
    if (it != m_tokenToId.end()) return it->second;

    // Byte-level BPE vocabularies store the byte-to-unicode form of a byte
    // (the relocated bytes are two-byte UTF-8 sequences above U+0100), so try
    // that before the raw single-character form.
    std::string unicodeForm = codepointToUtf8(byteToCodepoint(byte));
    it = m_tokenToId.find(unicodeForm);
    if (it != m_tokenToId.end()) return it->second;

    // Fall back to the single-character token.
    std::string single(1, static_cast<char>(byte));
    it = m_tokenToId.find(single);
    if (it != m_tokenToId.end()) return it->second;

    // No byte token for this byte and the model has no unknown token.
    return (m_unkId == kNoToken) ? 0u : m_unkId;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

std::vector<uint32_t> GgufTokenizer::encode(const std::string& text) const {
    if (!m_ready) return {};
    if (m_type == GgufTokenizerType::Bpe) return encodeBpe(text);
    return encodeSpm(text);
}

// SentencePiece tokenization.
//
// Mirrors llama.cpp's llm_tokenizer_spm_session: the text is escaped so that
// spaces become U+2581, split into UTF-8 characters, then adjacent characters
// are merged greedily - highest token score first - until no candidate pair
// remains. The surviving runs are then mapped onto vocabulary entries, with
// any leftover bytes emitted as byte-fallback tokens.
std::vector<uint32_t> GgufTokenizer::encodeSpm(const std::string& text) const {
    std::vector<uint32_t> output;

    // llama.cpp prepends a space when the tokenizer is configured with
    // add_space_prefix (the default for SPM models), then escapes every space
    // into U+2581. The prefix is therefore escaped too.
    std::string escaped;
    escaped.reserve(text.size() * 3 + 8);
    if (m_addSpacePrefix) escaped += "\xe2\x96\x81";  // U+2581
    for (char c : text) {
        if (c == ' ') {
            escaped += "\xe2\x96\x81";  // U+2581
        } else {
            escaped.push_back(c);
        }
    }

    // Split into UTF-8 characters, chained through prev/next.
    std::vector<SpmSymbol> syms;
    {
        size_t offs = 0;
        int index = 0;
        while (offs < escaped.size()) {
            SpmSymbol sym;
            sym.off = offs;
            sym.n = std::min(utf8Len(static_cast<uint8_t>(escaped[offs])), escaped.size() - offs);
            offs += sym.n;
            sym.prev = index - 1;
            sym.next = (offs == escaped.size()) ? -1 : index + 1;
            ++index;
            syms.push_back(sym);
        }
    }
    if (syms.empty()) return output;

    std::priority_queue<SpmBigram, std::vector<SpmBigram>, SpmBigramGreater> queue;
    std::map<std::string, std::pair<int, int>> revMerge;

    auto tryAddBigram = [&](int left, int right) {
        if (left < 0 || right < 0) return;
        const SpmSymbol& ls = syms[left];
        const SpmSymbol& rs = syms[right];
        std::string piece = escaped.substr(ls.off, ls.n + rs.n);
        auto it = m_tokenToId.find(piece);
        if (it == m_tokenToId.end()) return;

        SpmBigram bigram;
        bigram.left = left;
        bigram.right = right;
        bigram.score = (it->second < m_scores.size()) ? m_scores[it->second] : 0.0f;
        bigram.size = piece.size();
        queue.push(bigram);
        revMerge[piece] = std::make_pair(left, right);
    };

    for (int i = 1; i < static_cast<int>(syms.size()); ++i) tryAddBigram(i - 1, i);

    while (!queue.empty()) {
        SpmBigram bigram = queue.top();
        queue.pop();

        SpmSymbol& ls = syms[bigram.left];
        SpmSymbol& rs = syms[bigram.right];

        // Skip candidates whose symbols have already been consumed.
        if (ls.n == 0 || rs.n == 0 || ls.n + rs.n != bigram.size) continue;

        ls.n += rs.n;
        rs.n = 0;

        ls.next = rs.next;
        if (rs.next >= 0) syms[rs.next].prev = bigram.left;

        tryAddBigram(ls.prev, bigram.left);
        tryAddBigram(bigram.left, ls.next);
    }

    // Map the surviving runs onto vocabulary entries.
    std::function<void(int)> resegment = [&](int i) {
        if (i < 0) return;
        const SpmSymbol& sym = syms[i];
        if (sym.n == 0) return;
        std::string piece = escaped.substr(sym.off, sym.n);

        auto it = m_tokenToId.find(piece);
        if (it != m_tokenToId.end()) {
            output.push_back(it->second);
            return;
        }

        auto rm = revMerge.find(piece);
        if (rm == revMerge.end()) {
            // Not a vocabulary entry: emit the raw bytes.
            for (size_t j = 0; j < sym.n; ++j) {
                output.push_back(byteToToken(static_cast<uint8_t>(piece[j])));
            }
            return;
        }

        resegment(rm->second.first);
        resegment(rm->second.second);
    };

    for (int i = 0; i != -1; i = syms[i].next) resegment(i);

    return output;
}

// Byte-level BPE tokenization.
//
// Mirrors llama.cpp's llm_tokenizer_bpe_session: the text is split into
// pre-tokenizer fragments, each fragment's bytes are mapped through the GPT-2
// byte-to-unicode table, and the resulting symbols are merged using the
// merge table's ranks (lowest rank first).
std::vector<uint32_t> GgufTokenizer::encodeBpe(const std::string& text) const {
    std::vector<uint32_t> output;
    if (text.empty()) return output;

    for (const std::string& fragment : pretokenize(text)) {
        if (fragment.empty()) continue;

        // Map the fragment's bytes through the GPT-2 byte-to-unicode table.
        std::string encoded;
        encoded.reserve(fragment.size() * 2);
        for (unsigned char c : fragment) {
            encoded += codepointToUtf8(byteToCodepoint(c));
        }

        // Split the encoded fragment into symbols.
        struct BpeSymbol {
            int prev = -1;
            int next = -1;
            uint32_t id = 0;
            size_t off = 0;
            size_t n = 0;
        };
        std::vector<BpeSymbol> syms;
        {
            size_t offs = 0;
            int index = 0;
            size_t byteIdx = 0;
            while (offs < encoded.size()) {
                size_t p = offs;
                uint32_t cp = nextCodepoint(encoded, p);
                BpeSymbol sym;
                sym.off = offs;
                sym.n = p - offs;
                sym.prev = index - 1;
                sym.next = (p == encoded.size()) ? -1 : index + 1;
                ++index;

                std::string piece = encoded.substr(sym.off, sym.n);
                auto it = m_tokenToId.find(piece);
                if (it == m_tokenToId.end()) {
                    // Byte not present in the vocabulary: fall back to the
                    // byte-fallback token for the original byte. Each symbol
                    // carries exactly one source byte, because every byte maps
                    // to exactly one byte-to-unicode codepoint.
                    sym.id = byteToToken(byteIdx < fragment.size()
                                             ? static_cast<uint8_t>(fragment[byteIdx])
                                             : static_cast<uint8_t>(0));
                } else {
                    sym.id = it->second;
                }
                ++byteIdx;
                syms.push_back(sym);
                offs = p;
            }
        }
        if (syms.empty()) continue;

        // Merge the lowest-rank adjacent pair until no rule applies. The
        // symbols form a doubly linked list so a merged run stays adjacent to
        // its neighbours; a plain array would leave gaps and stall the merge.
        int head = 0;
        while (true) {
            uint32_t bestRank = 0xFFFFFFFFu;
            int bestLeft = -1;
            int bestRight = -1;
            for (int i = head; i != -1; ) {
                const int j = syms[i].next;
                if (j == -1) break;
                const uint64_t key = (static_cast<uint64_t>(syms[i].id) << 32) | syms[j].id;
                auto mit = m_mergeRanks.find(key);
                if (mit != m_mergeRanks.end() && mit->second < bestRank) {
                    bestRank = mit->second;
                    bestLeft = i;
                    bestRight = j;
                }
                i = j;
            }
            if (bestLeft < 0) break;

            BpeSymbol& left = syms[bestLeft];
            BpeSymbol& right = syms[bestRight];
            left.n += right.n;

            // The merged run maps to a different vocabulary entry.
            auto merged = m_tokenToId.find(encoded.substr(left.off, left.n));
            if (merged != m_tokenToId.end()) left.id = merged->second;

            // Unlink `right` from the chain.
            left.next = right.next;
            if (right.next != -1) syms[right.next].prev = bestLeft;
            right.n = 0;
            right.prev = -1;
            right.next = -1;
        }

        for (int i = head; i != -1; i = syms[i].next) {
            if (syms[i].n == 0) continue;
            // The symbol id tracks the merged run. Like llama.cpp, a merge
            // whose result is not a vocabulary entry keeps the left token's
            // id rather than emitting an unknown token.
            output.push_back(syms[i].id);
        }
    }

    return output;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

const std::string& GgufTokenizer::piece(uint32_t id) const {
    static const std::string kEmpty;
    if (id >= m_vocab.size()) return kEmpty;
    return m_vocab[id];
}

bool GgufTokenizer::isControl(uint32_t id) const {
    if (id >= m_tokenTypes.size()) return false;
    // GGUF token types: 1 normal, 2 unknown, 3 control, 4 byte, 5 user-defined.
    return m_tokenTypes[id] == 3;
}

std::string GgufTokenizer::decode(uint32_t id) const {
    if (id >= m_vocab.size()) return std::string();

    // Control tokens are emitted verbatim.
    if (isControl(id)) return m_vocab[id];

    const std::string& tok = m_vocab[id];

    // Byte-fallback token: "<0x41>" -> 'A'.
    if (tok.size() == 6 && tok[0] == '<' && tok[1] == '0' && tok[2] == 'x' && tok[5] == '>') {
        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexVal(tok[3]);
        int lo = hexVal(tok[4]);
        if (hi >= 0 && lo >= 0) {
            return std::string(1, static_cast<char>((hi << 4) | lo));
        }
    }

    if (m_type == GgufTokenizerType::Spm) {
        // SentencePiece: U+2581 stands for a space.
        std::string out;
        out.reserve(tok.size());
        for (size_t i = 0; i < tok.size(); ++i) {
            if (i + 2 < tok.size() && static_cast<uint8_t>(tok[i]) == 0xE2 &&
                static_cast<uint8_t>(tok[i + 1]) == 0x96 && static_cast<uint8_t>(tok[i + 2]) == 0x81) {
                out.push_back(' ');
                i += 2;
            } else {
                out.push_back(tok[i]);
            }
        }
        return out;
    }

    // BPE: map the byte-unicode codepoints back to their original bytes.
    std::string out;
    size_t off = 0;
    while (off < tok.size()) {
        size_t p = off;
        uint32_t cp = nextCodepoint(tok, p);
        bool mapped = false;
        if (cp >= 0x100 && cp < 0x100 + sizeof(kRelocatedBytes)) {
            out.push_back(static_cast<char>(kRelocatedBytes[cp - 0x100]));
            mapped = true;
        } else if ((cp >= 0x21 && cp <= 0x7E) || (cp >= 0xA1 && cp <= 0xAC) ||
                   (cp >= 0xAE && cp <= 0xFF)) {
            out.push_back(static_cast<char>(cp));
            mapped = true;
        }
        if (!mapped) out += codepointToUtf8(cp);
        off = p;
    }
    return out;
}

std::string GgufTokenizer::decode(const std::vector<uint32_t>& ids) const {
    std::string out;
    for (uint32_t id : ids) out += decode(id);
    return out;
}

}  // namespace Deep2Rom::Inference
