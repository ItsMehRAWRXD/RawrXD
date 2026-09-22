// ============================================================================
// Tokenizer.cpp — Batch 7 no-dependency GGUF tokenizer
// ============================================================================
#include "Tokenizer.hpp"
#include "GGUFLoader.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <limits>
#include <sstream>

namespace Deep2 {

namespace {
constexpr int32_t TOK_NORMAL  = 1;
constexpr int32_t TOK_UNKNOWN = 2;
constexpr int32_t TOK_CONTROL = 3;
constexpr int32_t TOK_USER    = 4;
constexpr int32_t TOK_UNUSED  = 5;
constexpr int32_t TOK_BYTE    = 6;

enum class CharClass : uint8_t { Space, Letter, Digit, Other };

static CharClass classifyUtf8Lead(const std::string& s, size_t pos, size_t cpBytes) {
    const unsigned char c = static_cast<unsigned char>(s[pos]);
    if (cpBytes > 1) return CharClass::Letter; // Unicode word-like fallback.
    if (std::isspace(c)) return CharClass::Space;
    if (std::isalpha(c)) return CharClass::Letter;
    if (std::isdigit(c)) return CharClass::Digit;
    return CharClass::Other;
}

static bool asciiContractionAt(const std::string& s, size_t pos, size_t& len) {
    static const char* k[] = {"'s","'t","'re","'ve","'m","'ll","'d"};
    for (const char* p : k) {
        const size_t n = std::char_traits<char>::length(p);
        if (pos + n > s.size()) continue;
        bool same = true;
        for (size_t i = 0; i < n; ++i) {
            unsigned char a = static_cast<unsigned char>(s[pos+i]);
            unsigned char b = static_cast<unsigned char>(p[i]);
            if (std::tolower(a) != std::tolower(b)) { same = false; break; }
        }
        if (same) { len = n; return true; }
    }
    return false;
}
} // namespace

void BPETokenizer::clear() {
    tokenToId_.clear();
    idToToken_.clear();
    scores_.clear();
    tokenTypes_.clear();
    mergeRanks_.clear();
    unicodeToByte_.clear();
    for (auto& s : byteToUnicode_) s.clear();
    byteTokenIds_.fill(-1);
    trie_.clear();
    literalSpecials_.clear();

    kind_ = Kind::Unknown;
    modelName_.clear();
    ready_ = false;
    addBos_ = false;
    addEos_ = false;

    bosId_ = eosId_ = unkId_ = sepId_ = padId_ = -1;
}

std::string BPETokenizer::utf8FromCodepoint(uint32_t cp) {
    std::string out;
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
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

size_t BPETokenizer::utf8CodepointBytes(unsigned char lead) {
    if ((lead & 0x80) == 0x00) return 1;
    if ((lead & 0xE0) == 0xC0) return 2;
    if ((lead & 0xF0) == 0xE0) return 3;
    if ((lead & 0xF8) == 0xF0) return 4;
    return 1;
}

std::string BPETokenizer::pairKey(const std::string& a, const std::string& b) {
    std::string k;
    k.reserve(a.size() + b.size() + 24);
    k += std::to_string(a.size());
    k.push_back(':');
    k += a;
    k += b;
    return k;
}

bool BPETokenizer::parseByteToken(const std::string& token, uint8_t& value) {
    if (token.size() != 6 || token[0] != '<' || token[1] != '0' ||
        (token[2] != 'x' && token[2] != 'X') || token[5] != '>')
        return false;

    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    const int hi = hex(token[3]);
    const int lo = hex(token[4]);
    if (hi < 0 || lo < 0) return false;
    value = static_cast<uint8_t>((hi << 4) | lo);
    return true;
}

bool BPETokenizer::looksSpecial(const std::string& token) {
    if (token.size() >= 4 &&
        token.rfind("<|", 0) == 0 &&
        token.compare(token.size()-2, 2, "|>") == 0)
        return true;
    return token == "<s>" || token == "</s>" ||
           token == "<unk>" || token == "<pad>" ||
           token == "[CLS]" || token == "[SEP]" ||
           token == "[PAD]" || token == "[UNK]";
}

bool BPETokenizer::loadFromFile(const std::string& vocabPath) {
    clear();

    std::ifstream f(vocabPath);
    if (!f) return false;

    std::string line;
    int maxId = -1;
    std::vector<std::pair<int,std::string>> rows;

    while (std::getline(f, line)) {
        if (line.empty()) continue;
        const size_t sp = line.find(' ');
        if (sp == std::string::npos) continue;

        int id = -1;
        try { id = std::stoi(line.substr(0, sp)); }
        catch (...) { return false; }
        if (id < 0) return false;

        std::string tok = line.substr(sp + 1);
        if (tok.size() >= 2 && tok.front() == '"' && tok.back() == '"')
            tok = tok.substr(1, tok.size()-2);

        rows.emplace_back(id, std::move(tok));
        maxId = std::max(maxId, id);
    }

    if (maxId < 0) return false;
    idToToken_.resize(static_cast<size_t>(maxId)+1);
    scores_.assign(idToToken_.size(), 0.0f);
    tokenTypes_.assign(idToToken_.size(), TOK_NORMAL);

    for (const auto& r : rows) {
        if (r.first < 0 || static_cast<size_t>(r.first) >= idToToken_.size())
            return false;
        idToToken_[static_cast<size_t>(r.first)] = r.second;
        tokenToId_[r.second] = r.first;
    }

    modelName_ = "file";
    kind_ = Kind::RWKV; // raw longest-match is safest for unspecified sidecars.
    buildAuxiliaryIndexes();
    ready_ = !idToToken_.empty();
    return ready_;
}

bool BPETokenizer::loadFromGGUF(const void* ggufData, size_t len) {
    (void)ggufData;
    (void)len;
    // Parsing raw GGUF bytes here would duplicate GGUFLoader authority and lose
    // mapped lifetime guarantees. Kept only for source compatibility.
    return false;
}

bool BPETokenizer::loadFromGGUF(const GGUFLoader& loader) {
    clear();

    if (!loader.loaded()) return false;
    if (!loader.getMetaStringArray("tokenizer.ggml.tokens", idToToken_) ||
        idToToken_.empty())
        return false;

    modelName_ = loader.getMetaString("tokenizer.ggml.model");
    std::string modelLower = modelName_;
    std::transform(modelLower.begin(), modelLower.end(), modelLower.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

    if (modelLower == "gpt2") {
        kind_ = Kind::GPT2BPE;
    } else if (modelLower == "llama" || modelLower == "replit") {
        kind_ = Kind::SentencePiece;
    } else if (modelLower == "rwkv") {
        kind_ = Kind::RWKV;
    } else {
        // A merge table is unambiguous evidence for the GGML GPT-2 BPE format.
        std::vector<std::string> probe;
        if (loader.getMetaStringArray("tokenizer.ggml.merges", probe) &&
            !probe.empty()) {
            kind_ = Kind::GPT2BPE;
        } else {
            return false; // Unknown tokenizer algorithm: fail closed.
        }
    }

    tokenToId_.reserve(idToToken_.size() * 2);
    for (size_t i = 0; i < idToToken_.size(); ++i) {
        if (tokenToId_.find(idToToken_[i]) == tokenToId_.end())
            tokenToId_.emplace(idToToken_[i], static_cast<int>(i));
    }

    if (!loader.getMetaFloatArray("tokenizer.ggml.scores", scores_))
        scores_.assign(idToToken_.size(), 0.0f);
    if (scores_.size() != idToToken_.size()) return false;

    if (!loader.getMetaInt32Array("tokenizer.ggml.token_type", tokenTypes_))
        tokenTypes_.assign(idToToken_.size(), TOK_NORMAL);
    if (tokenTypes_.size() != idToToken_.size()) return false;

    bosId_ = static_cast<int>(loader.getMetaInt("tokenizer.ggml.bos_token_id", -1));
    eosId_ = static_cast<int>(loader.getMetaInt("tokenizer.ggml.eos_token_id", -1));
    unkId_ = static_cast<int>(loader.getMetaInt("tokenizer.ggml.unknown_token_id", -1));
    sepId_ = static_cast<int>(loader.getMetaInt("tokenizer.ggml.separator_token_id", -1));
    padId_ = static_cast<int>(loader.getMetaInt("tokenizer.ggml.padding_token_id", -1));

    auto detectId = [&](int& id, const std::initializer_list<const char*>& names) {
        if (id >= 0) return;
        for (const char* n : names) {
            auto it = tokenToId_.find(n);
            if (it != tokenToId_.end()) { id = it->second; return; }
        }
    };
    detectId(bosId_, {"<s>", "<|begin_of_text|>"});
    detectId(eosId_, {"</s>", "<|end_of_text|>", "<|eot_id|>"});
    detectId(unkId_, {"<unk>", "[UNK]"});
    detectId(padId_, {"<pad>", "[PAD]"});

    const bool defaultBos = (kind_ == Kind::SentencePiece);
    addBos_ = loader.hasMeta("tokenizer.ggml.add_bos_token")
        ? loader.getMetaInt("tokenizer.ggml.add_bos_token", 0) != 0
        : defaultBos;
    addEos_ = loader.hasMeta("tokenizer.ggml.add_eos_token")
        ? loader.getMetaInt("tokenizer.ggml.add_eos_token", 0) != 0
        : false;

    if (addBos_ && (bosId_ < 0 || static_cast<size_t>(bosId_) >= idToToken_.size()))
        return false;
    if (addEos_ && (eosId_ < 0 || static_cast<size_t>(eosId_) >= idToToken_.size()))
        return false;

    std::vector<std::string> merges;
    if (loader.getMetaStringArray("tokenizer.ggml.merges", merges)) {
        for (size_t rank = 0; rank < merges.size(); ++rank) {
            const std::string& m = merges[rank];
            const size_t sp = m.find(' ');
            if (sp == std::string::npos || sp == 0 || sp + 1 >= m.size())
                return false;
            const std::string a = m.substr(0, sp);
            const std::string b = m.substr(sp + 1);
            mergeRanks_.emplace(pairKey(a,b), rank);
        }
    }

    if (kind_ == Kind::GPT2BPE && mergeRanks_.empty()) {
        // Atomic GPT2 vocab is legal, but ordinary GPT2 models should carry
        // merges. Do not reject an intentionally merge-free model.
    }

    buildAuxiliaryIndexes();
    ready_ = true;
    return true;
}

void BPETokenizer::buildAuxiliaryIndexes() {
    byteTokenIds_.fill(-1);
    literalSpecials_.clear();
    trie_.clear();
    trie_.push_back(TrieNode{});

    for (size_t i = 0; i < idToToken_.size(); ++i) {
        const int id = static_cast<int>(i);
        const int32_t type =
            i < tokenTypes_.size() ? tokenTypes_[i] : TOK_NORMAL;

        uint8_t byte = 0;
        if (type == TOK_BYTE || parseByteToken(idToToken_[i], byte)) {
            if (parseByteToken(idToToken_[i], byte))
                byteTokenIds_[byte] = id;
        }

        if (type == TOK_CONTROL || type == TOK_USER ||
            looksSpecial(idToToken_[i])) {
            literalSpecials_.emplace_back(idToToken_[i], id);
        }

        if (tokenUsableInTrie(id))
            trieInsert(idToToken_[i], id);
    }

    std::sort(literalSpecials_.begin(), literalSpecials_.end(),
              [](const auto& a, const auto& b) {
                  if (a.first.size() != b.first.size())
                      return a.first.size() > b.first.size();
                  return a.first < b.first;
              });

    // GPT-2 reversible bytes_to_unicode mapping.
    std::vector<uint32_t> bs;
    for (uint32_t i = 33; i <= 126; ++i) bs.push_back(i);
    for (uint32_t i = 161; i <= 172; ++i) bs.push_back(i);
    for (uint32_t i = 174; i <= 255; ++i) bs.push_back(i);

    std::array<bool,256> present{};
    for (uint32_t b : bs) present[b] = true;

    uint32_t n = 0;
    for (uint32_t b = 0; b < 256; ++b) {
        uint32_t cp = b;
        if (!present[b]) cp = 256 + n++;
        byteToUnicode_[b] = utf8FromCodepoint(cp);
        unicodeToByte_[byteToUnicode_[b]] = static_cast<uint8_t>(b);
    }
}

bool BPETokenizer::tokenUsableInTrie(int id) const {
    if (id < 0 || static_cast<size_t>(id) >= idToToken_.size()) return false;
    const int32_t type =
        static_cast<size_t>(id) < tokenTypes_.size()
        ? tokenTypes_[static_cast<size_t>(id)] : TOK_NORMAL;
    return type != TOK_CONTROL && type != TOK_UNUSED &&
           type != TOK_UNKNOWN && type != TOK_BYTE &&
           !idToToken_[static_cast<size_t>(id)].empty();
}

void BPETokenizer::trieInsert(const std::string& token, int id) {
    size_t node = 0;
    for (unsigned char c : token) {
        auto it = trie_[node].next.find(c);
        if (it == trie_[node].next.end()) {
            const size_t next = trie_.size();
            trie_[node].next.emplace(c, next);
            trie_.push_back(TrieNode{});
            node = next;
        } else {
            node = it->second;
        }
    }

    if (trie_[node].tokenId < 0) {
        trie_[node].tokenId = id;
    } else {
        const int old = trie_[node].tokenId;
        const float oldScore =
            static_cast<size_t>(old) < scores_.size() ? scores_[old] : 0.0f;
        const float newScore =
            static_cast<size_t>(id) < scores_.size() ? scores_[id] : 0.0f;
        if (newScore > oldScore) trie_[node].tokenId = id;
    }
}

std::vector<std::pair<size_t,int>>
BPETokenizer::trieMatches(const std::string& text, size_t pos) const {
    std::vector<std::pair<size_t,int>> out;
    if (trie_.empty() || pos >= text.size()) return out;

    size_t node = 0;
    for (size_t i = pos; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        auto it = trie_[node].next.find(c);
        if (it == trie_[node].next.end()) break;
        node = it->second;
        if (trie_[node].tokenId >= 0)
            out.emplace_back(i + 1, trie_[node].tokenId);
    }
    return out;
}

std::vector<std::string>
BPETokenizer::splitGPT2Pretokens(const std::string& text) const {
    std::vector<std::string> out;
    size_t i = 0;

    while (i < text.size()) {
        size_t contraction = 0;
        if (asciiContractionAt(text, i, contraction)) {
            out.push_back(text.substr(i, contraction));
            i += contraction;
            continue;
        }

        const size_t firstBytes =
            std::min(utf8CodepointBytes(static_cast<unsigned char>(text[i])),
                     text.size() - i);
        CharClass cls = classifyUtf8Lead(text, i, firstBytes);

        if (cls == CharClass::Space) {
            size_t j = i;
            while (j < text.size()) {
                const size_t n =
                    std::min(utf8CodepointBytes(static_cast<unsigned char>(text[j])),
                             text.size() - j);
                if (classifyUtf8Lead(text,j,n) != CharClass::Space) break;
                j += n;
            }

            // GPT-2 regex allows one leading ASCII space on the following
            // letter/number/punctuation run.
            if (j == i + 1 && text[i] == ' ' && j < text.size()) {
                const size_t n =
                    std::min(utf8CodepointBytes(static_cast<unsigned char>(text[j])),
                             text.size() - j);
                const CharClass nextClass = classifyUtf8Lead(text,j,n);
                if (nextClass != CharClass::Space) {
                    size_t k = j;
                    while (k < text.size()) {
                        size_t cc =
                            std::min(utf8CodepointBytes(
                                         static_cast<unsigned char>(text[k])),
                                     text.size() - k);
                        if (classifyUtf8Lead(text,k,cc) != nextClass) break;
                        k += cc;
                    }
                    out.push_back(text.substr(i, k-i));
                    i = k;
                    continue;
                }
            }

            out.push_back(text.substr(i, j-i));
            i = j;
            continue;
        }

        size_t j = i;
        while (j < text.size()) {
            size_t cc =
                std::min(utf8CodepointBytes(static_cast<unsigned char>(text[j])),
                         text.size() - j);
            if (classifyUtf8Lead(text,j,cc) != cls) break;

            size_t cLen = 0;
            if (j != i && asciiContractionAt(text,j,cLen)) break;
            j += cc;
        }
        out.push_back(text.substr(i, j-i));
        i = j;
    }

    return out;
}

std::string BPETokenizer::byteEncodeString(const std::string& raw) const {
    std::string out;
    for (unsigned char c : raw)
        out += byteToUnicode_[c];
    return out;
}

std::string BPETokenizer::byteDecodeString(const std::string& encoded) const {
    std::string out;
    size_t i = 0;
    while (i < encoded.size()) {
        const size_t n =
            std::min(utf8CodepointBytes(static_cast<unsigned char>(encoded[i])),
                     encoded.size() - i);
        const std::string cp = encoded.substr(i,n);
        auto it = unicodeToByte_.find(cp);
        if (it != unicodeToByte_.end()) {
            out.push_back(static_cast<char>(it->second));
        } else {
            out += cp;
        }
        i += n;
    }
    return out;
}

std::vector<std::string> BPETokenizer::bpeMerge(const std::string& raw) const {
    const std::string encoded = byteEncodeString(raw);
    std::vector<std::string> symbols;

    for (size_t i = 0; i < encoded.size();) {
        const size_t n =
            std::min(utf8CodepointBytes(static_cast<unsigned char>(encoded[i])),
                     encoded.size() - i);
        symbols.push_back(encoded.substr(i,n));
        i += n;
    }

    if (symbols.size() < 2 || mergeRanks_.empty())
        return symbols;

    for (;;) {
        size_t bestRank = std::numeric_limits<size_t>::max();
        std::string bestA, bestB;
        bool found = false;

        for (size_t i = 0; i + 1 < symbols.size(); ++i) {
            auto it = mergeRanks_.find(pairKey(symbols[i], symbols[i+1]));
            if (it != mergeRanks_.end() && it->second < bestRank) {
                bestRank = it->second;
                bestA = symbols[i];
                bestB = symbols[i+1];
                found = true;
            }
        }
        if (!found) break;

        std::vector<std::string> next;
        next.reserve(symbols.size());
        for (size_t i = 0; i < symbols.size();) {
            if (i + 1 < symbols.size() &&
                symbols[i] == bestA && symbols[i+1] == bestB) {
                next.push_back(symbols[i] + symbols[i+1]);
                i += 2;
            } else {
                next.push_back(symbols[i]);
                ++i;
            }
        }
        symbols.swap(next);
    }
    return symbols;
}

std::vector<int> BPETokenizer::encodeGPT2(const std::string& text) {
    std::vector<int> ids;
    for (const std::string& chunk : splitGPT2Pretokens(text)) {
        for (const std::string& sym : bpeMerge(chunk)) {
            auto it = tokenToId_.find(sym);
            if (it == tokenToId_.end()) {
                if (unkId_ >= 0) {
                    ids.push_back(unkId_);
                } else {
                    return {};
                }
            } else {
                ids.push_back(it->second);
            }
        }
    }
    return ids;
}

std::vector<int>
BPETokenizer::encodeSentencePiece(const std::string& text,
                                  bool addDummyPrefix) {
    std::string normalized;
    normalized.reserve(text.size() + 8);

    bool lastWasSpace = false;
    for (unsigned char c : text) {
        const bool ws = c == ' ' || c == '\t' || c == '\r' || c == '\n';
        if (ws) {
            if (!lastWasSpace) normalized.push_back(' ');
            lastWasSpace = true;
        } else {
            normalized.push_back(static_cast<char>(c));
            lastWasSpace = false;
        }
    }

    if (addDummyPrefix && !normalized.empty() && normalized.front() != ' ')
        normalized.insert(normalized.begin(), ' ');

    static const std::string kSP = "\xE2\x96\x81"; // U+2581
    std::string transformed;
    transformed.reserve(normalized.size() + 8);
    for (char c : normalized) {
        if (c == ' ') transformed += kSP;
        else transformed.push_back(c);
    }

    if (transformed.empty()) return {};

    std::vector<DPCell> dp(transformed.size() + 1);
    dp[0].score = 0.0f;
    dp[0].reachable = true;

    for (size_t pos = 0; pos < transformed.size(); ++pos) {
        if (!dp[pos].reachable) continue;

        bool hadMatch = false;
        const auto matches = trieMatches(transformed, pos);
        for (const auto& m : matches) {
            const size_t end = m.first;
            const int id = m.second;
            if (end <= pos || end > transformed.size()) continue;

            const float pieceScore =
                static_cast<size_t>(id) < scores_.size() ? scores_[id] : 0.0f;
            const float candidate = dp[pos].score + pieceScore;
            const size_t candidateLen = end - pos;
            const size_t oldLen =
                dp[end].reachable ? end - dp[end].prev : 0;

            if (!dp[end].reachable ||
                candidate > dp[end].score ||
                (candidate == dp[end].score && candidateLen > oldLen)) {
                dp[end].reachable = true;
                dp[end].score = candidate;
                dp[end].prev = pos;
                dp[end].tokenId = id;
            }
            hadMatch = true;
        }

        // Byte fallback is always a legal lower-priority edge when present.
        const uint8_t b = static_cast<uint8_t>(transformed[pos]);
        const int byteId = byteTokenIds_[b];
        if (byteId >= 0) {
            const size_t end = pos + 1;
            const float candidate = dp[pos].score - 100.0f;
            if (!dp[end].reachable || candidate > dp[end].score) {
                dp[end].reachable = true;
                dp[end].score = candidate;
                dp[end].prev = pos;
                dp[end].tokenId = byteId;
            }
        } else if (!hadMatch && unkId_ >= 0) {
            const size_t end = pos + 1;
            const float candidate = dp[pos].score - 1000.0f;
            if (!dp[end].reachable || candidate > dp[end].score) {
                dp[end].reachable = true;
                dp[end].score = candidate;
                dp[end].prev = pos;
                dp[end].tokenId = unkId_;
            }
        }
    }

    if (!dp[transformed.size()].reachable) return {};

    std::vector<int> rev;
    for (size_t p = transformed.size(); p > 0;) {
        const DPCell& c = dp[p];
        if (!c.reachable || c.tokenId < 0 || c.prev >= p) return {};
        rev.push_back(c.tokenId);
        p = c.prev;
    }
    return std::vector<int>(rev.rbegin(), rev.rend());
}

std::vector<int> BPETokenizer::encodeRWKV(const std::string& text) {
    std::vector<int> ids;
    size_t pos = 0;

    while (pos < text.size()) {
        const auto matches = trieMatches(text,pos);
        if (!matches.empty()) {
            auto best = std::max_element(matches.begin(), matches.end(),
                [](const auto& a, const auto& b) {
                    return a.first < b.first;
                });
            ids.push_back(best->second);
            pos = best->first;
            continue;
        }

        const uint8_t b = static_cast<uint8_t>(text[pos]);
        if (byteTokenIds_[b] >= 0) {
            ids.push_back(byteTokenIds_[b]);
            ++pos;
        } else if (unkId_ >= 0) {
            ids.push_back(unkId_);
            ++pos;
        } else {
            return {};
        }
    }
    return ids;
}

std::vector<int> BPETokenizer::encodeOrdinary(const std::string& text) {
    switch (kind_) {
        case Kind::GPT2BPE:       return encodeGPT2(text);
        case Kind::SentencePiece: return encodeSentencePiece(text, true);
        case Kind::RWKV:          return encodeRWKV(text);
        default:                  return {};
    }
}

std::vector<int> BPETokenizer::encode(const std::string& text) {
    if (!ready_) return {};

    std::vector<int> result;
    if (addBos_) result.push_back(bosId_);

    // Preserve user/control tokens literally and never feed them through BPE/SP.
    size_t cursor = 0;
    while (cursor < text.size()) {
        size_t bestPos = std::string::npos;
        size_t bestLen = 0;
        int bestId = -1;

        for (const auto& sp : literalSpecials_) {
            if (sp.first.empty()) continue;
            const size_t p = text.find(sp.first, cursor);
            if (p == std::string::npos) continue;
            if (bestPos == std::string::npos || p < bestPos ||
                (p == bestPos && sp.first.size() > bestLen)) {
                bestPos = p;
                bestLen = sp.first.size();
                bestId = sp.second;
            }
        }

        const size_t ordinaryEnd =
            bestPos == std::string::npos ? text.size() : bestPos;
        if (ordinaryEnd > cursor) {
            std::vector<int> part =
                encodeOrdinary(text.substr(cursor, ordinaryEnd-cursor));
            if (part.empty() && ordinaryEnd > cursor) return {};
            result.insert(result.end(), part.begin(), part.end());
        }

        if (bestPos == std::string::npos) {
            cursor = text.size();
        } else {
            result.push_back(bestId);
            cursor = bestPos + bestLen;
        }
    }

    if (text.empty() && !addBos_ && !addEos_) return {};
    if (addEos_) result.push_back(eosId_);
    return result;
}

bool BPETokenizer::isSpecial(int token) const {
    if (token < 0 || static_cast<size_t>(token) >= idToToken_.size())
        return false;
    if (token == bosId_ || token == eosId_ ||
        token == padId_ || token == sepId_)
        return true;
    const int32_t type =
        static_cast<size_t>(token) < tokenTypes_.size()
        ? tokenTypes_[static_cast<size_t>(token)] : TOK_NORMAL;
    return type == TOK_CONTROL;
}

std::string
BPETokenizer::decodeSentencePieceToken(const std::string& token) const {
    uint8_t b = 0;
    if (parseByteToken(token,b))
        return std::string(1, static_cast<char>(b));

    static const std::string kSP = "\xE2\x96\x81";
    std::string out;
    for (size_t i = 0; i < token.size();) {
        if (i + kSP.size() <= token.size() &&
            token.compare(i,kSP.size(),kSP) == 0) {
            out.push_back(' ');
            i += kSP.size();
        } else {
            out.push_back(token[i++]);
        }
    }
    return out;
}

std::string BPETokenizer::decodeTokenRaw(int token) const {
    if (token < 0 || static_cast<size_t>(token) >= idToToken_.size())
        return {};
    if (token == bosId_ || token == eosId_ || token == padId_)
        return {};

    const int32_t type =
        static_cast<size_t>(token) < tokenTypes_.size()
        ? tokenTypes_[static_cast<size_t>(token)] : TOK_NORMAL;
    if (type == TOK_CONTROL) return {};

    const std::string& piece = idToToken_[static_cast<size_t>(token)];
    switch (kind_) {
        case Kind::GPT2BPE:       return byteDecodeString(piece);
        case Kind::SentencePiece: return decodeSentencePieceToken(piece);
        case Kind::RWKV: {
            uint8_t b = 0;
            if (parseByteToken(piece,b))
                return std::string(1, static_cast<char>(b));
            return piece;
        }
        default: return {};
    }
}

std::string BPETokenizer::decode(const std::vector<int>& tokens) {
    if (!ready_) return {};
    std::string out;
    for (int token : tokens) out += decodeTokenRaw(token);

    if (kind_ == Kind::SentencePiece &&
        !out.empty() && out.front() == ' ')
        out.erase(out.begin()); // remove the tokenizer dummy-prefix space
    return out;
}

std::string BPETokenizer::decode(int token) {
    if (!ready_) return {};
    return decodeTokenRaw(token);
}

} // namespace Deep2
