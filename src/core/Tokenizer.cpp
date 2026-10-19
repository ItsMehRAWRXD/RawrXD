#include "Tokenizer.hpp"
#include "../GGUFLoader.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <cstdio>

namespace Deep2Rom::Inference {

    static inline uint64_t makeMergeKey(uint32_t a, uint32_t b) {
        return (static_cast<uint64_t>(a) << 32) | static_cast<uint64_t>(b);
    }

    void Tokenizer::initByteEncoder() {
        int n = 0;
        for (int b = 0; b < 256; ++b) {
            char32_t ch;
            if (b >= 33 && b <= 126) {
                ch = static_cast<char32_t>(b);
            } else if (b >= 161 && b <= 172) {
                ch = static_cast<char32_t>(b);
            } else if (b >= 174 && b <= 255) {
                ch = static_cast<char32_t>(b);
            } else {
                ch = 256 + n;
                ++n;
            }
            m_byteEncoder[static_cast<uint8_t>(b)] = ch;
            m_byteDecoder[ch] = static_cast<uint8_t>(b);
        }
    }

    std::string Tokenizer::byteToUnicode(uint8_t byte) const {
        auto it = m_byteEncoder.find(byte);
        if (it != m_byteEncoder.end()) {
            char32_t ch = it->second;
            std::string result;
            if (ch < 0x80) {
                result.push_back(static_cast<char>(ch));
            } else if (ch < 0x800) {
                result.push_back(static_cast<char>(0xC0 | (ch >> 6)));
                result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
            } else if (ch < 0x10000) {
                result.push_back(static_cast<char>(0xE0 | (ch >> 12)));
                result.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
            } else {
                result.push_back(static_cast<char>(0xF0 | (ch >> 18)));
                result.push_back(static_cast<char>(0x80 | ((ch >> 12) & 0x3F)));
                result.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
            }
            return result;
        }
        return std::string(1, static_cast<char>(byte));
    }

    uint8_t Tokenizer::unicodeToByte(char32_t ch) const {
        auto it = m_byteDecoder.find(ch);
        if (it != m_byteDecoder.end()) return it->second;
        return 0;
    }

    bool Tokenizer::loadFromGGUF(const std::string& ggufPath) {
        std::ifstream f(ggufPath, std::ios::binary);
        if (!f.is_open()) {
            std::cerr << "[Tokenizer] Cannot open GGUF: " << ggufPath << std::endl;
            return false;
        }

        uint32_t magic = 0, version = 0;
        f.read(reinterpret_cast<char*>(&magic), 4);
        f.read(reinterpret_cast<char*>(&version), 4);
        if (magic != 0x46554747) {
            std::cerr << "[Tokenizer] Invalid GGUF magic" << std::endl;
            return false;
        }

        uint64_t tensorCount = 0, kvCount = 0;
        f.read(reinterpret_cast<char*>(&tensorCount), 8);
        f.read(reinterpret_cast<char*>(&kvCount), 8);

        std::vector<std::string> tokens;
        std::vector<float> scores;
        std::vector<uint32_t> tokenTypes;
        std::vector<std::pair<std::string, std::string>> merges;

        uint64_t tokensPos = 0, scoresPos = 0, typesPos = 0, mergesPos = 0;
        bool foundTokens = false, foundScores = false, foundTypes = false, foundMerges = false;
        uint32_t tokensType = 0, scoresType = 0, typesType = 0, mergesType = 0;

        for (uint64_t i = 0; i < kvCount; ++i) {
            std::string key = ReadGGUFStr(f);
            uint32_t type = 0;
            f.read(reinterpret_cast<char*>(&type), sizeof(type));

            if (key == "tokenizer.ggml.tokens") {
                tokensPos = static_cast<uint64_t>(f.tellg());
                tokensType = type;
                foundTokens = true;
                SkipGGUFValue(type, f);
            } else if (key == "tokenizer.ggml.scores") {
                scoresPos = static_cast<uint64_t>(f.tellg());
                scoresType = type;
                foundScores = true;
                SkipGGUFValue(type, f);
            } else if (key == "tokenizer.ggml.token_type") {
                typesPos = static_cast<uint64_t>(f.tellg());
                typesType = type;
                foundTypes = true;
                SkipGGUFValue(type, f);
            } else if (key == "tokenizer.ggml.merges") {
                mergesPos = static_cast<uint64_t>(f.tellg());
                mergesType = type;
                foundMerges = true;
                SkipGGUFValue(type, f);
            } else if (key == "tokenizer.ggml.bos_token_id") {
                uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4);
                m_config.bosTokenId = v;
            } else if (key == "tokenizer.ggml.eos_token_id") {
                uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4);
                m_config.eosTokenId = v;
            } else if (key == "tokenizer.ggml.unk_token_id") {
                uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4);
                m_config.unkTokenId = v;
            } else if (key == "tokenizer.ggml.padding_token_id") {
                uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4);
                m_config.padTokenId = v;
            } else {
                SkipGGUFValue(type, f);
            }
        }

        if (!foundTokens || !foundScores || !foundTypes) {
            std::cerr << "[Tokenizer] Missing required tokenizer metadata" << std::endl;
            return false;
        }

        // Re-read tokens
        f.clear();
        f.seekg(static_cast<std::streampos>(tokensPos), std::ios::beg);
        if (tokensType == 9) {
            uint32_t at = 0; uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            m_config.vocabSize = static_cast<uint32_t>(al);
            tokens.reserve(al);
            for (uint64_t j = 0; j < al; ++j) {
                tokens.push_back(ReadGGUFStr(f));
            }
        } else {
            std::cerr << "[Tokenizer] Unexpected tokens array type: " << tokensType << std::endl;
            return false;
        }

        // Re-read scores
        f.clear();
        f.seekg(static_cast<std::streampos>(scoresPos), std::ios::beg);
        if (scoresType == 9) {
            uint32_t at = 0; uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            scores.reserve(al);
            for (uint64_t j = 0; j < al; ++j) {
                float s = 0.0f;
                f.read(reinterpret_cast<char*>(&s), 4);
                scores.push_back(s);
            }
        } else {
            std::cerr << "[Tokenizer] Unexpected scores array type: " << scoresType << std::endl;
            return false;
        }

        // Re-read token types
        f.clear();
        f.seekg(static_cast<std::streampos>(typesPos), std::ios::beg);
        if (typesType == 9) {
            uint32_t at = 0; uint64_t al = 0;
            f.read(reinterpret_cast<char*>(&at), 4);
            f.read(reinterpret_cast<char*>(&al), 8);
            tokenTypes.reserve(al);
            for (uint64_t j = 0; j < al; ++j) {
                uint32_t t = 0;
                f.read(reinterpret_cast<char*>(&t), 4);
                tokenTypes.push_back(t);
            }
        } else {
            std::cerr << "[Tokenizer] Unexpected token_type array type: " << typesType << std::endl;
            return false;
        }

        // Re-read merges
        if (foundMerges) {
            f.clear();
            f.seekg(static_cast<std::streampos>(mergesPos), std::ios::beg);
            if (mergesType == 9) {
                uint32_t at = 0; uint64_t al = 0;
                f.read(reinterpret_cast<char*>(&at), 4);
                f.read(reinterpret_cast<char*>(&al), 8);
                merges.reserve(al);
                for (uint64_t j = 0; j < al; ++j) {
                    std::string left = ReadGGUFStr(f);
                    std::string right = ReadGGUFStr(f);
                    merges.emplace_back(left, right);
                }
            } else {
                std::cerr << "[Tokenizer] Unexpected merges array type: " << mergesType << std::endl;
                return false;
            }
        }

        // Build vocab maps
        m_vocab.clear();
        m_reverseVocab.clear();
        m_merges.clear();
        m_tokenTypes.clear();

        for (uint32_t i = 0; i < static_cast<uint32_t>(tokens.size()); ++i) {
            m_vocab[tokens[i]] = i;
            m_reverseVocab[i] = tokens[i];

            // Detect the vocabulary flavour. SentencePiece models mark word
            // boundaries with U+2581; byte-level BPE models use the GPT-2
            // byte-to-unicode mapping (a leading space becomes U+0120).
            if (tokens[i].find("\xE2\x96\x81") != std::string::npos) {
                m_sentencePiece = true;
            } else if (tokens[i].find("\xC4\xA0") != std::string::npos) {
                m_byteLevelBpe = true;
            }

            TokenType tt = TokenType::Normal;
            if (i < tokenTypes.size()) {
                switch (tokenTypes[i]) {
                    case 1: tt = TokenType::Normal; break;
                    case 2: tt = TokenType::Unknown; break;
                    case 3: tt = TokenType::Control; break;
                    case 4: tt = TokenType::Byte; break;
                    case 5: tt = TokenType::UserDefined; break;
                    default: tt = TokenType::Normal; break;
                }
            }
            m_tokenTypes[i] = tt;
        }

        // Build merge rules: (left_piece, right_piece) -> score
        // Merges are ordered by score (lowest score = highest priority)
        for (size_t mergeIdx = 0; mergeIdx < merges.size(); ++mergeIdx) {
            const auto& [left, right] = merges[mergeIdx];
            auto lit = m_vocab.find(left);
            auto rit = m_vocab.find(right);
            if (lit == m_vocab.end() || rit == m_vocab.end()) continue;

            uint64_t key = makeMergeKey(lit->second, rit->second);
            float score = -static_cast<float>(mergeIdx);
            auto mit = m_merges.find(key);
            if (mit == m_merges.end() || score < mit->second) {
                m_merges[key] = score;
            }
        }

        initByteEncoder();
        m_ready = true;

        std::cout << "[Tokenizer] Loaded " << tokens.size() << " tokens, "
                  << m_merges.size() << " merges, vocabSize=" << m_config.vocabSize << std::endl;
        return true;
    }

    bool Tokenizer::loadFromROM(const std::string& romPath) {
        std::cerr << "[Tokenizer] loadFromROM not supported; use loadFromGGUF instead" << std::endl;
        return false;
    }

    std::vector<uint32_t> Tokenizer::encode(const std::string& text, bool addBos, bool addEos) const {
        if (!m_ready) {
            std::cerr << "[Tokenizer] Not ready" << std::endl;
            return {};
        }

        std::vector<uint32_t> result;
        if (addBos) result.push_back(m_config.bosTokenId);

        // Convert text to UTF-32
        std::vector<char32_t> utf32;
        for (size_t i = 0; i < text.size(); ) {
            unsigned char c = static_cast<unsigned char>(text[i]);
            char32_t ch = 0;
            if (c < 0x80) {
                ch = c;
                i += 1;
            } else if ((c & 0xE0) == 0xC0) {
                ch = ((c & 0x1F) << 6) | (static_cast<unsigned char>(text[i+1]) & 0x3F);
                i += 2;
            } else if ((c & 0xF0) == 0xE0) {
                ch = ((c & 0x0F) << 12) | ((static_cast<unsigned char>(text[i+1]) & 0x3F) << 6)
                     | (static_cast<unsigned char>(text[i+2]) & 0x3F);
                i += 3;
            } else if ((c & 0xF8) == 0xF0) {
                ch = ((c & 0x07) << 18) | ((static_cast<unsigned char>(text[i+1]) & 0x3F) << 12)
                     | ((static_cast<unsigned char>(text[i+2]) & 0x3F) << 6)
                     | (static_cast<unsigned char>(text[i+3]) & 0x3F);
                i += 4;
            } else {
                ch = c;
                i += 1;
            }
            utf32.push_back(ch);
        }

        // Convert to byte-units
        std::vector<std::string> pieces;
        for (char32_t ch : utf32) {
            auto dit = m_byteDecoder.find(ch);
            if (dit != m_byteDecoder.end()) {
                pieces.push_back(byteToUnicode(static_cast<uint8_t>(dit->second)));
            } else {
                std::string utf8Bytes;
                if (ch < 0x80) {
                    utf8Bytes.push_back(static_cast<char>(ch));
                } else if (ch < 0x800) {
                    utf8Bytes.push_back(static_cast<char>(0xC0 | (ch >> 6)));
                    utf8Bytes.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
                } else if (ch < 0x10000) {
                    utf8Bytes.push_back(static_cast<char>(0xE0 | (ch >> 12)));
                    utf8Bytes.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                    utf8Bytes.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
                } else {
                    utf8Bytes.push_back(static_cast<char>(0xF0 | (ch >> 18)));
                    utf8Bytes.push_back(static_cast<char>(0x80 | ((ch >> 12) & 0x3F)));
                    utf8Bytes.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                    utf8Bytes.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
                }
                for (unsigned char b : utf8Bytes) {
                    pieces.push_back(byteToUnicode(b));
                }
            }
        }

        // Apply BPE merges
        applyBPE(pieces);

        // Convert pieces to token IDs
        for (const auto& piece : pieces) {
            auto it = m_vocab.find(piece);
            if (it != m_vocab.end()) {
                result.push_back(it->second);
            } else {
                result.push_back(m_config.unkTokenId);
            }
        }

        if (addEos) result.push_back(m_config.eosTokenId);
        return result;
    }

    std::string Tokenizer::decode(const std::vector<uint32_t>& tokens, bool skipSpecial) const {
        if (!m_ready) return "";

        std::string result;
        for (uint32_t id : tokens) {
            if (skipSpecial &&
                (id == m_config.bosTokenId || id == m_config.eosTokenId ||
                 id == m_config.unkTokenId || id == m_config.padTokenId)) {
                continue;
            }
            auto it = m_reverseVocab.find(id);
            if (it != m_reverseVocab.end()) {
                result += decodePiece(it->second);
            } else {
                result += "\xEF\xBF\xBD";  // U+FFFD replacement character
            }
        }
        return result;
    }

    // Turn a vocabulary entry back into the text it represents.
    //
    // SentencePiece entries use U+2581 for a space; byte-level BPE entries
    // use the GPT-2 byte-to-unicode mapping, where each codepoint stands for
    // one original byte. Both have to be undone, otherwise chat output shows
    // "▁word" and "Ġword" instead of " word".
    std::string Tokenizer::decodePiece(const std::string& piece) const {
        // Byte-fallback token: "<0x41>" -> 'A'.
        if (piece.size() == 6 && piece[0] == '<' && piece[1] == '0' && piece[2] == 'x' &&
            piece[5] == '>') {
            auto hexVal = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hexVal(piece[3]);
            const int lo = hexVal(piece[4]);
            if (hi >= 0 && lo >= 0) {
                return std::string(1, static_cast<char>((hi << 4) | lo));
            }
        }

        std::string out;
        out.reserve(piece.size());

        size_t i = 0;
        while (i < piece.size()) {
            const uint8_t b = static_cast<uint8_t>(piece[i]);
            size_t len = 1;
            char32_t cp = b;
            if (b >= 0xF0)      { len = 4; cp = b & 0x07u; }
            else if (b >= 0xE0) { len = 3; cp = b & 0x0Fu; }
            else if (b >= 0xC0) { len = 2; cp = b & 0x1Fu; }
            if (i + len > piece.size()) { len = 1; cp = b; }

            if (len == 3) {
                cp = (cp << 6) | (static_cast<uint8_t>(piece[i + 1]) & 0x3Fu);
                cp = (cp << 6) | (static_cast<uint8_t>(piece[i + 2]) & 0x3Fu);
            } else if (len == 4) {
                cp = (cp << 6) | (static_cast<uint8_t>(piece[i + 1]) & 0x3Fu);
                cp = (cp << 6) | (static_cast<uint8_t>(piece[i + 2]) & 0x3Fu);
                cp = (cp << 6) | (static_cast<uint8_t>(piece[i + 3]) & 0x3Fu);
            } else if (len == 2) {
                cp = (cp << 6) | (static_cast<uint8_t>(piece[i + 1]) & 0x3Fu);
            }

            if (m_sentencePiece && cp == 0x2581) {
                out.push_back(' ');
            } else if (m_byteLevelBpe) {
                auto it = m_byteDecoder.find(cp);
                if (it != m_byteDecoder.end()) {
                    out.push_back(static_cast<char>(it->second));
                } else {
                    out.append(piece, i, len);
                }
            } else {
                out.append(piece, i, len);
            }
            i += len;
        }
        return out;
    }

    std::vector<int> Tokenizer::encodeInt(const std::string& text, bool addBos, bool addEos) const {
        auto result = encode(text, addBos, addEos);
        std::vector<int> intResult;
        intResult.reserve(result.size());
        for (uint32_t v : result) intResult.push_back(static_cast<int>(v));
        return intResult;
    }

    void Tokenizer::applyBPE(std::vector<std::string>& pieces) const {
        if (pieces.size() < 2) return;
        while (true) {
            float bestScore = std::numeric_limits<float>::max();
            int bestIdx = -1;

            for (size_t i = 0; i + 1 < pieces.size(); ++i) {
                auto lit = m_vocab.find(pieces[i]);
                auto rit = m_vocab.find(pieces[i + 1]);
                if (lit == m_vocab.end() || rit == m_vocab.end()) continue;

                uint64_t key = makeMergeKey(lit->second, rit->second);
                auto mit = m_merges.find(key);
                if (mit != m_merges.end() && mit->second < bestScore) {
                    bestScore = mit->second;
                    bestIdx = static_cast<int>(i);
                }
            }

            if (bestIdx < 0) break;
            mergePair(pieces, bestIdx);
        }
    }

    int Tokenizer::findBestMerge(const std::vector<std::string>& pieces, float& bestScore) const {
        int bestIdx = -1;
        bestScore = std::numeric_limits<float>::max();
        for (size_t i = 0; i + 1 < pieces.size(); ++i) {
            auto lit = m_vocab.find(pieces[i]);
            auto rit = m_vocab.find(pieces[i + 1]);
            if (lit == m_vocab.end() || rit == m_vocab.end()) continue;
            uint64_t key = makeMergeKey(lit->second, rit->second);
            auto mit = m_merges.find(key);
            if (mit != m_merges.end() && mit->second < bestScore) {
                bestScore = mit->second;
                bestIdx = static_cast<int>(i);
            }
        }
        return bestIdx;
    }

    void Tokenizer::mergePair(std::vector<std::string>& pieces, int i) const {
        if (i < 0 || i + 1 >= static_cast<int>(pieces.size())) return;
        pieces[i] = pieces[i] + pieces[i + 1];
        pieces.erase(pieces.begin() + i + 1);
    }

} // namespace Deep2Rom::Inference
