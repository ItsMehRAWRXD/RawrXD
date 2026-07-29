#include "token_generator.h"
#include <mutex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <codecvt>
#include <locale>
#include <cwctype>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

// Fix for map mergeRank using std::pair keys if hashing not provided
namespace std {
    template <>
    struct hash<std::pair<std::string, std::string>> {
        size_t operator()(const std::pair<std::string, std::string>& k) const {
            return std::hash<std::string>()(k.first) ^ (std::hash<std::string>()(k.second) << 1);
        }
    };
}

namespace RawrXD {

TokenGenerator::TokenGenerator() : m_config(TokenizationConfig()) {
    initialize();
}

TokenGenerator::TokenGenerator(const TokenizationConfig& config) : m_config(config) {
    initialize();
}

TokenGenerator::~TokenGenerator() {
    clearCache();
}

TokenGenerator::TokenGenerator(TokenGenerator&& other) noexcept
    : m_config(std::move(other.m_config)),
      m_initialized(other.m_initialized.load()),
      m_vocab(std::move(other.m_vocab)),
      m_idToToken(std::move(other.m_idToToken)),
      m_tokenInfo(std::move(other.m_tokenInfo)),
      m_mergeRules(std::move(other.m_mergeRules)),
      m_mergeRank(std::move(other.m_mergeRank)),
      m_bosToken(other.m_bosToken),
      m_eosToken(other.m_eosToken),
      m_padToken(other.m_padToken),
      m_unkToken(other.m_unkToken),
      m_maskToken(other.m_maskToken),
      m_cacheHits(other.m_cacheHits.load()),
      m_cacheMisses(other.m_cacheMisses.load()),
      m_cacheSize(other.m_cacheSize.load()),
      m_totalEncodings(other.m_totalEncodings.load()),
      m_totalDecodings(other.m_totalDecodings.load()),
      m_totalEncodingTime(other.m_totalEncodingTime.load()),
      m_totalDecodingTime(other.m_totalDecodingTime.load()) {
    
    std::lock_guard lock(other.m_cacheMutex);
    m_encodeCache = std::move(other.m_encodeCache);
    m_decodeCache = std::move(other.m_decodeCache);
}

TokenGenerator& TokenGenerator::operator=(TokenGenerator&& other) noexcept {
    if (this != &other) {
        m_config = std::move(other.m_config);
        m_initialized = other.m_initialized.load();
        m_vocab = std::move(other.m_vocab);
        m_idToToken = std::move(other.m_idToToken);
        m_tokenInfo = std::move(other.m_tokenInfo);
        m_mergeRules = std::move(other.m_mergeRules);
        m_mergeRank = std::move(other.m_mergeRank);
        m_bosToken = other.m_bosToken;
        m_eosToken = other.m_eosToken;
        m_padToken = other.m_padToken;
        m_unkToken = other.m_unkToken;
        m_maskToken = other.m_maskToken;
        m_cacheHits = other.m_cacheHits.load();
        m_cacheMisses = other.m_cacheMisses.load();
        m_cacheSize = other.m_cacheSize.load();
        m_totalEncodings = other.m_totalEncodings.load();
        m_totalDecodings = other.m_totalDecodings.load();
        m_totalEncodingTime = other.m_totalEncodingTime.load();
        m_totalDecodingTime = other.m_totalDecodingTime.load();
        
        std::lock_guard lock(other.m_cacheMutex);
        m_encodeCache = std::move(other.m_encodeCache);
        m_decodeCache = std::move(other.m_decodeCache);
    }
    return *this;
}

RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::initialize() {
    std::lock_guard lock(m_mutex);
    
    m_vocab["<pad>"] = m_padToken;
    m_vocab["<s>"] = m_bosToken;
    m_vocab["</s>"] = m_eosToken;
    m_vocab["<unk>"] = m_unkToken;
    m_vocab["<mask>"] = m_maskToken;
    
    m_initialized = true;
    return {};
}

RawrXD::Expected<int, RawrXD::TokenError> TokenGenerator::findToken(const std::string& token) {
    auto it = m_vocab.find(token);
    if (it != m_vocab.end()) return it->second;
    return RawrXD::Unexpected(RawrXD::TokenError::TokenNotFound);
}

RawrXD::Expected<std::string, RawrXD::TokenError> TokenGenerator::findTokenString(int tokenId) {
    auto it = m_idToToken.find(tokenId);
    if (it != m_idToToken.end()) return it->second;
    return RawrXD::Unexpected(RawrXD::TokenError::TokenNotFound);
}

RawrXD::Expected<std::vector<int>, RawrXD::TokenError> TokenGenerator::encode(const std::string& text) {
    if (!m_initialized.load()) return RawrXD::Unexpected(RawrXD::TokenError::TokenizationFailed);
    if (text.empty()) return std::vector<int>();

    if (m_config.enableCache) {
        auto res = getFromCache(text, true);
        if (res) { m_cacheHits++; return res.value(); }
        m_cacheMisses++;
    }

    auto start = std::chrono::steady_clock::now();
    std::vector<int> tokens;
    
    RawrXD::Expected<std::vector<int>, RawrXD::TokenError> res = RawrXD::Unexpected(RawrXD::TokenError::NotImplemented); 

    if (m_config.strategy == TokenizationStrategy::BPE) {
         res = bpeEncode(text);
    } else if (m_config.strategy == TokenizationStrategy::WordPiece) {
         res = wordpieceEncode(text);
    } else {
         res = bpeEncode(text);
    }

    if (!res) return res;
    tokens = res.value();

    if (m_config.addSpecialTokens) {
        tokens.insert(tokens.begin(), m_bosToken);
        tokens.push_back(m_eosToken);
    }

    if (m_config.enableCache) addToCache(text, tokens, true);

    auto end = std::chrono::steady_clock::now();
    m_totalEncodingTime.fetch_add(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
    m_totalEncodings++;

    logTokenization(text, tokens);
    return tokens;
}

RawrXD::Expected<std::string, RawrXD::TokenError> TokenGenerator::decode(const std::vector<int>& tokens) {
    if (!m_initialized.load()) return RawrXD::Unexpected(RawrXD::TokenError::TokenizationFailed);
    if (tokens.empty()) return std::string();

    auto start = std::chrono::steady_clock::now();
    std::string text;
    
    RawrXD::Expected<std::string, RawrXD::TokenError> res = RawrXD::Unexpected(RawrXD::TokenError::NotImplemented);
    if (m_config.strategy == TokenizationStrategy::BPE) {
        res = bpeDecode(tokens);
    } else {
        res = wordpieceDecode(tokens);
    }

    if (!res) return res;
    text = res.value();

    auto end = std::chrono::steady_clock::now();
    m_totalDecodings++;
    m_totalDecodingTime.fetch_add(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

    return text;
}

RawrXD::Expected<std::vector<int>, RawrXD::TokenError> TokenGenerator::bpeEncode(const std::string& text) {
    if (m_vocab.empty()) return RawrXD::Unexpected(RawrXD::TokenError::VocabularyNotLoaded);
    
    std::string processed = text;
    if (m_config.handleUnicode) {
        std::transform(processed.begin(), processed.end(), processed.begin(), ::tolower);
    }
    if (m_config.addPrefixSpace && !processed.empty() && processed[0] != ' ') {
        processed = " " + processed;
    }

    std::vector<std::string> words;
    std::istringstream stream(processed);
    std::string word;
    while(stream >> word) words.push_back(word);

    std::vector<int> tokens;
    for (const auto& w : words) {
        std::vector<std::string> wordTokens;
        for(char c : w) wordTokens.push_back(std::string(1, c));

        if (!m_mergeRules.empty()) {
            auto merged = applyBPERules(wordTokens);
            if (merged) wordTokens = merged.value();
        }

        for(const auto& t : wordTokens) {
            auto id = findToken(t);
            if (id) tokens.push_back(id.value());
            else tokens.push_back(m_unkToken);
        }
    }
    return tokens;
}

RawrXD::Expected<std::vector<std::string>, RawrXD::TokenError> TokenGenerator::applyBPERules(const std::vector<std::string>& tokens) {
    if (m_mergeRules.empty()) return tokens;
    
    auto result = tokens;
    for (int i=0; i<100; ++i) { 
        int bestRank = -1;
        int bestIdx = -1;
        
        for (size_t j=0; j+1 < result.size(); ++j) {
            std::string key = result[j] + " " + result[j+1]; 
            auto it = m_mergeRank.find(key);
            if (it != m_mergeRank.end()) {
                if (bestRank == -1 || it->second < bestRank) {
                    bestRank = it->second;
                    bestIdx = j;
                }
            }
        }

        if (bestIdx != -1) {
            result[bestIdx] = result[bestIdx] + result[bestIdx+1];
            result.erase(result.begin() + bestIdx + 1);
        } else {
            break;
        }
    }
    return result;
}

RawrXD::Expected<std::string, RawrXD::TokenError> TokenGenerator::bpeDecode(const std::vector<int>& tokens) {
    std::string text;
    for (int id : tokens) {
        if (id == m_bosToken || id == m_eosToken || id == m_padToken) continue;
        auto s = findTokenString(id);
        if (s) {
            std::string str = s.value();
            if (str.find("</w>") != std::string::npos) {
                str = str.substr(0, str.length()-4) + " ";
            }
            text += str;
        }
    }
    return text;
}

RawrXD::Expected<std::vector<int>, RawrXD::TokenError> TokenGenerator::wordpieceEncode(const std::string& text) { return bpeEncode(text); } 
RawrXD::Expected<std::string, RawrXD::TokenError> TokenGenerator::wordpieceDecode(const std::vector<int>& tokens) { return bpeDecode(tokens); }
RawrXD::Expected<std::vector<int>, RawrXD::TokenError> TokenGenerator::sentencepieceEncode(const std::string& text) { return bpeEncode(text); }
RawrXD::Expected<std::string, RawrXD::TokenError> TokenGenerator::sentencepieceDecode(const std::vector<int>& tokens) { return bpeDecode(tokens); }

RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabulary(const std::string& path) {
    std::ifstream file(path);
    if (!file) return RawrXD::Unexpected(RawrXD::TokenError::FileReadFailed);
    m_vocab.clear(); m_idToToken.clear();
    
    std::string line;
    int autoId = 0;
    while(std::getline(file, line)) {
        if(line.empty()) continue;
        m_vocab[line] = autoId;
        m_idToToken[autoId] = line;
        autoId++;
    }
    return {};
}

RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadMergeRules(const std::string& path) {
    std::ifstream file(path);
    if (!file) return RawrXD::Unexpected(RawrXD::TokenError::FileReadFailed);
    m_mergeRules.clear(); m_mergeRank.clear();
    
    std::string line;
    int rank = 0;
    while(std::getline(file, line)) {
         if (line.empty() || line[0] == '#') continue;
         size_t space = line.find(' ');
         if (space != std::string::npos) {
             std::string t1 = line.substr(0, space);
             std::string t2 = line.substr(space+1);
             m_mergeRules.push_back({t1, t2});
             m_mergeRank[t1 + " " + t2] = rank++; 
         }
    }
    return {};
}

RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabularyFromModel(const std::string& path) {
    if (fs::exists(path + "/tokenizer.json")) return loadVocabularyFromHuggingFace(path + "/tokenizer.json");
    if (fs::exists(path + "/vocab.txt")) return loadVocabulary(path + "/vocab.txt");
    
    createMinimalVocabulary(); 
    return {};
}

RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabularyFromHuggingFace(const std::string& path) {
    std::ifstream file(path);
    if(!file) return RawrXD::Unexpected(RawrXD::TokenError::FileReadFailed);
    json j; 
    try { file >> j; } catch(...) { return RawrXD::Unexpected(RawrXD::TokenError::InvalidFormat); }
    
    if (j.contains("model") && j["model"].contains("vocab")) {
        for (auto& [key, val] : j["model"]["vocab"].items()) {
            m_vocab[key] = val;
            m_idToToken[val] = key;
        }
    }
    return {};
}

void TokenGenerator::createMinimalVocabulary() {
    m_vocab.clear(); m_idToToken.clear();
    const char* toks[] = {"the", "and", "code", "return", "void", "int", "if", "else"};
    int id = 10;
    for(auto t : toks) { m_vocab[t] = id; m_idToToken[id] = t; id++; }
    
    for(char c=' '; c<='~'; ++c) {
        std::string s(1, c);
        m_vocab[s] = id; m_idToToken[id] = s; id++;
    }
}

<<<<<<< HEAD
void TokenGenerator::loadConfigFromJSON(const std::string& jsonStr) {
    if (jsonStr.empty()) return;
    
    try {
        json config = json::parse(jsonStr);
        
        // Parse common tokenizer config fields
        if (config.contains("vocab_size")) {
            // Config contains vocabulary size info
        }
        if (config.contains("bos_token")) {
            m_bosToken = config["bos_token"].get<int>();
        }
        if (config.contains("eos_token")) {
            m_eosToken = config["eos_token"].get<int>();
        }
        if (config.contains("pad_token")) {
            m_padToken = config["pad_token"].get<int>();
        }
        if (config.contains("unk_token")) {
            m_unkToken = config["unk_token"].get<int>();
        }
        
        // Parse strategy if specified
        if (config.contains("tokenizer_class")) {
            std::string tokenizerClass = config["tokenizer_class"].get<std::string>();
            if (tokenizerClass.find("BPE") != std::string::npos) {
                m_config.strategy = TokenizationStrategy::BPE;
            } else if (tokenizerClass.find("SentencePiece") != std::string::npos) {
                m_config.strategy = TokenizationStrategy::SentencePiece;
            } else if (tokenizerClass.find("WordPiece") != std::string::npos) {
                m_config.strategy = TokenizationStrategy::WordPiece;
            }
        }
    } catch (const std::exception& e) {
        logError("Failed to parse config JSON: " + std::string(e.what()), TokenError::InvalidFormat);
    }
}

void TokenGenerator::loadTokenizerConfigFromJSON(const std::string& jsonStr) {
    // Same implementation as loadConfigFromJSON for tokenizer-specific config
    loadConfigFromJSON(jsonStr);
}
=======
void TokenGenerator::loadConfigFromJSON(const std::string&) {}
void TokenGenerator::loadTokenizerConfigFromJSON(const std::string&) {}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabularyFromMemory(
    const std::vector<std::string>& tokens,
    const std::vector<float>& scores,
    const std::vector<uint32_t>& types
) {
    if (tokens.empty()) return RawrXD::Unexpected(RawrXD::TokenError::VocabularyNotLoaded);
    
    std::unique_lock lock(m_mutex);
    m_vocab.clear();
    m_idToToken.clear();
    m_tokenInfo.clear();
    
    for (size_t i = 0; i < tokens.size(); ++i) {
        int id = static_cast<int>(i);
        m_vocab[tokens[i]] = id;
        m_idToToken[id] = tokens[i];
        
        TokenInfo info;
        info.id = id;
        info.text = tokens[i];
        if (i < scores.size()) info.score = scores[i];
        info.type = (i < types.size() && types[i] == 3) ? "control" : "normal"; 
        
        m_tokenInfo[id] = info;
    }
    
    if (m_vocab.count("<s>")) m_bosToken = m_vocab["<s>"];
    if (m_vocab.count("</s>")) m_eosToken = m_vocab["</s>"];
    if (m_vocab.count("<|endoftext|>")) m_eosToken = m_vocab["<|endoftext|>"];
    
    m_initialized = true;
    return {};
}

<<<<<<< HEAD
RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabularyFromSentencePiece(const std::string& modelPath) {
    // SentencePiece model loading
    // SentencePiece models are typically stored as protobuf files
    std::ifstream file(modelPath, std::ios::binary);
    if (!file.is_open()) {
        return RawrXD::Unexpected(TokenError::FileReadFailed);
    }

    // Read file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read model data
    std::vector<uint8_t> modelData(fileSize);
    if (!file.read(reinterpret_cast<char*>(modelData.data()), fileSize)) {
        return RawrXD::Unexpected(TokenError::FileReadFailed);
    }

    // Parse SentencePiece model (simplified - would use sentencepiece library in production)
    // For now, extract vocabulary from model metadata
    std::lock_guard<std::mutex> lock(m_mutex);
    m_vocab.clear();
    m_idToToken.clear();

    // Extract pieces from model (simplified parsing)
    // Real implementation would use sentencepiece::SentencePieceProcessor
    // This is a placeholder that creates a minimal vocabulary
    createMinimalVocabulary();

    m_initialized = true;
    return {};
}

RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabularyFromJSON(const std::string& jsonPath) {
    // Load vocabulary from JSON file (HuggingFace format)
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        return RawrXD::Unexpected(TokenError::FileReadFailed);
    }

    try {
        json vocabJson;
        file >> vocabJson;

        std::lock_guard<std::mutex> lock(m_mutex);
        m_vocab.clear();
        m_idToToken.clear();
        m_tokenInfo.clear();

        // Parse vocabulary
        if (vocabJson.contains("model") && vocabJson["model"].contains("vocab")) {
            // HuggingFace tokenizer format
            const auto& vocab = vocabJson["model"]["vocab"];
            int id = 0;
            for (const auto& [token, tokenId] : vocab.items()) {
                int token_id = tokenId.get<int>();
                m_vocab[token] = token_id;
                m_idToToken[token_id] = token;

                TokenInfo info;
                info.id = token_id;
                info.text = token;
                info.score = 0.0f;
                info.isSpecial = (token.find('<') == 0 && token.find('>') != std::string::npos);
                info.type = info.isSpecial ? "special" : "normal";
                m_tokenInfo[token_id] = info;
            }
        } else if (vocabJson.is_object()) {
            // Simple vocab format: {"token": id, ...}
            for (const auto& [token, tokenId] : vocabJson.items()) {
                int token_id = tokenId.get<int>();
                m_vocab[token] = token_id;
                m_idToToken[token_id] = token;

                TokenInfo info;
                info.id = token_id;
                info.text = token;
                info.score = 0.0f;
                info.isSpecial = (token.find('<') == 0 && token.find('>') != std::string::npos);
                info.type = info.isSpecial ? "special" : "normal";
                m_tokenInfo[token_id] = info;
            }
        }

        // Load special tokens if present
        if (vocabJson.contains("added_tokens")) {
            for (const auto& token : vocabJson["added_tokens"]) {
                std::string token_str = token["content"].get<std::string>();
                int token_id = token["id"].get<int>();
                bool special = token.value("special", false);

                m_vocab[token_str] = token_id;
                m_idToToken[token_id] = token_str;

                TokenInfo info;
                info.id = token_id;
                info.text = token_str;
                info.score = 0.0f;
                info.isSpecial = special;
                info.type = special ? "special" : "normal";
                m_tokenInfo[token_id] = info;
            }
        }

        // Set special tokens
        if (m_vocab.count("<s>")) m_bosToken = m_vocab["<s>"];
        if (m_vocab.count("</s>")) m_eosToken = m_vocab["</s>"];
        if (m_vocab.count("<pad>")) m_padToken = m_vocab["<pad>"];
        if (m_vocab.count("<unk>")) m_unkToken = m_vocab["<unk>"];
        if (m_vocab.count("<|endoftext|>")) m_eosToken = m_vocab["<|endoftext|>"];

        m_initialized = true;
        return {};
    } catch (const std::exception& e) {
        return RawrXD::Unexpected(TokenError::InvalidFormat);
    }
}
=======
RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabularyFromSentencePiece(const std::string&) { return {}; }
RawrXD::Expected<void, RawrXD::TokenError> TokenGenerator::loadVocabularyFromJSON(const std::string&) { return {}; }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

bool TokenGenerator::isValidTokenId(int id) const { return m_idToToken.count(id); }
bool TokenGenerator::isValidToken(const std::string& t) const { return m_vocab.count(t); }
void TokenGenerator::clearCache() { 
    std::lock_guard l(m_cacheMutex); m_encodeCache.clear(); m_decodeCache.clear(); 
}
size_t TokenGenerator::getCacheSize() const { return m_cacheSize; }

RawrXD::Expected<std::vector<int>, RawrXD::TokenError> TokenGenerator::getFromCache(const std::string& k, bool) {
    return RawrXD::Unexpected(RawrXD::TokenError::TokenNotFound); 
}
<<<<<<< HEAD
void TokenGenerator::addToCache(const std::string& key, const std::vector<int>& tokens, bool encoding) {
    if (!m_config.enableCache || key.empty()) return;
    
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    
    // Check if we need to evict before adding
    if (encoding) {
        if (m_encodeCache.size() >= m_config.cacheSize) {
            evictCacheIfNeeded();
        }
        m_encodeCache[key] = tokens;
    } else {
        // For decode cache, convert tokens to string key
        std::string tokenKey;
        for (size_t i = 0; i < tokens.size() && i < 10; ++i) {
            if (i > 0) tokenKey += ",";
            tokenKey += std::to_string(tokens[i]);
        }
        if (m_decodeCache.size() >= m_config.cacheSize) {
            evictCacheIfNeeded();
        }
        m_decodeCache[tokenKey] = key; // key is the decoded text
    }
    
    m_cacheSize = m_encodeCache.size() + m_decodeCache.size();
}

void TokenGenerator::evictCacheIfNeeded() {
    // Simple LRU eviction: remove 10% of oldest entries
    size_t encodeEvict = m_encodeCache.size() / 10;
    size_t decodeEvict = m_decodeCache.size() / 10;
    
    // For encode cache, remove oldest entries (beginning of unordered_map)
    auto encodeIt = m_encodeCache.begin();
    for (size_t i = 0; i < encodeEvict && encodeIt != m_encodeCache.end(); ++i) {
        encodeIt = m_encodeCache.erase(encodeIt);
    }
    
    // For decode cache
    auto decodeIt = m_decodeCache.begin();
    for (size_t i = 0; i < decodeEvict && decodeIt != m_decodeCache.end(); ++i) {
        decodeIt = m_decodeCache.erase(decodeIt);
    }
}

void TokenGenerator::logTokenization(const std::string& text, const std::vector<int>& tokens) {
    if (!m_initialized) return;
    
    // Log tokenization details for debugging
    std::string tokenStr;
    for (size_t i = 0; i < tokens.size() && i < 20; ++i) {
        if (i > 0) tokenStr += ", ";
        tokenStr += std::to_string(tokens[i]);
    }
    if (tokens.size() > 20) {
        tokenStr += ", ... (" + std::to_string(tokens.size() - 20) + " more)";
    }
    
    // Use spdlog if available, otherwise silent
#ifdef SPDLOG_ACTIVE_LEVEL
    spdlog::debug("Tokenized: \"{}\" -> [{}]", text.substr(0, 50), tokenStr);
#endif
}

void TokenGenerator::logError(const std::string& message, RawrXD::TokenError error) {
    // Log error with error code
    std::string errorStr;
    switch (error) {
        case TokenError::EncodingFailed: errorStr = "EncodingFailed"; break;
        case TokenError::DecodingFailed: errorStr = "DecodingFailed"; break;
        case TokenError::VocabularyNotLoaded: errorStr = "VocabularyNotLoaded"; break;
        case TokenError::TokenNotFound: errorStr = "TokenNotFound"; break;
        case TokenError::InvalidTokenId: errorStr = "InvalidTokenId"; break;
        case TokenError::InvalidFormat: errorStr = "InvalidFormat"; break;
        case TokenError::OutOfMemory: errorStr = "OutOfMemory"; break;
        default: errorStr = "Unknown"; break;
    }
    
#ifdef SPDLOG_ACTIVE_LEVEL
    spdlog::error("[TokenGenerator] {}: {}", errorStr, message);
#else
    (void)message; // Suppress unused warning if spdlog not available
#endif
}
=======
void TokenGenerator::addToCache(const std::string&, const std::vector<int>&, bool) {}
void TokenGenerator::evictCacheIfNeeded() {}

std::string TokenGenerator::detectTokenType(const std::string&) const { return "word"; }
void TokenGenerator::logTokenization(const std::string&, const std::vector<int>&) {}
void TokenGenerator::logError(const std::string&, RawrXD::TokenError) {}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

RawrXD::Expected<RawrXD::TokenInfo, RawrXD::TokenError> TokenGenerator::getTokenInfo(int id) {
     if (m_tokenInfo.count(id)) return m_tokenInfo.at(id);
     return RawrXD::Unexpected(RawrXD::TokenError::TokenNotFound); 
}
RawrXD::Expected<RawrXD::TokenInfo, RawrXD::TokenError> TokenGenerator::getTokenInfo(const std::string& t) { 
    if (m_vocab.count(t)) return getTokenInfo(m_vocab.at(t));
    return RawrXD::Unexpected(RawrXD::TokenError::TokenNotFound); 
}
RawrXD::Expected<std::wstring, RawrXD::TokenError> TokenGenerator::utf8ToWide(const std::string&) { return std::wstring(L""); }
RawrXD::Expected<std::string, RawrXD::TokenError> TokenGenerator::wideToUtf8(const std::wstring&) { return std::string(""); }
json TokenGenerator::getStatus() const { return {}; }
void TokenGenerator::setConfig(const TokenizationConfig& c) { m_config = c; }
RawrXD::Expected<std::vector<std::vector<int>>, RawrXD::TokenError> TokenGenerator::encodeBatch(const std::vector<std::string>&) { return std::vector<std::vector<int>>(); }
RawrXD::Expected<std::vector<std::string>, RawrXD::TokenError> TokenGenerator::decodeBatch(const std::vector<std::vector<int>>&) { return std::vector<std::string>(); }

void TokenGenerator::setVulkanCompute(std::shared_ptr<VulkanCompute> vulkan) {
    m_vulkan = vulkan;
    if (m_vulkan) {
        spdlog::info("TokenGenerator: GPU Acceleration Enabled");
        m_config.enableGpu = true;
    }
}

RawrXD::Expected<std::vector<std::vector<int>>, RawrXD::TokenError> TokenGenerator::encodeBatchGPU(
    const std::vector<std::string>& texts
) {
    if (!m_vulkan || !m_config.enableGpu) {
        spdlog::warn("GPU encoding requested but Vulkan not available. Falling back to CPU.");
        return encodeBatch(texts);
    }
    return encodeBatch(texts);
}

} // namespace RawrXD
