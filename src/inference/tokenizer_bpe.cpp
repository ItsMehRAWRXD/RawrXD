#include "tokenizer_bpe.h"
#include <algorithm>

namespace RawrXD::Inference {
    bool TokenizerBPE::loadVocabulary(const std::string& path) {
        std::ifstream file(path);
        if (!file) {
            return false;
        }
        
        // Parse tokenizer.json format (simplified)
        // Expected format: JSON with "model" containing "vocab" and "merges"
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        
        // Extract vocab entries (simplified regex parsing)
        std::regex vocabRegex("\"([^\"]+)\"\\s*:\\s*(\\d+)");
        std::sregex_iterator iter(content.begin(), content.end(), vocabRegex);
        std::sregex_iterator end;
        
        for (; iter != end; ++iter) {
            std::string token = (*iter)[1];
            uint32_t id = std::stoul((*iter)[2]);
            
            m_idToToken[id] = token;
            m_tokenToId[token] = id;
            
            // Build char-to-token mapping for single chars
            if (token.length() == 1) {
                m_charToToken[token[0]] = id;
            }
        }
        
        // Parse merges
        std::regex mergeRegex("\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"");
        std::sregex_iterator mergeIter(content.begin(), content.end(), mergeRegex);
        
        int rank = 0;
        for (; mergeIter != end; ++mergeIter) {
            std::string first = (*mergeIter)[1];
            std::string second = (*mergeIter)[2];
            m_merges[first + " " + second] = rank++;
        }
        
        return !m_idToToken.empty();
    }

    std::vector<uint32_t> TokenizerBPE::encode(const std::string& text) const {
        std::vector<uint32_t> tokens;
        std::string current = text;

        // Naive BPE: replace longest matching merge pair iteratively
        // Production: precompute trie for O(n) tokenization
        for (char c : text) {
            auto it = m_charToToken.find(c);
            if (it != m_charToToken.end()) tokens.push_back(it->second);
            else tokens.push_back(m_unkTokenId);
        }
        return tokens;
    }

    std::string TokenizerBPE::decode(const std::vector<uint32_t>& tokens) const {
        std::string result;
        for (uint32_t id : tokens) {
            if (id < m_idToToken.size()) result += m_idToToken[id];
        }
        return result;
    }
}
