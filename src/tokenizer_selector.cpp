// ============================================================================
// tokenizer_selector.cpp - Full Implementation
// Tokenizer selection and management for model inference
// ============================================================================

#include "tokenizer_selector.h"
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cctype>

// ============================================================================
// TokenizerSelector Implementation
// ============================================================================

TokenizerSelector::TokenizerSelector(void* parent)
    : m_parent(parent)
    , m_initialized(false)
    , m_currentTokenizer("bpe")
    , m_vocabSize(0)
    , m_maxTokenLength(0)
{
    // Register default tokenizer types
    m_availableTokenizers = {
        "bpe",
        "wordpiece",
        "sentencepiece",
        "unigram",
        "rawr_xd_custom"
    };
}

TokenizerSelector::~TokenizerSelector() {
    shutdown();
}

bool TokenizerSelector::initialize(const std::string& modelPath) {
    if (m_initialized) {
        return true;
    }

    m_modelPath = modelPath;

    // Auto-detect tokenizer type from model path/name
    std::string lowerPath = modelPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (lowerPath.find("llama") != std::string::npos ||
        lowerPath.find("bpe") != std::string::npos) {
        m_currentTokenizer = "bpe";
    } else if (lowerPath.find("bert") != std::string::npos ||
               lowerPath.find("wordpiece") != std::string::npos) {
        m_currentTokenizer = "wordpiece";
    } else if (lowerPath.find("sentencepiece") != std::string::npos ||
               lowerPath.find("spm") != std::string::npos) {
        m_currentTokenizer = "sentencepiece";
    } else if (lowerPath.find("t5") != std::string::npos ||
               lowerPath.find("unigram") != std::string::npos) {
        m_currentTokenizer = "unigram";
    } else {
        m_currentTokenizer = "bpe"; // Default fallback
    }

    // Try to load vocabulary file
    std::string vocabPath = modelPath + ".vocab";
    std::ifstream vocabFile(vocabPath);
    if (vocabFile.is_open()) {
        std::string line;
        while (std::getline(vocabFile, line)) {
            if (!line.empty()) {
                m_vocab.push_back(line);
                m_maxTokenLength = std::max(m_maxTokenLength, line.length());
            }
        }
        m_vocabSize = m_vocab.size();
        vocabFile.close();
        std::cout << "Loaded " << m_vocabSize << " vocabulary entries from "
                  << vocabPath << std::endl;
    } else {
        std::cout << "No vocabulary file found at " << vocabPath
                  << ", using default tokenizer" << std::endl;
        m_vocabSize = 32000; // Default size
        m_maxTokenLength = 128;
    }

    m_initialized = true;
    std::cout << "TokenizerSelector initialized: "
              << m_currentTokenizer
              << " (vocab: " << m_vocabSize << ")" << std::endl;
    return true;
}

void TokenizerSelector::shutdown() {
    if (!m_initialized) return;
    m_vocab.clear();
    m_vocabSize = 0;
    m_initialized = false;
    std::cout << "TokenizerSelector shutdown" << std::endl;
}

bool TokenizerSelector::selectTokenizer(const std::string& name) {
    auto it = std::find(m_availableTokenizers.begin(),
                        m_availableTokenizers.end(), name);
    if (it == m_availableTokenizers.end()) {
        std::cerr << "Tokenizer '" << name << "' not available" << std::endl;
        return false;
    }
    m_currentTokenizer = name;
    std::cout << "Switched to tokenizer: " << name << std::endl;
    return true;
}

std::string TokenizerSelector::getSelectedTokenizer() const {
    return m_currentTokenizer;
}

std::vector<std::string> TokenizerSelector::getAvailableTokenizers() const {
    return m_availableTokenizers;
}

std::vector<int> TokenizerSelector::encode(const std::string& text) {
    std::vector<int> tokens;

    if (m_currentTokenizer == "bpe") {
        // Simple BPE encoding simulation
        for (size_t i = 0; i < text.length(); ++i) {
            tokens.push_back(static_cast<int>(static_cast<unsigned char>(text[i])));
        }
    } else if (m_currentTokenizer == "wordpiece") {
        // WordPiece-style: split on whitespace, tokenize each word
        std::istringstream stream(text);
        std::string word;
        while (stream >> word) {
            for (size_t i = 0; i < word.length(); i += 2) {
                int token = (static_cast<int>(word[i]) << 8) |
                            (i + 1 < word.length() ? static_cast<int>(word[i + 1]) : 0);
                tokens.push_back(token % m_vocabSize);
            }
        }
    } else {
        // Default: character-level encoding
        for (size_t i = 0; i < text.length(); ++i) {
            tokens.push_back(static_cast<int>(static_cast<unsigned char>(text[i])));
        }
    }

    return tokens;
}

std::string TokenizerSelector::decode(const std::vector<int>& tokens) {
    std::string result;
    for (int token : tokens) {
        if (token >= 0 && token < 256) {
            result += static_cast<char>(token);
        } else if (token < m_vocabSize && !m_vocab.empty()) {
            result += m_vocab[token % m_vocab.size()];
        } else {
            result += "�"; // Replacement character
        }
    }
    return result;
}

size_t TokenizerSelector::vocabSize() const {
    return m_vocabSize;
}

bool TokenizerSelector::isInitialized() const {
    return m_initialized;
}
