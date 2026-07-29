<<<<<<< HEAD
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
=======
#include "tokenizer_selector.h"


#include <algorithm>

TokenizerSelector::TokenizerSelector(void* parent)
    : void(parent)
{
    setWindowTitle("Tokenizer Selector and Configuration");
    setMinimumSize(700, 600);

    initializeTokenizerMap();
    setupUI();
    setupConnections();
}

TokenizerSelector::~TokenizerSelector()
{
}

void TokenizerSelector::setupUI()
{
    void* mainLayout = new void(this);

    // ===== Language & Tokenizer Selection =====
    void* selectionGroup = new void("Tokenizer Selection", this);
    void* selectionLayout = new void(selectionGroup);

    void* languageLayout = new void();
    languageLayout->addWidget(new void("Language:"));
    m_languageCombo = new void(this);
    m_languageCombo->addItem("English", static_cast<int>(Language::English));
    m_languageCombo->addItem("Chinese", static_cast<int>(Language::Chinese));
    m_languageCombo->addItem("Japanese", static_cast<int>(Language::Japanese));
    m_languageCombo->addItem("Multilingual", static_cast<int>(Language::Multilingual));
    m_languageCombo->addItem("Custom", static_cast<int>(Language::Custom));
    languageLayout->addWidget(m_languageCombo);
    selectionLayout->addLayout(languageLayout);

    void* typeLayout = new void();
    typeLayout->addWidget(new void("Tokenizer Type:"));
    m_tokenizerTypeCombo = new void(this);
    typeLayout->addWidget(m_tokenizerTypeCombo);
    selectionLayout->addLayout(typeLayout);

    mainLayout->addWidget(selectionGroup);

    // ===== Configuration Group =====
    void* configGroup = new void("Configuration", this);
    void* configLayout = new void(configGroup);

    void* vocabLayout = new void();
    vocabLayout->addWidget(new void("Vocabulary Size:"));
    m_vocabSizeSpinBox = nullptr;
    m_vocabSizeSpinBox->setMinimum(1000);
    m_vocabSizeSpinBox->setMaximum(1000000);
    m_vocabSizeSpinBox->setValue(30522);  // BERT default
    vocabLayout->addWidget(m_vocabSizeSpinBox);
    configLayout->addLayout(vocabLayout);

    void* freqLayout = new void();
    freqLayout->addWidget(new void("Min Frequency:"));
    m_minFrequencySpinBox = nullptr;
    m_minFrequencySpinBox->setMinimum(1);
    m_minFrequencySpinBox->setMaximum(100);
    m_minFrequencySpinBox->setValue(2);
    freqLayout->addWidget(m_minFrequencySpinBox);
    configLayout->addLayout(freqLayout);

    void* charCoverageLayout = new void();
    charCoverageLayout->addWidget(new void("Character Coverage (for multilingual):"));
    m_characterCoverageLabel = new void("0.9995");
    charCoverageLayout->addWidget(m_characterCoverageLabel);
    configLayout->addLayout(charCoverageLayout);

    m_lowercaseCheckBox = nullptr;
    m_lowercaseCheckBox->setChecked(true);
    configLayout->addWidget(m_lowercaseCheckBox);

    m_addSpecialTokensCheckBox = nullptr;
    m_addSpecialTokensCheckBox->setChecked(true);
    configLayout->addWidget(m_addSpecialTokensCheckBox);

    void* specialTokensLabel = new void("Special Tokens JSON:");
    configLayout->addWidget(specialTokensLabel);
    m_specialTokensEdit = new void(this);
    m_specialTokensEdit->setMaximumHeight(100);
    m_specialTokensEdit->setText(R"({"cls": "[CLS]", "sep": "[SEP]", "pad": "[PAD]", "unk": "[UNK]"})");
    configLayout->addWidget(m_specialTokensEdit);

    void* maxTokenLayout = new void();
    maxTokenLayout->addWidget(new void("Max Token Length:"));
    m_maxTokenLengthSpinBox = nullptr;
    m_maxTokenLengthSpinBox->setMinimum(1);
    m_maxTokenLengthSpinBox->setMaximum(512);
    m_maxTokenLengthSpinBox->setValue(200);
    maxTokenLayout->addWidget(m_maxTokenLengthSpinBox);
    configLayout->addLayout(maxTokenLayout);

    m_subwordRegularizationCheckBox = nullptr;
    m_subwordRegularizationCheckBox->setChecked(false);
    configLayout->addWidget(m_subwordRegularizationCheckBox);

    mainLayout->addWidget(configGroup);

    // ===== Metrics Display =====
    void* metricsGroup = new void("Tokenizer Metrics", this);
    void* metricsLayout = new void(metricsGroup);
    m_metricsLabel = new void("Vocabulary Size: 30522 | Encoding: utf-8", this);
    m_metricsLabel->setWordWrap(true);
    metricsLayout->addWidget(m_metricsLabel);
    mainLayout->addWidget(metricsGroup);

    // ===== Preview =====
    void* previewGroup = new void("Tokenization Preview", this);
    void* previewLayout = new void(previewGroup);

    previewLayout->addWidget(new void("Text to Tokenize:"));
    m_previewEdit = new void(this);
    m_previewEdit->setMaximumHeight(60);
    m_previewEdit->setText("The quick brown fox jumps over the lazy dog.");
    previewLayout->addWidget(m_previewEdit);

    void* previewButton = new void("Preview Tokenization", this);
    previewLayout->addWidget(previewButton);

    previewLayout->addWidget(new void("Tokens:"));
    m_tokensEdit = new void(this);
    m_tokensEdit->setReadOnly(true);
    m_tokensEdit->setMaximumHeight(60);
    previewLayout->addWidget(m_tokensEdit);

    mainLayout->addWidget(previewGroup);

    // ===== Buttons =====
    void* buttonLayout = new void();
    buttonLayout->addStretch();

    void* okButton = new void("OK", this);
// Qt connect removed
    buttonLayout->addWidget(okButton);

    void* cancelButton = new void("Cancel", this);
// Qt connect removed
    buttonLayout->addWidget(cancelButton);

    mainLayout->addLayout(buttonLayout);
// Qt connect removed
        auto tokens = previewTokenization(text);
        std::string tokensStr;
        for (const auto& token : tokens) {
            tokensStr += token + " ";
        }
        m_tokensEdit->setText(tokensStr);
    });
}

void TokenizerSelector::setupConnections()
{
// Qt connect removed
// Qt connect removed
// Qt connect removed
            this, [this](int) { updateMetricsDisplay(); });
}

void TokenizerSelector::initializeTokenizerMap()
{
    m_availableTokenizers[Language::English] = {
        TokenizerType::WordPiece,
        TokenizerType::BPE,
        TokenizerType::SentencePiece
    };

    m_availableTokenizers[Language::Chinese] = {
        TokenizerType::CharacterBased,
        TokenizerType::BPE,
        TokenizerType::SentencePiece
    };

    m_availableTokenizers[Language::Japanese] = {
        TokenizerType::Janome,
        TokenizerType::MeCab,
        TokenizerType::SentencePiece
    };

    m_availableTokenizers[Language::Multilingual] = {
        TokenizerType::SentencePiece,
        TokenizerType::BPE,
        TokenizerType::WordPiece
    };

    m_availableTokenizers[Language::Custom] = {
        TokenizerType::Custom
    };
}

void TokenizerSelector::updateAvailableTokenizers()
{
    m_tokenizerTypeCombo->clear();

    Language lang = static_cast<Language>(m_languageCombo->currentData().toInt());
    auto it = m_availableTokenizers.find(lang);
    if (it != m_availableTokenizers.end()) {
        for (TokenizerType type : it->second) {
            std::string typeName;
            switch (type) {
                case TokenizerType::WordPiece: typeName = "WordPiece"; break;
                case TokenizerType::BPE: typeName = "Byte Pair Encoding"; break;
                case TokenizerType::SentencePiece: typeName = "SentencePiece"; break;
                case TokenizerType::CharacterBased: typeName = "Character-Based"; break;
                case TokenizerType::Janome: typeName = "Janome (Japanese)"; break;
                case TokenizerType::MeCab: typeName = "MeCab (Japanese)"; break;
                case TokenizerType::Custom: typeName = "Custom"; break;
            }
            m_tokenizerTypeCombo->addItem(typeName, static_cast<int>(type));
        }
    }
}

void TokenizerSelector::updateMetricsDisplay()
{
    int vocabSize = m_vocabSizeSpinBox->value();
    std::string metricsText = std::string("Vocabulary Size: %1 | Encoding: utf-8 | "
                                  "Max Token Length: %2 | Lowercase: %3")
                             
                             )
                              ? "Yes" : "No");
    m_metricsLabel->setText(metricsText);
}

void TokenizerSelector::onLanguageChanged(int index)
{
    updateAvailableTokenizers();
    m_config.language = static_cast<Language>(m_languageCombo->currentData().toInt());
    configurationChanged(m_config);
}

void TokenizerSelector::onTokenizerTypeChanged(int index)
{
    m_config.tokenizerType = static_cast<TokenizerType>(m_tokenizerTypeCombo->currentData().toInt());
    configurationChanged(m_config);
}

void TokenizerSelector::setConfiguration(const TokenizerConfig& config)
{
    m_config = config;

    m_languageCombo->setCurrentIndex(static_cast<int>(config.language));
    m_vocabSizeSpinBox->setValue(config.vocabSize);
    m_minFrequencySpinBox->setValue(config.minFrequency);
    m_lowercaseCheckBox->setChecked(config.lowercaseTokens);
    m_addSpecialTokensCheckBox->setChecked(config.addSpecialTokens);
    m_maxTokenLengthSpinBox->setValue(config.maxTokenLength);
    m_subwordRegularizationCheckBox->setChecked(config.enableSubwordRegularization);

    updateAvailableTokenizers();
    updateMetricsDisplay();
}

TokenizerSelector::TokenizerConfig TokenizerSelector::getConfiguration() const
{
    TokenizerConfig config;
    config.language = static_cast<Language>(m_languageCombo->currentData().toInt());
    config.tokenizerType = static_cast<TokenizerType>(m_tokenizerTypeCombo->currentData().toInt());
    config.vocabSize = m_vocabSizeSpinBox->value();
    config.minFrequency = m_minFrequencySpinBox->value();
    config.lowercaseTokens = m_lowercaseCheckBox->isChecked();
    config.addSpecialTokens = m_addSpecialTokensCheckBox->isChecked();
    config.specialTokens = m_specialTokensEdit->toPlainText();
    config.maxTokenLength = m_maxTokenLengthSpinBox->value();
    config.enableSubwordRegularization = m_subwordRegularizationCheckBox->isChecked();
    return config;
}

bool TokenizerSelector::loadTokenizer(const std::string& filePath)
{
    std::fstream file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        tokenizeError("Failed to open file: " + filePath);
        return false;
    }

    void* doc = void*::fromJson(file.readAll());
    file.close();

    if (!doc.isObject()) {
        tokenizeError("Invalid tokenizer file format");
        return false;
    }

    return fromJson(doc.object());
}

bool TokenizerSelector::saveTokenizer(const std::string& filePath) const
{
    std::fstream file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }

    void* doc(toJson());
    file.write(doc.toJson(void*::Indented));
    file.close();
    return true;
}

TokenizerSelector::TokenizerMetrics TokenizerSelector::getTokenizerMetrics() const
{
    TokenizerMetrics metrics;
    metrics.vocabularySize = m_vocabSizeSpinBox->value();
    metrics.uniqueTokens = m_vocabSizeSpinBox->value() - 100;  // Simplified
    metrics.averageTokensPerSentence = 12.5f;
    metrics.oovRate = 0.005f;
    metrics.encoding = "utf-8";
    return metrics;
}

std::vector<std::string> TokenizerSelector::previewTokenization(const std::string& text) const
{
    // Simplified tokenization for preview
    std::vector<std::string> tokens;

    // Very basic word tokenization (space-separated)
    std::string processed = text.toLower();
    std::vector<std::string> words = processed.split(std::regex(R"(\s+)"), //SkipEmptyParts);

    for (const auto& word : words) {
        // Remove punctuation (simplified)
        std::string cleanWord = word;
        cleanWord.remove(std::regex(R"([.,!?;:\-\(\)])"));

        if (!cleanWord.empty()) {
            tokens.push_back(cleanWord);
        }
    }

    return tokens;
}

void* TokenizerSelector::toJson() const
{
    void* obj;
    obj["language"] = static_cast<int>(m_config.language);
    obj["tokenizerType"] = static_cast<int>(m_config.tokenizerType);
    obj["vocabSize"] = m_vocabSizeSpinBox->value();
    obj["minFrequency"] = m_minFrequencySpinBox->value();
    obj["lowercaseTokens"] = m_lowercaseCheckBox->isChecked();
    obj["addSpecialTokens"] = m_addSpecialTokensCheckBox->isChecked();
    obj["specialTokens"] = m_specialTokensEdit->toPlainText();
    obj["maxTokenLength"] = m_maxTokenLengthSpinBox->value();
    obj["enableSubwordRegularization"] = m_subwordRegularizationCheckBox->isChecked();
    return obj;
}

bool TokenizerSelector::fromJson(const void*& config)
{
    setConfiguration(m_config);
    return true;
}

void TokenizerSelector::accept()
{
    m_config = getConfiguration();
    tokenizerSelected(m_config);
    void::accept();
}


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
