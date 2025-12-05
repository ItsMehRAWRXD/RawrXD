#include "tokenizer_selector.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QTextEdit>
#include <QPushButton>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QFileDialog>
#include <QStandardPaths>
#include <algorithm>
#include <cctype>

/**
 * @brief TokenizerSelector::TokenizerSelector - Constructor
 */
TokenizerSelector::TokenizerSelector(QWidget* parent)
    : QDialog(parent), m_selectedTokenizer(TokenizerType::WordPiece),
      m_selectedLanguage(Language::English), m_vocabSize(30522), m_characterCoverage(0.95f)
{
    qDebug() << "[TokenizerSelector] Initializing tokenizer selector";
    setupUI();
    loadConfiguration();
}

/**
 * @brief TokenizerSelector::~TokenizerSelector - Destructor
 */
TokenizerSelector::~TokenizerSelector()
{
    qDebug() << "[TokenizerSelector] Tokenizer selector destroyed";
}

/**
 * @brief TokenizerSelector::setupUI - Create UI components
 */
void TokenizerSelector::setupUI()
{
    setWindowTitle("Tokenizer Selector");
    setMinimumWidth(600);
    setMinimumHeight(400);
    
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Tokenizer type selection
    QHBoxLayout* tokLayout = new QHBoxLayout();
    QLabel* tokLabel = new QLabel("Tokenizer Type:");
    QComboBox* tokCombo = new QComboBox();
    tokCombo->addItem("WordPiece (BERT)", static_cast<int>(TokenizerType::WordPiece));
    tokCombo->addItem("BPE (GPT)", static_cast<int>(TokenizerType::BPE));
    tokCombo->addItem("SentencePiece (Universal)", static_cast<int>(TokenizerType::SentencePiece));
    tokCombo->addItem("Character-based", static_cast<int>(TokenizerType::CharacterBased));
    tokCombo->addItem("Janome (Japanese)", static_cast<int>(TokenizerType::Janome));
    tokCombo->addItem("MeCab (Japanese)", static_cast<int>(TokenizerType::MeCab));
    tokCombo->addItem("Custom", static_cast<int>(TokenizerType::Custom));
    
    connect(tokCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TokenizerSelector::onTokenizerTypeChanged);
    
    tokLayout->addWidget(tokLabel);
    tokLayout->addWidget(tokCombo);
    tokLayout->addStretch();
    mainLayout->addLayout(tokLayout);
    
    // Language selection
    QHBoxLayout* langLayout = new QHBoxLayout();
    QLabel* langLabel = new QLabel("Language:");
    QComboBox* langCombo = new QComboBox();
    langCombo->addItem("English", static_cast<int>(Language::English));
    langCombo->addItem("Chinese", static_cast<int>(Language::Chinese));
    langCombo->addItem("Japanese", static_cast<int>(Language::Japanese));
    langCombo->addItem("Multilingual", static_cast<int>(Language::Multilingual));
    langCombo->addItem("Custom", static_cast<int>(Language::Custom));
    
    connect(langCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TokenizerSelector::onLanguageChanged);
    
    langLayout->addWidget(langLabel);
    langLayout->addWidget(langCombo);
    langLayout->addStretch();
    mainLayout->addLayout(langLayout);
    
    // Vocabulary size
    QHBoxLayout* vocabLayout = new QHBoxLayout();
    QLabel* vocabLabel = new QLabel("Vocabulary Size:");
    QSpinBox* vocabSpinBox = new QSpinBox();
    vocabSpinBox->setRange(1000, 1000000);
    vocabSpinBox->setValue(30522);
    vocabSpinBox->setSingleStep(1000);
    
    connect(vocabSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &TokenizerSelector::onVocabSizeChanged);
    
    vocabLayout->addWidget(vocabLabel);
    vocabLayout->addWidget(vocabSpinBox);
    vocabLayout->addStretch();
    mainLayout->addLayout(vocabLayout);
    
    // Character coverage
    QHBoxLayout* coverageLayout = new QHBoxLayout();
    QLabel* coverageLabel = new QLabel("Character Coverage:");
    QSpinBox* coverageSpinBox = new QSpinBox();
    coverageSpinBox->setRange(0, 100);
    coverageSpinBox->setValue(95);
    coverageSpinBox->setSuffix("%");
    
    connect(coverageSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &TokenizerSelector::onCharacterCoverageChanged);
    
    coverageLayout->addWidget(coverageLabel);
    coverageLayout->addWidget(coverageSpinBox);
    coverageLayout->addStretch();
    mainLayout->addLayout(coverageLayout);
    
    // Special tokens
    QLabel* specialTokensLabel = new QLabel("Special Tokens:");
    mainLayout->addWidget(specialTokensLabel);
    
    QHBoxLayout* specialLayout = new QHBoxLayout();
    QCheckBox* clsCheckbox = new QCheckBox("[CLS]");
    clsCheckbox->setChecked(true);
    QCheckBox* sepCheckbox = new QCheckBox("[SEP]");
    sepCheckbox->setChecked(true);
    QCheckBox* padCheckbox = new QCheckBox("[PAD]");
    padCheckbox->setChecked(true);
    QCheckBox* unkCheckbox = new QCheckBox("[UNK]");
    unkCheckbox->setChecked(true);
    
    specialLayout->addWidget(clsCheckbox);
    specialLayout->addWidget(sepCheckbox);
    specialLayout->addWidget(padCheckbox);
    specialLayout->addWidget(unkCheckbox);
    specialLayout->addStretch();
    mainLayout->addLayout(specialLayout);
    
    // Tokenization preview
    QLabel* previewLabel = new QLabel("Tokenization Preview:");
    mainLayout->addWidget(previewLabel);
    
    QTextEdit* previewText = new QTextEdit();
    previewText->setReadOnly(true);
    previewText->setMaximumHeight(150);
    mainLayout->addWidget(previewText);
    
    // Sample text for preview
    QHBoxLayout* sampleLayout = new QHBoxLayout();
    QLabel* sampleLabel = new QLabel("Sample Text:");
    QTextEdit* sampleText = new QTextEdit();
    sampleText->setPlaceholderText("Enter text to preview tokenization");
    sampleText->setMaximumHeight(100);
    
    sampleLayout->addWidget(sampleLabel);
    mainLayout->addLayout(sampleLayout);
    mainLayout->addWidget(sampleText);
    
    // Preview button
    QPushButton* previewBtn = new QPushButton("Preview Tokenization");
    connect(previewBtn, &QPushButton::clicked, [this, sampleText, previewText]() {
        QString text = sampleText->toPlainText();
        std::vector<QString> tokens = tokenize(text);
        
        QString preview;
        for (const auto& token : tokens) {
            preview += token + "\n";
        }
        
        previewText->setText(preview);
    });
    mainLayout->addWidget(previewBtn);
    
    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    
    QPushButton* exportBtn = new QPushButton("Export Config");
    connect(exportBtn, &QPushButton::clicked, this, &TokenizerSelector::exportConfiguration);
    buttonLayout->addWidget(exportBtn);
    
    QPushButton* importBtn = new QPushButton("Import Config");
    connect(importBtn, &QPushButton::clicked, this, &TokenizerSelector::importConfiguration);
    buttonLayout->addWidget(importBtn);
    
    QPushButton* okBtn = new QPushButton("OK");
    connect(okBtn, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(okBtn);
    
    QPushButton* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    buttonLayout->addWidget(cancelBtn);
    
    mainLayout->addLayout(buttonLayout);
    
    setLayout(mainLayout);
}

/**
 * @brief TokenizerSelector::tokenize - Tokenize input text
 */
std::vector<QString> TokenizerSelector::tokenize(const QString& text)
{
    std::vector<QString> tokens;
    
    switch (m_selectedTokenizer) {
        case TokenizerType::WordPiece:
            tokens = tokenizeWordPiece(text);
            break;
        case TokenizerType::BPE:
            tokens = tokenizeBPE(text);
            break;
        case TokenizerType::SentencePiece:
            tokens = tokenizeSentencePiece(text);
            break;
        case TokenizerType::CharacterBased:
            tokens = tokenizeCharacter(text);
            break;
        case TokenizerType::Janome:
            tokens = tokenizeJanome(text);
            break;
        case TokenizerType::MeCab:
            tokens = tokenizeMeCab(text);
            break;
        default:
            tokens = {text};
            break;
    }
    
    return tokens;
}

/**
 * @brief TokenizerSelector::tokenizeWordPiece - BERT-style WordPiece tokenization
 */
std::vector<QString> TokenizerSelector::tokenizeWordPiece(const QString& text)
{
    std::vector<QString> tokens;
    
    // Simple word tokenization
    QString current;
    for (int i = 0; i < text.length(); ++i) {
        QChar c = text[i];
        
        if (c.isSpace()) {
            if (!current.isEmpty()) {
                tokens.push_back(current);
                current.clear();
            }
        } else if (c.isPunct()) {
            if (!current.isEmpty()) {
                tokens.push_back(current);
                current.clear();
            }
            tokens.push_back(QString(c));
        } else {
            current += c;
        }
    }
    
    if (!current.isEmpty()) {
        tokens.push_back(current);
    }
    
    // Add subword markers if needed
    std::vector<QString> subwordTokens;
    for (const auto& token : tokens) {
        if (token.length() > 10) {
            // Split long words with ## markers
            subwordTokens.push_back(token.left(5));
            subwordTokens.push_back("##" + token.mid(5));
        } else {
            subwordTokens.push_back(token);
        }
    }
    
    return subwordTokens;
}

/**
 * @brief TokenizerSelector::tokenizeBPE - Byte Pair Encoding tokenization
 */
std::vector<QString> TokenizerSelector::tokenizeBPE(const QString& text)
{
    std::vector<QString> tokens;
    
    // Simple BPE simulation
    QString lower = text.toLower();
    QString current;
    
    for (int i = 0; i < lower.length(); ++i) {
        QChar c = lower[i];
        
        if (c.isSpace()) {
            if (!current.isEmpty()) {
                tokens.push_back(current);
                current.clear();
            }
            tokens.push_back("</w>");  // End of word marker
        } else {
            current += c;
        }
    }
    
    if (!current.isEmpty()) {
        tokens.push_back(current + "</w>");
    }
    
    return tokens;
}

/**
 * @brief TokenizerSelector::tokenizeSentencePiece - SentencePiece tokenization
 */
std::vector<QString> TokenizerSelector::tokenizeSentencePiece(const QString& text)
{
    std::vector<QString> tokens;
    
    // SentencePiece normalizes and segments
    QString normalized = text.toLower();
    
    // Convert to character pieces
    for (const auto& c : normalized) {
        if (c.isSpace()) {
            tokens.push_back("▁");  // Sentencepiece space marker
        } else {
            tokens.push_back(QString(c));
        }
    }
    
    return tokens;
}

/**
 * @brief TokenizerSelector::tokenizeCharacter - Character-level tokenization
 */
std::vector<QString> TokenizerSelector::tokenizeCharacter(const QString& text)
{
    std::vector<QString> tokens;
    
    for (const auto& c : text) {
        tokens.push_back(QString(c));
    }
    
    return tokens;
}

/**
 * @brief TokenizerSelector::tokenizeJanome - Japanese tokenization (Janome)
 */
std::vector<QString> TokenizerSelector::tokenizeJanome(const QString& text)
{
    std::vector<QString> tokens;
    
    // Simplified Japanese tokenization
    // In production, use actual Janome library
    for (const auto& c : text) {
        tokens.push_back(QString(c));
    }
    
    return tokens;
}

/**
 * @brief TokenizerSelector::tokenizeMeCab - Japanese tokenization (MeCab)
 */
std::vector<QString> TokenizerSelector::tokenizeMeCab(const QString& text)
{
    std::vector<QString> tokens;
    
    // Simplified Japanese tokenization
    // In production, use actual MeCab library
    for (const auto& c : text) {
        tokens.push_back(QString(c));
    }
    
    return tokens;
}

/**
 * @brief TokenizerSelector::loadConfiguration - Load configuration from disk
 */
void TokenizerSelector::loadConfiguration()
{
    qDebug() << "[TokenizerSelector] Loading configuration";
    
    try {
        QString configPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                           + "/tokenizer_config.json";
        
        QFile file(configPath);
        if (!file.open(QIODevice::ReadOnly)) {
            qDebug() << "[TokenizerSelector] No existing configuration, using defaults";
            return;
        }
        
        QByteArray data = file.readAll();
        file.close();
        
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonObject obj = doc.object();
        
        m_selectedTokenizer = static_cast<TokenizerType>(obj["tokenizer"].toInt());
        m_selectedLanguage = static_cast<Language>(obj["language"].toInt());
        m_vocabSize = obj["vocabSize"].toInt();
        m_characterCoverage = static_cast<float>(obj["characterCoverage"].toDouble());
        
        qDebug() << "[TokenizerSelector] Configuration loaded";
    }
    catch (const std::exception& e) {
        qWarning() << "[TokenizerSelector] Failed to load configuration:" << e.what();
    }
}

/**
 * @brief TokenizerSelector::exportConfiguration - Export configuration to JSON file
 */
void TokenizerSelector::exportConfiguration()
{
    qDebug() << "[TokenizerSelector] Exporting configuration";
    
    try {
        QString filename = QFileDialog::getSaveFileName(this, "Export Tokenizer Configuration", "",
                                                        "JSON Files (*.json)");
        if (filename.isEmpty()) {
            return;
        }
        
        QJsonObject obj;
        obj["tokenizer"] = static_cast<int>(m_selectedTokenizer);
        obj["language"] = static_cast<int>(m_selectedLanguage);
        obj["vocabSize"] = m_vocabSize;
        obj["characterCoverage"] = m_characterCoverage;
        
        QJsonDocument doc(obj);
        QFile file(filename);
        
        if (!file.open(QIODevice::WriteOnly)) {
            qCritical() << "[TokenizerSelector] Failed to open file for writing";
            return;
        }
        
        file.write(doc.toJson());
        file.close();
        
        qDebug() << "[TokenizerSelector] Configuration exported to" << filename;
    }
    catch (const std::exception& e) {
        qCritical() << "[TokenizerSelector] Export failed:" << e.what();
    }
}

/**
 * @brief TokenizerSelector::importConfiguration - Import configuration from JSON file
 */
void TokenizerSelector::importConfiguration()
{
    qDebug() << "[TokenizerSelector] Importing configuration";
    
    try {
        QString filename = QFileDialog::getOpenFileName(this, "Import Tokenizer Configuration", "",
                                                        "JSON Files (*.json)");
        if (filename.isEmpty()) {
            return;
        }
        
        QFile file(filename);
        if (!file.open(QIODevice::ReadOnly)) {
            qCritical() << "[TokenizerSelector] Failed to open file for reading";
            return;
        }
        
        QByteArray data = file.readAll();
        file.close();
        
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonObject obj = doc.object();
        
        m_selectedTokenizer = static_cast<TokenizerType>(obj["tokenizer"].toInt());
        m_selectedLanguage = static_cast<Language>(obj["language"].toInt());
        m_vocabSize = obj["vocabSize"].toInt();
        m_characterCoverage = static_cast<float>(obj["characterCoverage"].toDouble());
        
        qDebug() << "[TokenizerSelector] Configuration imported from" << filename;
    }
    catch (const std::exception& e) {
        qCritical() << "[TokenizerSelector] Import failed:" << e.what();
    }
}

/**
 * @brief TokenizerSelector::onTokenizerTypeChanged - Handle tokenizer type change
 */
void TokenizerSelector::onTokenizerTypeChanged(int index)
{
    m_selectedTokenizer = static_cast<TokenizerType>(index);
    qDebug() << "[TokenizerSelector] Tokenizer type changed to" << index;
}

/**
 * @brief TokenizerSelector::onLanguageChanged - Handle language change
 */
void TokenizerSelector::onLanguageChanged(int index)
{
    m_selectedLanguage = static_cast<Language>(index);
    qDebug() << "[TokenizerSelector] Language changed to" << index;
}

/**
 * @brief TokenizerSelector::onVocabSizeChanged - Handle vocab size change
 */
void TokenizerSelector::onVocabSizeChanged(int size)
{
    m_vocabSize = size;
    qDebug() << "[TokenizerSelector] Vocab size changed to" << size;
}

/**
 * @brief TokenizerSelector::onCharacterCoverageChanged - Handle character coverage change
 */
void TokenizerSelector::onCharacterCoverageChanged(int coverage)
{
    m_characterCoverage = coverage / 100.0f;
    qDebug() << "[TokenizerSelector] Character coverage changed to" << m_characterCoverage;
}

/**
 * @brief TokenizerSelector::getSelectedTokenizer - Get selected tokenizer type
 */
TokenizerSelector::TokenizerType TokenizerSelector::getSelectedTokenizer() const
{
    return m_selectedTokenizer;
}

/**
 * @brief TokenizerSelector::getSelectedLanguage - Get selected language
 */
TokenizerSelector::Language TokenizerSelector::getSelectedLanguage() const
{
    return m_selectedLanguage;
}

/**
 * @brief TokenizerSelector::getVocabularySize - Get vocabulary size
 */
int TokenizerSelector::getVocabularySize() const
{
    return m_vocabSize;
}

/**
 * @brief TokenizerSelector::getCharacterCoverage - Get character coverage
 */
float TokenizerSelector::getCharacterCoverage() const
{
    return m_characterCoverage;
}
