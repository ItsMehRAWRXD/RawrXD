// Chat Interface - Chat UI component
#include "chat_interface.h"
#include "agentic_engine.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QDir>
#include <QFileInfo>

ChatInterface::ChatInterface(QWidget* parent) : QWidget(parent), maxMode_(false) {
    QVBoxLayout* layout = new QVBoxLayout(this);
    
    // Header with title
    QLabel* title = new QLabel("Agent Chat", this);
    title->setStyleSheet("font-weight: bold; font-size: 14px;");
    layout->addWidget(title);
    
    // Model selector row
    QHBoxLayout* modelLayout = new QHBoxLayout();
    
    QLabel* modelLabel = new QLabel("Model 1:", this);
    modelLayout->addWidget(modelLabel);
    
    modelSelector_ = new QComboBox(this);
    modelSelector_->setMinimumWidth(200);
    modelSelector_->addItem("No Model Selected");
    loadAvailableModels();
    connect(modelSelector_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ChatInterface::onModelChanged);
    modelLayout->addWidget(modelSelector_);
    
    // Second model selector for dual GGUF loading
    QLabel* model2Label = new QLabel("Model 2:", this);
    modelLayout->addWidget(model2Label);
    
    modelSelector2_ = new QComboBox(this);
    modelSelector2_->setMinimumWidth(200);
    modelSelector2_->addItem("No Model Selected");
    loadAvailableModelsForSecond();
    connect(modelSelector2_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ChatInterface::onModel2Changed);
    modelLayout->addWidget(modelSelector2_);
    
    modelLayout->addStretch();
    
    // Max Mode toggle
    maxModeToggle_ = new QCheckBox("Max Mode", this);
    maxModeToggle_->setToolTip("Enable maximum context and response length");
    connect(maxModeToggle_, &QCheckBox::toggled, this, &ChatInterface::onMaxModeToggled);
    modelLayout->addWidget(maxModeToggle_);
    
    // Refresh models button
    QPushButton* refreshBtn = new QPushButton("🔄", this);
    refreshBtn->setMaximumWidth(30);
    refreshBtn->setToolTip("Refresh model list");
    connect(refreshBtn, &QPushButton::clicked, this, &ChatInterface::refreshModels);
    modelLayout->addWidget(refreshBtn);
    
    layout->addLayout(modelLayout);
    
    // Message history
    message_history_ = new QTextEdit(this);
    message_history_->setReadOnly(true);
    message_history_->setStyleSheet(
        "QTextEdit { background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #3c3c3c; }");
    layout->addWidget(message_history_);
    
    // Input area
    QHBoxLayout* inputLayout = new QHBoxLayout();
    message_input_ = new QLineEdit(this);
    message_input_->setPlaceholderText("Type your message here...");
    message_input_->setStyleSheet(
        "QLineEdit { background-color: #252526; color: #d4d4d4; border: 1px solid #3c3c3c; padding: 5px; }");
    connect(message_input_, &QLineEdit::returnPressed, this, &ChatInterface::sendMessage);
    
    QPushButton* sendButton = new QPushButton("Send", this);
    sendButton->setStyleSheet(
        "QPushButton { background-color: #0e639c; color: white; padding: 5px 15px; border: none; }"
        "QPushButton:hover { background-color: #1177bb; }");
    connect(sendButton, &QPushButton::clicked, this, &ChatInterface::sendMessage);
    
    inputLayout->addWidget(message_input_);
    inputLayout->addWidget(sendButton);
    layout->addLayout(inputLayout);
    
    // Status label
    statusLabel_ = new QLabel("Ready", this);
    statusLabel_->setStyleSheet("color: #888888; font-size: 11px;");
    layout->addWidget(statusLabel_);
}

void ChatInterface::loadAvailableModels() {
    // Check common GGUF model locations
    QStringList searchPaths = {
        "D:/OllamaModels",
        QDir::homePath() + "/.ollama/models",
        QDir::homePath() + "/models",
        "C:/models",
        "./models"
    };
    
    for (const QString& path : searchPaths) {
        QDir dir(path);
        if (dir.exists()) {
            QStringList filters;
            filters << "*.gguf";
            QFileInfoList files = dir.entryInfoList(filters, QDir::Files);
            for (const QFileInfo& file : files) {
                modelSelector_->addItem(file.fileName(), file.absoluteFilePath());
            }
        }
    }
    
    if (modelSelector_->count() == 1) {
        statusLabel_->setText("No GGUF models found. Add models to D:/OllamaModels or ~/models");
    }
}

void ChatInterface::refreshModels() {
    QString currentModel = modelSelector_->currentData().toString();
    QString currentModel2 = modelSelector2_->currentData().toString();
    
    modelSelector_->clear();
    modelSelector_->addItem("No Model Selected");
    loadAvailableModels();
    
    modelSelector2_->clear();
    modelSelector2_->addItem("No Model Selected");
    loadAvailableModelsForSecond();
    
    // Try to restore previous selections
    int idx = modelSelector_->findData(currentModel);
    if (idx >= 0) {
        modelSelector_->setCurrentIndex(idx);
    }
    
    int idx2 = modelSelector2_->findData(currentModel2);
    if (idx2 >= 0) {
        modelSelector2_->setCurrentIndex(idx2);
    }
    
    statusLabel_->setText("Model list refreshed");
}

void ChatInterface::onModelChanged(int index) {
    if (index > 0) {
        QString modelPath = modelSelector_->currentData().toString();
        QString modelName = modelSelector_->currentText();
        statusLabel_->setText("Selected: " + modelName);
        emit modelSelected(modelPath);
    } else {
        statusLabel_->setText("No model selected");
    }
}

void ChatInterface::onMaxModeToggled(bool enabled) {
    maxMode_ = enabled;
    if (enabled) {
        statusLabel_->setText("Max Mode enabled - Extended context and responses");
    } else {
        statusLabel_->setText("Standard mode");
    }
    emit maxModeChanged(enabled);
}

void ChatInterface::loadAvailableModelsForSecond() {
    // Check common GGUF model locations
    QStringList searchPaths = {
        "D:/OllamaModels",
        QDir::homePath() + "/.ollama/models",
        QDir::homePath() + "/models",
        "C:/models",
        "./models"
    };
    
    for (const QString& path : searchPaths) {
        QDir dir(path);
        if (dir.exists()) {
            QStringList filters;
            filters << "*.gguf";
            QFileInfoList files = dir.entryInfoList(filters, QDir::Files);
            for (const QFileInfo& file : files) {
                modelSelector2_->addItem(file.fileName(), file.absoluteFilePath());
            }
        }
    }
}

void ChatInterface::onModel2Changed(int index) {
    if (index > 0) {
        QString modelPath = modelSelector2_->currentData().toString();
        QString modelName = modelSelector2_->currentText();
        statusLabel_->setText("Model 2 selected: " + modelName);
        emit model2Selected(modelPath);
    } else {
        statusLabel_->setText("No secondary model selected");
    }
}

QString ChatInterface::selectedModel() const {
    return modelSelector_->currentData().toString();
}

bool ChatInterface::isMaxMode() const {
    return maxMode_;
}

void ChatInterface::addMessage(const QString& sender, const QString& message) {
    QString color = (sender == "User") ? "#569cd6" : "#4ec9b0";
    message_history_->append("<span style='color:" + color + ";font-weight:bold;'>" + sender + ":</span> " + message);
}

void ChatInterface::displayResponse(const QString& response) {
    addMessage("Agent", response);
    statusLabel_->setText("Response received");
}

void ChatInterface::focusInput() {
    message_input_->setFocus();
}

void ChatInterface::sendMessage() {
    QString message = message_input_->text().trimmed();
    if (!message.isEmpty()) {
        addMessage("User", message);
        statusLabel_->setText("Processing...");
        
        // Check if this is an agent command
        if (isAgentCommand(message)) {
            executeAgentCommand(message);
        } else {
            emit messageSent(message);
        }
        
        message_input_->clear();
    }
}

bool ChatInterface::isAgentCommand(const QString& message) const {
    // Commands start with @ or use known keywords
    return message.startsWith("@") || 
           message.startsWith("grep ") ||
           message.startsWith("read ") ||
           message.startsWith("search ") ||
           message.startsWith("ref ");
}

void ChatInterface::executeAgentCommand(const QString& command, const QString& args) {
    Q_UNUSED(args);  // Currently using command parsing instead
    
    if (!m_agenticEngine) {
        addMessage("System", "Agentic Engine not initialized");
        statusLabel_->setText("Agent error: Engine not ready");
        return;
    }
    
    QString response;
    
    // Parse and execute agent commands
    if (command.startsWith("@grep ")) {
        QString pattern = command.mid(6).trimmed();
        response = m_agenticEngine->grepFiles(pattern, ".");
        addMessage("Agent", response);
    } 
    else if (command.startsWith("@read ")) {
        QString filepath = command.mid(6).trimmed();
        response = m_agenticEngine->readFile(filepath);
        addMessage("Agent", response);
    } 
    else if (command.startsWith("@search ")) {
        QString query = command.mid(8).trimmed();
        response = m_agenticEngine->searchFiles(query, ".");
        addMessage("Agent", response);
    } 
    else if (command.startsWith("@ref ")) {
        QString symbol = command.mid(5).trimmed();
        response = m_agenticEngine->referenceSymbol(symbol);
        addMessage("Agent", response);
    }
    else if (command.startsWith("grep ")) {
        // Support without @ prefix
        QString pattern = command.mid(5).trimmed();
        response = m_agenticEngine->grepFiles(pattern, ".");
        addMessage("Agent", response);
    }
    else if (command.startsWith("read ")) {
        QString filepath = command.mid(5).trimmed();
        response = m_agenticEngine->readFile(filepath);
        addMessage("Agent", response);
    }
    else if (command.startsWith("search ")) {
        QString query = command.mid(7).trimmed();
        response = m_agenticEngine->searchFiles(query, ".");
        addMessage("Agent", response);
    }
    else if (command.startsWith("ref ")) {
        QString symbol = command.mid(4).trimmed();
        response = m_agenticEngine->referenceSymbol(symbol);
        addMessage("Agent", response);
    }
    else {
        response = "Unknown agent command. Available commands:\n"
                   "  @grep <pattern> - Search for text pattern in files\n"
                   "  @read <filepath> - Read file contents\n"
                   "  @search <query> - Search for files matching query\n"
                   "  @ref <symbol> - Find symbol references and definitions";
        addMessage("System", response);
    }
    
    statusLabel_->setText("Agent command executed");
}

