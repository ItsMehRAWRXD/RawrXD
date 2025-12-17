#include "ai_chat_panel.hpp"
#include <QDateTime>
#include <QScrollBar>
#include <QSyntaxHighlighter>
#include <QTextDocument>
#include <QHBoxLayout>
#include <QFont>
#include <QFontMetrics>
#include <QUrl>
#include <QNetworkRequest>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QComboBox>
#include <algorithm>

AIChatPanel::AIChatPanel(QWidget* parent)
    : QWidget(parent)
{
    // Lazy initialization - defer all Qt widget creation
    // Configuration will be set up when initialize() is called
    qDebug() << "AIChatPanel created with lazy initialization - D: \\temp location";
}

void AIChatPanel::initialize() {
    if (m_initialized) return;  // Already initialized
    
    // Initialize configuration with defaults
    m_cloudEnabled = false;
    m_localEnabled = true; // Default to local
    m_cloudEndpoint = "https://api.openai.com/v1/chat/completions";
    m_localEndpoint = "http://localhost:11434/api/generate";
    m_apiKey = QString();
    m_requestTimeout = 30000;
    
    // Create Qt widgets
    setupUI();
    applyDarkTheme();
    
    m_initialized = true;
    m_widgetsCreated = true;
    
    // Fetch available models asynchronously after UI is ready
    QTimer::singleShot(100, this, &AIChatPanel::fetchAvailableModels);
    
    qDebug() << "AIChatPanel initialized with lazy loading - D: \\temp location";
}

void AIChatPanel::setupUI()
{
    if (m_widgetsCreated) {
        qWarning() << "UI already setup - skipping";
        return;
    }
    
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);
    
    // Agent chat breadcrumb with mode and model selector
    m_breadcrumb = new AgentChatBreadcrumb(this);
    m_breadcrumb->initialize();
    mainLayout->addWidget(m_breadcrumb);
    
    // Connect breadcrumb signals to this panel
    connect(m_breadcrumb, &AgentChatBreadcrumb::agentModeChanged,
            this, [this](AgentChatBreadcrumb::AgentMode mode) {
                emit agentModeChanged(static_cast<int>(mode));
                qDebug() << "[AIChatPanel] Agent mode changed to:" << static_cast<int>(mode);
            });
    
    connect(m_breadcrumb, &AgentChatBreadcrumb::modelSelected,
            this, [this](const QString& modelName) {
                setSelectedModel(modelName);
                emit modelSelected(modelName);
                qDebug() << "[AIChatPanel] Model selected:" << modelName;
            });
    
    // Header
    QLabel* header = new QLabel("  AI Assistant", this);
    QFont headerFont = header->font();
    headerFont.setPointSize(11);
    headerFont.setBold(true);
    header->setFont(headerFont);
    header->setMinimumHeight(35);
    
    // Quick actions
    m_quickActionsWidget = createQuickActions();
    
    // Messages scroll area
    m_scrollArea = new QScrollArea(this);
    m_scrollArea->setWidgetResizable(true);
    m_scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scrollArea->setFrameStyle(QFrame::NoFrame);
    
    m_messagesContainer = new QWidget();
    m_messagesLayout = new QVBoxLayout(m_messagesContainer);
    m_messagesLayout->setContentsMargins(10, 10, 10, 10);
    m_messagesLayout->setSpacing(10);
    m_messagesLayout->addStretch();
    
    m_scrollArea->setWidget(m_messagesContainer);
    
    // Input area
    QWidget* inputContainer = new QWidget(this);
    QHBoxLayout* inputLayout = new QHBoxLayout(inputContainer);
    inputLayout->setContentsMargins(10, 8, 10, 8);
    inputLayout->setSpacing(8);
    
    m_inputField = new QLineEdit(inputContainer);
    m_inputField->setPlaceholderText("Ask AI anything...");
    m_inputField->setMinimumHeight(32);
    
    connect(m_inputField, &QLineEdit::returnPressed,
            this, &AIChatPanel::onSendClicked);
    
    m_sendButton = new QPushButton("Send", inputContainer);
    m_sendButton->setMinimumWidth(70);
    m_sendButton->setMaximumHeight(32);
    
    connect(m_sendButton, &QPushButton::clicked,
            this, &AIChatPanel::onSendClicked);
    
    inputLayout->addWidget(m_inputField);
    inputLayout->addWidget(m_sendButton);
    
    // Model selector  
    QWidget* modelContainer = new QWidget(this);
    QHBoxLayout* modelLayout = new QHBoxLayout(modelContainer);
    modelLayout->setContentsMargins(10, 5, 10, 5);
    modelLayout->setSpacing(8);
    
    QLabel* modelLabel = new QLabel("Model:", modelContainer);
    modelLabel->setMinimumWidth(50);
    
    m_modelSelector = new QComboBox(modelContainer);
    m_modelSelector->setMinimumHeight(28);
    m_modelSelector->addItem("Loading models...");
    connect(m_modelSelector, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AIChatPanel::onModelSelected);
    
    modelLayout->addWidget(modelLabel);
    modelLayout->addWidget(m_modelSelector, 1);
    
    // Assembly
    mainLayout->addWidget(header);
    mainLayout->addWidget(m_quickActionsWidget);
    mainLayout->addWidget(m_scrollArea, 1);
    mainLayout->addWidget(modelContainer);
    mainLayout->addWidget(inputContainer);
    
    setLayout(mainLayout);

    // Networking setup
    if (!m_network) {
        m_network = new QNetworkAccessManager(this);
        // Note: Individual replies connect their own finished signals
    }
}

QWidget* AIChatPanel::createQuickActions()
{
    QWidget* container = new QWidget(this);
    QHBoxLayout* layout = new QHBoxLayout(container);
    layout->setContentsMargins(10, 5, 10, 5);
    layout->setSpacing(5);
    
    QStringList actions = {"Explain", "Fix", "Refactor", "Document", "Test"};
    
    for (const QString& action : actions) {
        QPushButton* btn = new QPushButton(action, container);
        btn->setMaximumHeight(26);
        btn->setFlat(true);
        btn->setCursor(Qt::PointingHandCursor);
        
        connect(btn, &QPushButton::clicked, this, [this, action]() {
            onQuickActionClicked(action);
        });
        
        layout->addWidget(btn);
    }
    
    layout->addStretch();
    
    return container;
}

void AIChatPanel::applyDarkTheme()
{
    QString styleSheet = R"(
        AIChatPanel {
            background-color: #1e1e1e;
        }
        QLabel {
            background-color: #252526;
            color: #cccccc;
            border-bottom: 1px solid #3e3e42;
        }
        QScrollArea {
            background-color: #1e1e1e;
            border: none;
        }
        QLineEdit {
            background-color: #3c3c3c;
            color: #cccccc;
            border: 1px solid #3e3e42;
            border-radius: 4px;
            padding: 6px 10px;
            selection-background-color: #094771;
        }
        QLineEdit:focus {
            border: 1px solid #007acc;
        }
        QPushButton {
            background-color: #0e639c;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #1177bb;
        }
        QPushButton:pressed {
            background-color: #0d5a8f;
        }
        QPushButton[flat="true"] {
            background-color: #2d2d30;
            color: #cccccc;
            font-weight: normal;
        }
        QPushButton[flat="true"]:hover {
            background-color: #3e3e42;
        }
        QTextEdit {
            background-color: transparent;
            color: #cccccc;
            border: none;
            selection-background-color: #094771;
        }
    )";
    
    setStyleSheet(styleSheet);
}

void AIChatPanel::addUserMessage(const QString& message)
{
    if (!m_initialized) {
        qWarning() << "AIChatPanel not initialized - cannot add message";
        return;
    }
    
    Message msg;
    msg.role = Message::User;
    msg.content = message;
    msg.timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    
    m_messages.append(msg);
    
    QWidget* bubble = createMessageBubble(msg);
    m_messagesLayout->insertWidget(m_messagesLayout->count() - 1, bubble);
    
    scrollToBottom();
}

void AIChatPanel::addAssistantMessage(const QString& message, bool streaming)
{
    if (!m_initialized) {
        qWarning() << "AIChatPanel not initialized - cannot add assistant message";
        return;
    }
    
    Message msg;
    msg.role = Message::Assistant;
    msg.content = message;
    msg.timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    msg.isStreaming = streaming;
    
    m_messages.append(msg);
    
    QWidget* bubble = createMessageBubble(msg);
    m_messagesLayout->insertWidget(m_messagesLayout->count() - 1, bubble);
    
    if (streaming) {
        m_streamingBubble = bubble;
        m_streamingText = bubble->findChild<QTextEdit*>();
    }
    
    scrollToBottom();
}

void AIChatPanel::updateStreamingMessage(const QString& content)
{
    if (m_streamingText) {
        m_streamingText->setPlainText(content);
        scrollToBottom();
    }
}

void AIChatPanel::finishStreaming()
{
    m_streamingBubble = nullptr;
    m_streamingText = nullptr;
}

QWidget* AIChatPanel::createMessageBubble(const Message& msg)
{
    QWidget* container = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(4);
    
    // Role label
    QLabel* roleLabel = new QLabel(
        msg.role == Message::User ? "You" : "AI Assistant"
    );
    QFont roleFont = roleLabel->font();
    roleFont.setPointSize(9);
    roleFont.setBold(true);
    roleLabel->setFont(roleFont);
    
    QString roleLabelStyle = QString(
        "QLabel { background-color: transparent; color: %1; border: none; }"
    ).arg(msg.role == Message::User ? "#569cd6" : "#4ec9b0");
    roleLabel->setStyleSheet(roleLabelStyle);
    
    // Message content
    QTextEdit* contentEdit = new QTextEdit();
    contentEdit->setPlainText(msg.content);
    contentEdit->setReadOnly(true);
    contentEdit->setFrameStyle(QFrame::NoFrame);
    contentEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    contentEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    
    // Calculate height based on content
    QFontMetrics fm(contentEdit->font());
    int lineHeight = fm.lineSpacing();
    int numLines = msg.content.split('\n').count();
    int estimatedHeight = numLines * lineHeight + 20;
    contentEdit->setMaximumHeight(std::min(estimatedHeight, 300));
    
    QString bubbleStyle = QString(
        "QTextEdit { background-color: %1; border-radius: 8px; padding: 8px; }"
    ).arg(msg.role == Message::User ? "#2d2d30" : "#1a1a1a");
    contentEdit->setStyleSheet(bubbleStyle);
    
    // Timestamp
    QLabel* timeLabel = new QLabel(msg.timestamp);
    QFont timeFont = timeLabel->font();
    timeFont.setPointSize(8);
    timeLabel->setFont(timeFont);
    timeLabel->setStyleSheet("QLabel { background-color: transparent; color: #858585; border: none; }");
    
    layout->addWidget(roleLabel);
    layout->addWidget(contentEdit);
    layout->addWidget(timeLabel, 0, msg.role == Message::User ? Qt::AlignRight : Qt::AlignLeft);
    
    return container;
}

void AIChatPanel::onSendClicked()
{
    QString message = m_inputField->text().trimmed();
    if (message.isEmpty()) return;
    
    // Validate model is selected
    if (m_localModel.isEmpty()) {
        addAssistantMessage("Please select a model from the dropdown first.", false);
        qWarning() << "Message sent but no model selected";
        return;
    }
    
    addUserMessage(message);
    m_inputField->clear();
    
    emit messageSubmitted(message);
    
    // Check if message is an agentic request
    if (isAgenticRequest(message)) {
        // Classify intent and route to agentic processing
        MessageIntent intent = classifyMessageIntent(message);
        processAgenticMessage(message, intent);
    } else {
        // Simple chat message - send to model normally
        sendMessageToBackend(message);
    }
}

void AIChatPanel::onQuickActionClicked(const QString& action)
{
    emit quickActionTriggered(action, m_contextCode);
}

void AIChatPanel::setCloudConfiguration(bool enabled, const QString& endpoint, const QString& apiKey) {
    if (!m_initialized) {
        qWarning() << "AIChatPanel not initialized before setting cloud configuration";
        return;
    }
    
    m_cloudEnabled = enabled;
    m_cloudEndpoint = endpoint;
    m_apiKey = apiKey;
    
    qDebug() << "Cloud configuration updated - Enabled:" << enabled 
             << "Endpoint:" << endpoint;
}

void AIChatPanel::setLocalConfiguration(bool enabled, const QString& endpoint) {
    if (!m_initialized) {
        qWarning() << "AIChatPanel not initialized before setting local configuration";
        return;
    }
    
    m_localEnabled = enabled;
    m_localEndpoint = endpoint;
    
    qDebug() << "Local configuration updated - Enabled:" << enabled 
             << "Endpoint:" << endpoint;
}

void AIChatPanel::setLocalModel(const QString& modelName) {
    m_localModel = modelName;
    qDebug() << "Local model set to:" << modelName;
}

void AIChatPanel::setRequestTimeout(int timeoutMs) {
    if (!m_initialized) {
        qWarning() << "AIChatPanel not initialized before setting timeout";
        return;
    }
    
    m_requestTimeout = timeoutMs;
    qDebug() << "Request timeout set to:" << timeoutMs << "ms";
}

void AIChatPanel::clear()
{
    // Remove all message widgets except the stretch
    while (m_messagesLayout->count() > 1) {
        QLayoutItem* item = m_messagesLayout->takeAt(0);
        if (item->widget()) {
            delete item->widget();
        }
        delete item;
    }
    
    m_messages.clear();
    m_streamingBubble = nullptr;
    m_streamingText = nullptr;
}

void AIChatPanel::scrollToBottom()
{
    QScrollBar* scrollBar = m_scrollArea->verticalScrollBar();
    scrollBar->setValue(scrollBar->maximum());
}

void AIChatPanel::setContext(const QString& code, const QString& filePath)
{
    m_contextCode = code;
    m_contextFilePath = filePath;
    qDebug() << "AIChatPanel context set for file:" << filePath
             << " code length:" << code.length();
}

void AIChatPanel::sendMessageToBackend(const QString& message)
{
    if (!m_initialized) {
        qWarning() << "AIChatPanel sendMessageToBackend called before initialize";
        return;
    }

    const bool useCloud = m_cloudEnabled && !m_apiKey.isEmpty();
    const QString endpoint = useCloud ? m_cloudEndpoint : m_localEndpoint;

    QNetworkRequest* req = new QNetworkRequest(QUrl(endpoint));
    req->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (useCloud) {
        req->setRawHeader("Authorization", QByteArray("Bearer ") + m_apiKey.toUtf8());
    }

    const QByteArray payload = useCloud ? buildCloudPayload(message) : buildLocalPayload(message);

    QNetworkReply* reply = m_network->post(*req, payload);
    delete req;  // Delete after posting
    reply->setProperty("_msg_ts", QDateTime::currentMSecsSinceEpoch());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        onNetworkFinished(reply);
    });
    connect(reply, &QNetworkReply::errorOccurred, this, &AIChatPanel::onNetworkError);

    // timeout guard
    QTimer::singleShot(m_requestTimeout, this, [reply]() {
        if (reply->isRunning()) reply->abort();
    });
}

QByteArray AIChatPanel::buildCloudPayload(const QString& message) const
{
    QJsonObject root;
    root["model"] = "gpt-4o-mini"; // configurable if needed
    QJsonArray msgs;
    QJsonObject sys; sys["role"] = "system"; sys["content"] = "You are a helpful assistant."; msgs.append(sys);
    QJsonObject usr; usr["role"] = "user"; usr["content"] = message; msgs.append(usr);
    root["messages"] = msgs;
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QByteArray AIChatPanel::buildLocalPayload(const QString& message) const
{
    // Ollama-like schema - use selected model or default
    QJsonObject root;
    root["model"] = m_localModel.isEmpty() ? "llama3.1" : m_localModel;
    root["prompt"] = message;
    root["stream"] = false;
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QString AIChatPanel::extractAssistantText(const QJsonDocument& doc) const
{
    QString extractedText;
    auto obj = doc.object();
    
    // Try OpenAI-style response (choices array)
    if (obj.contains("choices")) {
        auto arr = obj["choices"].toArray();
        if (!arr.isEmpty()) {
            auto choice = arr[0].toObject();
            
            // Try message.content first
            if (choice.contains("message")) {
                auto msg = choice["message"].toObject();
                extractedText = msg["content"].toString();
                if (!extractedText.isEmpty()) return extractedText;
            }
            
            // Try direct text field
            if (choice.contains("text")) {
                extractedText = choice["text"].toString();
                if (!extractedText.isEmpty()) return extractedText;
            }
        }
    }
    
    // Try Ollama response format
    if (obj.contains("response")) {
        extractedText = obj["response"].toString();
        if (!extractedText.isEmpty()) return extractedText;
    }
    
    // Try direct 'text' field
    if (obj.contains("text")) {
        extractedText = obj["text"].toString();
        if (!extractedText.isEmpty()) return extractedText;
    }
    
    // Try 'generated_text' field (HuggingFace style)
    if (obj.contains("generated_text")) {
        extractedText = obj["generated_text"].toString();
        if (!extractedText.isEmpty()) return extractedText;
    }
    
    // Try 'output' field
    if (obj.contains("output")) {
        extractedText = obj["output"].toString();
        if (!extractedText.isEmpty()) return extractedText;
    }
    
    // Try 'result' field
    if (obj.contains("result")) {
        auto result = obj["result"];
        if (result.isObject()) {
            auto resultObj = result.toObject();
            if (resultObj.contains("text")) {
                return resultObj["text"].toString();
            }
        } else if (result.isString()) {
            return result.toString();
        }
    }
    
    // Fallback: return empty - caller will use raw body
    return QString();
}

void AIChatPanel::onNetworkFinished(QNetworkReply* reply)
{
    const qint64 start = reply->property("_msg_ts").toLongLong();
    const qint64 dur = start > 0 ? (QDateTime::currentMSecsSinceEpoch() - start) : -1;
    
    if (reply->error() != QNetworkReply::NoError) {
        qWarning() << "AIChatPanel network error on finish:" << reply->error() << reply->errorString();
        addAssistantMessage(QString("Error: %1").arg(reply->errorString()), false);
        reply->deleteLater();
        return;
    }
    
    const QByteArray body = reply->readAll();
    
    if (body.isEmpty()) {
        qWarning() << "AIChatPanel received empty response";
        addAssistantMessage("No response from model. Please try again.", false);
        reply->deleteLater();
        return;
    }
    
    // Log response for debugging
    qDebug() << "AIChatPanel raw response (first 200 chars):" << body.left(200);
    
    // Try to parse as JSON
    QJsonParseError perr;
    QJsonDocument doc = QJsonDocument::fromJson(body, &perr);
    
    QString responseText;
    
    if (perr.error == QJsonParseError::NoError && doc.isObject()) {
        // Successfully parsed JSON - extract text
        responseText = extractAssistantText(doc);
        
        if (responseText.isEmpty()) {
            qDebug() << "Could not extract text from JSON, using raw body";
            responseText = QString::fromUtf8(body);
        }
    } else {
        // Not valid JSON - use raw text response
        qDebug() << "JSON parse error:" << perr.errorString() << "- treating as raw response";
        responseText = QString::fromUtf8(body);
    }
    
    // Clean up tokenization artifacts and show response
    if (!responseText.isEmpty()) {
        addAssistantMessage(responseText, false);
        qDebug() << "Response added to chat (length:" << responseText.length() << "chars)";
    } else {
        qWarning() << "Empty response after processing";
        addAssistantMessage("Empty response from model. Check model configuration.", false);
    }
    
    if (dur >= 0) qDebug() << "AIChatPanel request latency ms:" << dur;
    reply->deleteLater();
}

void AIChatPanel::onNetworkError(QNetworkReply::NetworkError code)
{
    QNetworkReply* r = qobject_cast<QNetworkReply*>(sender());
    if (!r) return;
    qWarning() << "AIChatPanel network error:" << code << r->errorString();
}

void AIChatPanel::setInputEnabled(bool enabled)
{
    if (m_inputField) {
        m_inputField->setEnabled(enabled);
        qDebug() << "AIChatPanel input field" << (enabled ? "enabled" : "disabled");
    }
    if (m_sendButton) {
        m_sendButton->setEnabled(enabled);
    }
}

void AIChatPanel::fetchAvailableModels()
{
    if (!m_network) {
        qWarning() << "Network manager not initialized";
        return;
    }
    
    if (m_localEnabled && !m_localEndpoint.isEmpty()) {
        QString endpoint = m_localEndpoint;
        if (endpoint.endsWith("/api/generate")) {
            endpoint = endpoint.left(endpoint.length() - 13);
        }
        if (!endpoint.endsWith("/")) endpoint += "/";
        endpoint += "api/tags";
        
        qDebug() << "Fetching Ollama models from:" << endpoint;
        
        QNetworkRequest* req = new QNetworkRequest(QUrl(endpoint));
        req->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        
        QNetworkReply* reply = m_network->get(*req);
        delete req;  // Delete after requesting
        if (!reply) {
            qWarning() << "Failed to create model list request";
            return;
        }
        
        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            onModelsListFetched(reply);
        });
    }
}

void AIChatPanel::onModelsListFetched(QNetworkReply* reply)
{
    if (!reply) return;
    
    if (reply->error() != QNetworkReply::NoError) {
        qWarning() << "Failed to fetch models:" << reply->errorString();
        if (m_modelSelector) {
            m_modelSelector->blockSignals(true);
            m_modelSelector->clear();
            m_modelSelector->addItem("Error loading models");
            m_modelSelector->blockSignals(false);
        }
        reply->deleteLater();
        return;
    }
    
    QByteArray data = reply->readAll();
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    
    if (err.error != QJsonParseError::NoError) {
        qWarning() << "Failed to parse models JSON:" << err.errorString();
        reply->deleteLater();
        return;
    }
    
    if (!m_modelSelector) {
        reply->deleteLater();
        return;
    }
    
    m_modelSelector->blockSignals(true);
    m_modelSelector->clear();
    
    QJsonArray models = doc.object().value("models").toArray();
    
    // Sort models by size (largest first)
    QVector<QPair<QString, QJsonObject>> sortedModels;
    for (const QJsonValue& modelVal : models) {
        QJsonObject modelObj = modelVal.toObject();
        sortedModels.append({modelObj.value("name").toString(), modelObj});
    }
    
    std::sort(sortedModels.begin(), sortedModels.end(), 
        [](const auto& a, const auto& b) {
            return a.second.value("size").toInt() > b.second.value("size").toInt();
        });
    
    // Add models with metadata
    for (const auto& [modelName, modelObj] : sortedModels) {
        if (!modelName.isEmpty()) {
            QJsonObject details = modelObj.value("details").toObject();
            QString params = details.value("parameter_size").toString("?");
            QString quant = details.value("quantization_level").toString("?");
            qint64 size = modelObj.value("size").toInt();
            
            QString sizeStr;
            if (size > 1e9) {
                sizeStr = QString::number(size / 1e9, 'f', 1) + "GB";
            } else if (size > 1e6) {
                sizeStr = QString::number(size / 1e6, 'f', 0) + "MB";
            } else {
                sizeStr = QString::number(size / 1e3, 'f', 0) + "KB";
            }
            
            QString displayText = QString("%1 [%2, %3, %4]")
                .arg(modelName).arg(params).arg(quant).arg(sizeStr);
            
            m_modelSelector->addItem(displayText, modelName);
            qDebug() << "Added model:" << modelName << "Size:" << sizeStr;
        }
    }
    
    if (m_modelSelector->count() == 0) {
        m_modelSelector->addItem("No models available");
        m_modelSelector->blockSignals(false);
    } else {
        // Do NOT auto-select - user must explicitly choose a model
        // Default to first available model showing prompt text
        m_modelSelector->insertItem(0, "Select a model...", "");
        m_modelSelector->setCurrentIndex(0);
        m_modelSelector->blockSignals(false);
        qDebug() << "Model list ready - user must explicitly select";
    }
    
    setInputEnabled(false);  // Disable chat until model is selected
    qDebug() << "Loaded" << m_modelSelector->count() << "models";
    
    reply->deleteLater();
}

void AIChatPanel::onModelSelected(int index)
{
    if (!m_modelSelector || index < 0) return;
    
    QString model = m_modelSelector->itemData(index).toString();
    if (model.isEmpty()) model = m_modelSelector->currentText();
    
    // Only process valid model selections
    if (model.isEmpty() || model == "Loading models..." || 
        model == "Error loading models" || model == "No models available" ||
        model == "Select a model...") {
        qWarning() << "Invalid model selected:" << model;
        setInputEnabled(false);  // Disable chat until valid model selected
        return;
    }
    
    // Valid model - save and enable chat
    setLocalModel(model);
    setInputEnabled(true);  // Enable chat input now that model is ready
    
    qDebug() << "Model successfully selected and ready:" << model;
}

void AIChatPanel::setSelectedModel(const QString& modelName)
{
    if (!m_modelSelector) return;
    
    for (int i = 0; i < m_modelSelector->count(); ++i) {
        if (m_modelSelector->itemData(i).toString() == modelName) {
            m_modelSelector->setCurrentIndex(i);
            return;
        }
    }
}

bool AIChatPanel::isAgenticRequest(const QString& message) const
{
    // Detect action verbs and intent patterns that suggest agentic processing
    QStringList agenticKeywords = {
        "create", "write", "modify", "delete", "fix", "build", "compile",
        "run", "execute", "analyze", "debug", "refactor", "optimize",
        "implement", "generate", "rename", "move", "copy", "search",
        "replace", "add", "remove", "update", "setup", "install",
        "please", "can you", "would you", "could you", "i need you to"
    };
    
    QString lowerMsg = message.toLower();
    
    // Check if message contains agentic keywords
    for (const QString& keyword : agenticKeywords) {
        if (lowerMsg.contains(keyword)) {
            return true;
        }
    }
    
    // Check for technical patterns (file paths, commands, code)
    if (lowerMsg.contains("if ") || lowerMsg.contains("then ") || 
        lowerMsg.contains("function") || lowerMsg.contains("class ") ||
        lowerMsg.contains(".cpp") || lowerMsg.contains(".hpp") ||
        lowerMsg.contains(".py") || lowerMsg.contains("//") ||
        lowerMsg.contains("/*")) {
        return true;
    }
    
    return false;
}

AIChatPanel::MessageIntent AIChatPanel::classifyMessageIntent(const QString& message)
{
    QString lowerMsg = message.toLower();
    
    // Check for code editing intent
    if (lowerMsg.contains("create") || lowerMsg.contains("write") ||
        lowerMsg.contains("modify") || lowerMsg.contains("refactor") ||
        lowerMsg.contains(".cpp") || lowerMsg.contains(".hpp") ||
        lowerMsg.contains("class") || lowerMsg.contains("function")) {
        return CodeEdit;
    }
    
    // Check for tool use intent
    if (lowerMsg.contains("build") || lowerMsg.contains("compile") ||
        lowerMsg.contains("run") || lowerMsg.contains("execute") ||
        lowerMsg.contains("cmd") || lowerMsg.contains("terminal") ||
        lowerMsg.contains("git") || lowerMsg.contains("make")) {
        return ToolUse;
    }
    
    // Check for planning intent
    if (lowerMsg.contains("plan") || lowerMsg.contains("design") ||
        lowerMsg.contains("architecture") || lowerMsg.contains("steps") ||
        lowerMsg.contains("approach") || lowerMsg.contains("strategy")) {
        return Planning;
    }
    
    // Check if it's just a question/chat
    if (lowerMsg.endsWith("?") || lowerMsg.contains("what ") ||
        lowerMsg.contains("how ") || lowerMsg.contains("why ") ||
        lowerMsg.contains("explain")) {
        return Chat;
    }
    
    return Unknown;
}

void AIChatPanel::processAgenticMessage(const QString& message, MessageIntent intent)
{
    // Log the intent classification
    QString intentStr;
    switch (intent) {
        case CodeEdit: intentStr = "CODE_EDIT"; break;
        case ToolUse: intentStr = "TOOL_USE"; break;
        case Planning: intentStr = "PLANNING"; break;
        case Chat: intentStr = "CHAT"; break;
        default: intentStr = "UNKNOWN"; break;
    }
    
    qDebug() << "Agentic message classified as:" << intentStr;
    addAssistantMessage(QString("[Processing agentic request as %1...]").arg(intentStr), false);
    
    // If we have an agentic executor, use it for autonomous execution
    if (m_agenticExecutor) {
        qDebug() << "Routing to AgenticExecutor for autonomous execution";
        QJsonObject result = m_agenticExecutor->executeUserRequest(message);
        
        // Parse result and display
        if (result.contains("success") && result["success"].toBool()) {
            QString output = result["output"].toString();
            if (!output.isEmpty()) {
                addAssistantMessage(output, false);
            }
        } else {
            QString error = result.contains("error") ? result["error"].toString() : QString("Unknown error occurred");
            addAssistantMessage(QString("Error: %1").arg(error), false);
        }
    } else {
        // Fall back to regular backend processing
        qDebug() << "No agentic executor - falling back to standard model processing";
        sendMessageToBackend(message);
    }
}

void AIChatPanel::setAgenticExecutor(AgenticExecutor* executor)
{
    m_agenticExecutor = executor;
    if (executor) {
        qDebug() << "AgenticExecutor connected to AIChatPanel";
    }
}

