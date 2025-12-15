#include "ai_chat_panel.hpp"
#include <QDateTime>
#include <QScrollBar>
#include <QSyntaxHighlighter>
#include <QTextDocument>
#include <QHBoxLayout>
#include <QFont>
#include <QFontMetrics>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

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
    
    // Assembly
    mainLayout->addWidget(header);
    mainLayout->addWidget(m_quickActionsWidget);
    mainLayout->addWidget(m_scrollArea, 1);
    mainLayout->addWidget(inputContainer);
    
    setLayout(mainLayout);

    // Networking setup
    if (!m_network) {
        m_network = new QNetworkAccessManager(this);
        connect(m_network, &QNetworkAccessManager::finished, this, &AIChatPanel::onNetworkFinished);
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
    
    addUserMessage(message);
    m_inputField->clear();
    
    emit messageSubmitted(message);
    sendMessageToBackend(message);
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

    QNetworkRequest req(QUrl(endpoint));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (useCloud) {
        req.setRawHeader("Authorization", QByteArray("Bearer ") + m_apiKey.toUtf8());
    }

    const QByteArray payload = useCloud ? buildCloudPayload(message) : buildLocalPayload(message);

    QNetworkReply* reply = m_network->post(req, payload);
    reply->setProperty("_msg_ts", QDateTime::currentMSecsSinceEpoch());
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
    // Ollama-like schema
    QJsonObject root;
    root["model"] = "llama3.1";
    root["prompt"] = message;
    root["stream"] = false;
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QString AIChatPanel::extractAssistantText(const QJsonDocument& doc) const
{
    // Try OpenAI-style first
    auto obj = doc.object();
    if (obj.contains("choices")) {
        auto arr = obj["choices"].toArray();
        if (!arr.isEmpty()) {
            auto msg = arr[0].toObject()["message"].toObject();
            return msg["content"].toString();
        }
    }
    // Try Ollama-like
    if (obj.contains("response")) return obj["response"].toString();
    // Fallback
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
    QJsonParseError perr; QJsonDocument doc = QJsonDocument::fromJson(body, &perr);
    if (perr.error != QJsonParseError::NoError) {
        qWarning() << "AIChatPanel parse error:" << perr.errorString();
        addAssistantMessage(QString::fromUtf8(body), false);
    } else {
        const QString text = extractAssistantText(doc);
        addAssistantMessage(text.isEmpty() ? QString::fromUtf8(body) : text, false);
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
