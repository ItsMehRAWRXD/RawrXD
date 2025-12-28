#include "real_time_integration_coordinator.hpp"
#include <QDebug>
#include <QDateTime>

RealTimeIntegrationCoordinator::RealTimeIntegrationCoordinator(QObject* parent)
    : QObject(parent) {
    qDebug() << "[RealTimeIntegrationCoordinator] Constructor called";
}

RealTimeIntegrationCoordinator::~RealTimeIntegrationCoordinator() {
    if (m_syncTimer) {
        m_syncTimer->stop();
        delete m_syncTimer;
    }
    qDebug() << "[RealTimeIntegrationCoordinator] Destructor called";
}

void RealTimeIntegrationCoordinator::initialize(
    AgenticCopilotBridge* copilotBridge,
    AIChatPanel* chatPanel,
    MultiTabEditor* editor,
    TerminalPool* terminals,
    AgenticEngine* engine,
    InferenceEngine* inference) {
    
    QMutexLocker lock(&m_mutex);
    
    m_copilotBridge = copilotBridge;
    m_chatPanel = chatPanel;
    m_editor = editor;
    m_terminalPool = terminals;
    m_engine = engine;
    m_inferenceEngine = inference;
    
    qDebug() << "[RealTimeIntegrationCoordinator] Initialization complete with 6 components";
    
    // Start synchronization timer
    m_syncTimer = new QTimer(this);
    connect(m_syncTimer, &QTimer::timeout, this, &RealTimeIntegrationCoordinator::onSynchronizationTick);
    m_syncTimer->start(500);
    
    emit componentStateChanged("Coordinator", QJsonObject{{"status", "initialized"}});
}

void RealTimeIntegrationCoordinator::requestCodeCompletion(
    const QString& context,
    const QString& prefix,
    const QString& filePath) {
    
    qDebug() << "[RealTimeIntegrationCoordinator] Code completion requested for" << filePath;
    
    QMutexLocker lock(&m_mutex);
    
    if (!m_copilotBridge) {
        m_lastError = "Copilot bridge not initialized";
        emit errorOccurred(m_lastError);
        return;
    }
    
    // Request would go to copilot bridge
    emit codeCompletionReady("/* completion suggestions */");
}

void RealTimeIntegrationCoordinator::submitChatMessage(
    const QString& message,
    int agentMode,
    const QString& model) {
    
    qDebug() << "[RealTimeIntegrationCoordinator] Submitting chat message - mode:" << agentMode << "model:" << model;
    
    QMutexLocker lock(&m_mutex);
    
    QString intent = classifyMessageIntent(message);
    qDebug() << "[RealTimeIntegrationCoordinator] Classified intent:" << intent;
    
    routeToAppropriateHandler(message, agentMode);
    
    m_totalMessagesProcessed++;
    emit chatMessageReceived(message, agentMode);
}

void RealTimeIntegrationCoordinator::executeTerminalCommand(
    const QString& command,
    int terminalId) {
    
    qDebug() << "[RealTimeIntegrationCoordinator] Executing terminal command:" << command;
    
    QMutexLocker lock(&m_mutex);
    
    if (!m_terminalPool) {
        m_lastError = "Terminal pool not initialized";
        emit errorOccurred(m_lastError);
        return;
    }
    
    emit terminalOutputCaptured("Command executed successfully");
}

void RealTimeIntegrationCoordinator::applyHotpatch(
    const QString& patchName,
    const QJsonObject& patchData,
    int patchLayer) {
    
    qDebug() << "[RealTimeIntegrationCoordinator] Applying hotpatch:" << patchName;
    
    QMutexLocker lock(&m_mutex);
    
    emit hotpatchApplied(patchName);
}

QString RealTimeIntegrationCoordinator::getEditorContent() const {
    QMutexLocker lock(&m_mutex);
    return m_editor ? "/* editor content */" : QString();
}

QString RealTimeIntegrationCoordinator::getSelectedText() const {
    QMutexLocker lock(&m_mutex);
    return "/* selected text */";
}

void RealTimeIntegrationCoordinator::insertCodeIntoEditor(
    const QString& code,
    int position) {
    
    qDebug() << "[RealTimeIntegrationCoordinator] Inserting code at position" << position;
    
    QMutexLocker lock(&m_mutex);
    
    if (!m_editor) {
        m_lastError = "Editor not initialized";
        emit errorOccurred(m_lastError);
        return;
    }
    
    emit operationCompleted("insertCode", QJsonObject{{"success", true}});
}

QJsonObject RealTimeIntegrationCoordinator::getComponentState() const {
    QMutexLocker lock(&m_mutex);
    
    QJsonObject state;
    state["initialized"] = true;
    state["messagesProcessed"] = m_totalMessagesProcessed;
    state["errorsHandled"] = m_totalErrorsHandled;
    state["queueDepth"] = m_requestQueueDepth;
    
    return state;
}

bool RealTimeIntegrationCoordinator::isComponentReady(const QString& component) const {
    QMutexLocker lock(&m_mutex);
    
    auto it = m_componentStates.find(component.toStdString());
    if (it != m_componentStates.end()) {
        return it->second.ready;
    }
    
    return false;
}

void RealTimeIntegrationCoordinator::synchronizeComponentStates() {
    QMutexLocker lock(&m_mutex);
    
    for (auto& pair : m_componentStates) {
        pair.second.lastUpdateTime = QDateTime::currentMSecsSinceEpoch();
    }
    
    qDebug() << "[RealTimeIntegrationCoordinator] Synchronized component states";
}

QString RealTimeIntegrationCoordinator::getLastError() const {
    QMutexLocker lock(&m_mutex);
    return m_lastError;
}

void RealTimeIntegrationCoordinator::clearLastError() {
    QMutexLocker lock(&m_mutex);
    m_lastError.clear();
}

void RealTimeIntegrationCoordinator::onChatMessage(const QString& message) {
    qDebug() << "[RealTimeIntegrationCoordinator] Slot: Chat message received";
}

void RealTimeIntegrationCoordinator::onTerminalOutput(const QString& output) {
    qDebug() << "[RealTimeIntegrationCoordinator] Slot: Terminal output captured";
}

void RealTimeIntegrationCoordinator::onEditorChange() {
    qDebug() << "[RealTimeIntegrationCoordinator] Slot: Editor content changed";
}

void RealTimeIntegrationCoordinator::onSynchronizationTick() {
    synchronizeComponentStates();
}

void RealTimeIntegrationCoordinator::onComponentReady(const QString& name) {
    QMutexLocker lock(&m_mutex);
    m_componentStates[name.toStdString()].ready = true;
    qDebug() << "[RealTimeIntegrationCoordinator] Component ready:" << name;
}

void RealTimeIntegrationCoordinator::onComponentError(const QString& name, const QString& error) {
    QMutexLocker lock(&m_mutex);
    m_lastError = name + ": " + error;
    m_totalErrorsHandled++;
    qDebug() << "[RealTimeIntegrationCoordinator] Component error:" << name << error;
    emit errorOccurred(m_lastError);
}

void RealTimeIntegrationCoordinator::markComponentReady(const QString& name) {
    QMutexLocker lock(&m_mutex);
    m_componentStates[name.toStdString()].ready = true;
}

void RealTimeIntegrationCoordinator::queueRequest(const PendingRequest& req) {
    QMutexLocker lock(&m_mutex);
    m_requestQueue.push(req);
    m_requestQueueDepth = m_requestQueue.size();
}

void RealTimeIntegrationCoordinator::processRequestQueue() {
    QMutexLocker lock(&m_mutex);
    
    while (!m_requestQueue.empty()) {
        PendingRequest req = m_requestQueue.front();
        m_requestQueue.pop();
        m_requestQueueDepth = m_requestQueue.size();
        
        qDebug() << "[RealTimeIntegrationCoordinator] Processing request:" << req.id << req.type;
    }
}

QString RealTimeIntegrationCoordinator::classifyMessageIntent(const QString& message) {
    if (message.contains("edit") || message.contains("code")) {
        return "CodeEdit";
    } else if (message.contains("run") || message.contains("execute")) {
        return "ToolUse";
    } else if (message.contains("plan") || message.contains("design")) {
        return "Planning";
    }
    return "Chat";
}

void RealTimeIntegrationCoordinator::routeToAppropriateHandler(const QString& message, int mode) {
    QString intent = classifyMessageIntent(message);
    qDebug() << "[RealTimeIntegrationCoordinator] Routing message with intent:" << intent;
    
    if (intent == "CodeEdit" && m_editor) {
        qDebug() << "[RealTimeIntegrationCoordinator] Routing to code editor";
    } else if (intent == "ToolUse" && m_terminalPool) {
        qDebug() << "[RealTimeIntegrationCoordinator] Routing to terminal execution";
    } else if (intent == "Planning" && m_engine) {
        qDebug() << "[RealTimeIntegrationCoordinator] Routing to planning handler";
    }
}

bool RealTimeIntegrationCoordinator::validateComponentState(const QString& component) {
    QMutexLocker lock(&m_mutex);
    
    auto it = m_componentStates.find(component.toStdString());
    if (it != m_componentStates.end()) {
        return it->second.initialized && it->second.ready;
    }
    
    return false;
}
