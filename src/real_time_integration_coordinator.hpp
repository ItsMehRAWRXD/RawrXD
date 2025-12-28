#ifndef REAL_TIME_INTEGRATION_COORDINATOR_HPP
#define REAL_TIME_INTEGRATION_COORDINATOR_HPP

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QMutex>
#include <QThread>
#include <QTimer>
#include <memory>
#include <unordered_map>
#include <queue>

// Forward declarations
class AgenticCopilotBridge;
class AIChatPanel;
class MultiTabEditor;
class TerminalPool;
class AgenticEngine;
class InferenceEngine;

/**
 * @class RealTimeIntegrationCoordinator
 * @brief Orchestrates real-time communication between all IDE components
 */
class RealTimeIntegrationCoordinator : public QObject {
    Q_OBJECT

public:
    explicit RealTimeIntegrationCoordinator(QObject* parent = nullptr);
    ~RealTimeIntegrationCoordinator() override;

    void initialize(
        AgenticCopilotBridge* copilotBridge,
        AIChatPanel* chatPanel,
        MultiTabEditor* editor,
        TerminalPool* terminals,
        AgenticEngine* engine,
        InferenceEngine* inference);

    void requestCodeCompletion(
        const QString& context,
        const QString& prefix,
        const QString& filePath);

    void submitChatMessage(
        const QString& message,
        int agentMode,
        const QString& model);

    void executeTerminalCommand(
        const QString& command,
        int terminalId = -1);

    void applyHotpatch(
        const QString& patchName,
        const QJsonObject& patchData,
        int patchLayer);

    QString getEditorContent() const;
    QString getSelectedText() const;

    void insertCodeIntoEditor(
        const QString& code,
        int position = -1);

    QJsonObject getComponentState() const;
    bool isComponentReady(const QString& component) const;

    void synchronizeComponentStates();

    // Error reporting
    QString getLastError() const;
    void clearLastError();

signals:
    void chatMessageReceived(const QString& message, int mode);
    void codeCompletionReady(const QString& suggestions);
    void terminalOutputCaptured(const QString& output);
    void hotpatchApplied(const QString& patchName);
    void componentStateChanged(const QString& component, const QJsonObject& state);
    void errorOccurred(const QString& errorMessage);
    void operationCompleted(const QString& operationName, const QJsonObject& result);

private slots:
    void onChatMessage(const QString& message);
    void onTerminalOutput(const QString& output);
    void onEditorChange();
    void onSynchronizationTick();
    void onComponentReady(const QString& name);
    void onComponentError(const QString& name, const QString& error);

private:
    struct ComponentState {
        bool initialized = false;
        bool ready = false;
        QJsonObject lastState;
        qint64 lastUpdateTime = 0;
    };

    struct PendingRequest {
        QString id;
        QString type;
        QJsonObject data;
        qint64 createdTime = 0;
        int retryCount = 0;
    };

    // Component references
    AgenticCopilotBridge* m_copilotBridge = nullptr;
    AIChatPanel* m_chatPanel = nullptr;
    MultiTabEditor* m_editor = nullptr;
    TerminalPool* m_terminalPool = nullptr;
    AgenticEngine* m_engine = nullptr;
    InferenceEngine* m_inferenceEngine = nullptr;

    // State management
    mutable QMutex m_mutex;
    std::unordered_map<std::string, ComponentState> m_componentStates;
    std::queue<PendingRequest> m_requestQueue;
    QString m_lastError;
    QTimer* m_syncTimer = nullptr;

    // Metrics
    int m_totalMessagesProcessed = 0;
    int m_totalErrorsHandled = 0;
    int m_requestQueueDepth = 0;

    // Helper methods
    void markComponentReady(const QString& name);
    void queueRequest(const PendingRequest& req);
    void processRequestQueue();
    QString classifyMessageIntent(const QString& message);
    void routeToAppropriateHandler(const QString& message, int mode);
    bool validateComponentState(const QString& component);
};

#endif // REAL_TIME_INTEGRATION_COORDINATOR_HPP
