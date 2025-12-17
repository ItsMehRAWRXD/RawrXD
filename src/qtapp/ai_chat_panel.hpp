#pragma once

#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QFrame>
#include <QList>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QComboBox>
#include "agent_chat_breadcrumb.hpp"
#include "../agentic_executor.h"  // Use the one from src/

class AgentChatBreadcrumb;

/**
 * @brief GitHub Copilot-style AI chat panel
 * 
 * Features:
 * - Chat-style message bubbles
 * - Streaming responses
 * - Code block highlighting
 * - Quick actions (explain, fix, refactor)
 * - Context awareness (selected code)
 */
class AIChatPanel : public QWidget {
    Q_OBJECT

public:
    struct Message {
        enum Role { User, Assistant, System };
        Role role;
        QString content;
        QString timestamp;
        bool isStreaming = false;
    };

    explicit AIChatPanel(QWidget* parent = nullptr);
    
    /**
     * Two-phase initialization - call after QApplication is ready
     * Creates all Qt widgets and applies theme
     */
    void initialize();
    
    void addUserMessage(const QString& message);
    void addAssistantMessage(const QString& message, bool streaming = false);
    void updateStreamingMessage(const QString& content);
    void finishStreaming();
    void clear();
    
    void setContext(const QString& code, const QString& filePath);
    void setInputEnabled(bool enabled);  // Enable/disable input based on model readiness
    void setCloudConfiguration(bool enabled, const QString& endpoint, const QString& apiKey);
    void setLocalConfiguration(bool enabled, const QString& endpoint);
    void setLocalModel(const QString& modelName);
    void setSelectedModel(const QString& modelName);
    void setRequestTimeout(int timeoutMs);
    void setAgenticExecutor(AgenticExecutor* executor);  // Connect agentic execution
    AgentChatBreadcrumb* getBreadcrumb() const { return m_breadcrumb; }
    
signals:
    void messageSubmitted(const QString& message);
    void quickActionTriggered(const QString& action, const QString& context);
    void agentModeChanged(int mode);  // Forwarded from breadcrumb
    void modelSelected(const QString& modelName);  // Forwarded from breadcrumb
    
private slots:
    void onSendClicked();
    void onQuickActionClicked(const QString& action);
    void onNetworkFinished(QNetworkReply* reply);
    void onNetworkError(QNetworkReply::NetworkError code);
    void onModelsListFetched(QNetworkReply* reply);
    void onModelSelected(int index);
    void fetchAvailableModels();
    
private:
    void setupUI();
    void applyDarkTheme();
    QWidget* createMessageBubble(const Message& msg);
    QWidget* createQuickActions();
    void scrollToBottom();
    void sendMessageToBackend(const QString& message);
    QByteArray buildCloudPayload(const QString& message) const;
    QByteArray buildLocalPayload(const QString& message) const;
    QString extractAssistantText(const QJsonDocument& doc) const;
    
    // Intent classification and agentic processing
    enum MessageIntent {
        Chat,           // Simple conversation
        CodeEdit,       // Modify code/files
        ToolUse,        // Use tools/commands
        Planning,       // Multi-step task planning
        Unknown         // Could not determine
    };
    
    MessageIntent classifyMessageIntent(const QString& message);
    void processAgenticMessage(const QString& message, MessageIntent intent);
    bool isAgenticRequest(const QString& message) const;
    
    QVBoxLayout* m_messagesLayout = nullptr;
    QScrollArea* m_scrollArea = nullptr;
    QWidget* m_messagesContainer = nullptr;
    QLineEdit* m_inputField = nullptr;
    QPushButton* m_sendButton = nullptr;
    QWidget* m_quickActionsWidget = nullptr;
    AgentChatBreadcrumb* m_breadcrumb = nullptr;  // Agent mode and model selector
    QComboBox* m_modelSelector = nullptr;  // Model selection dropdown (legacy)
    
    QList<Message> m_messages;
    QWidget* m_streamingBubble = nullptr;
    QTextEdit* m_streamingText = nullptr;
    
    QString m_contextCode;
    QString m_contextFilePath;
    QString m_localModel;  // Currently selected local model
    
    // Cloud/Local configuration
    bool m_initialized = false;
    bool m_cloudEnabled = false;
    bool m_localEnabled = false;
    QString m_cloudEndpoint;
    QString m_localEndpoint;
    QString m_apiKey;
    int m_requestTimeout = 30000; // 30 seconds
    
    // Lazy initialization tracking
    bool m_widgetsCreated = false;

    // Networking
    QNetworkAccessManager* m_network = nullptr;
    
    // Agentic execution
    AgenticExecutor* m_agenticExecutor = nullptr;
};
