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
    
signals:
    void messageSubmitted(const QString& message);
    void quickActionTriggered(const QString& action, const QString& context);
    
private slots:
    void onSendClicked();
    void onQuickActionClicked(const QString& action);
    void onNetworkFinished(QNetworkReply* reply);
    void onNetworkError(QNetworkReply::NetworkError code);
    
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
    
    QVBoxLayout* m_messagesLayout = nullptr;
    QScrollArea* m_scrollArea = nullptr;
    QWidget* m_messagesContainer = nullptr;
    QLineEdit* m_inputField = nullptr;
    QPushButton* m_sendButton = nullptr;
    QWidget* m_quickActionsWidget = nullptr;
    
    QList<Message> m_messages;
    QWidget* m_streamingBubble = nullptr;
    QTextEdit* m_streamingText = nullptr;
    
    QString m_contextCode;
    QString m_contextFilePath;
    
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
};
