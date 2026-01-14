/**
 * @file ai_chat_widget.h
 * @brief Header for AIChatWidget - AI-powered chat interface
 */

#pragma once

#include <QWidget>
#include <QMap>
#include <QString>
#include <QList>
#include <QDateTime>
#include <QThread>
#include <QJsonObject>

class QVBoxLayout;
class QHBoxLayout;
class QSplitter;
class QTextEdit;
class QLineEdit;
class QPushButton;
class QLabel;
class QListWidget;
class QListWidgetItem;
class QComboBox;
class QGroupBox;
class QProgressBar;
class QScrollArea;
class QTimer;

struct ChatMessage {
    QString id;
    QString role; // "user", "assistant", "system"
    QString content;
    QDateTime timestamp;
    QJsonObject metadata;
};

struct ChatSession {
    QString id;
    QString title;
    QList<ChatMessage> messages;
    QDateTime created;
    QDateTime lastModified;
    QString model;
    QJsonObject settings;
};

class AIChatWorker : public QObject {
    Q_OBJECT
public:
    explicit AIChatWorker(QObject* parent = nullptr);
    ~AIChatWorker() override = default;

    void setApiKey(const QString& key) { apiKey_ = key; }
    void setModel(const QString& model) { model_ = model; }
    void sendMessage(const QString& message, const QList<ChatMessage>& context, const QJsonObject& options);

signals:
    void responseReceived(const QString& response, const QJsonObject& metadata);
    void error(const QString& error);
    void progress(int current, int total);

private:
    QString apiKey_;
    QString model_;
    QJsonObject callAIAPI(const QString& prompt, const QList<ChatMessage>& context, const QJsonObject& options);
};

class AIChatWidget : public QWidget {
    Q_OBJECT
public:
    explicit AIChatWidget(QWidget* parent = nullptr);
    ~AIChatWidget() override;

    // Session management
    bool createNewSession(const QString& title = QString());
    bool loadSession(const QString& sessionId);
    bool saveSession(const QString& sessionId = QString());
    void deleteSession(const QString& sessionId);

    // Message handling
    void sendMessage(const QString& message);
    void clearChat();
    void exportChat(const QString& format = "txt");

    // Settings
    void setApiKey(const QString& key);
    void setModel(const QString& model);
    void setTemperature(double temperature);
    void setMaxTokens(int tokens);

signals:
    void sessionCreated(const QString& sessionId);
    void sessionLoaded(const QString& sessionId);
    void messageSent(const QString& message);
    void responseReceived(const QString& response);
    void error(const QString& message);

public slots:
    void refresh();
    void onResponseReceived(const QString& response, const QJsonObject& metadata);
    void onError(const QString& error);

private slots:
    void onNewChat();
    void onLoadChat();
    void onSaveChat();
    void onDeleteChat();
    void onExportChat();
    void onSendMessage();
    void onMessageTextChanged();
    void onSessionSelected(QListWidgetItem* item);
    void onModelChanged(const QString& model);
    void onSettingsChanged();
    void onStopGeneration();
    void onClearChat();
    void onCopyMessage();
    void onRegenerateResponse();

private:
    void setupUI();
    void setupToolbar();
    void setupChatArea();
    void setupSidebar();
    void setupConnections();

    void updateSessionList();
    void updateChatDisplay();
    void addMessageToChat(const ChatMessage& message);
    void scrollToBottom();
    void updateSendButton();

    QString generateSessionTitle(const QString& firstMessage) const;
    QString formatMessageForDisplay(const ChatMessage& message) const;
    QColor getRoleColor(const QString& role) const;

    void saveCurrentSession();
    void loadCurrentSession();

    void saveState();
    void restoreState();

    // UI components
    QVBoxLayout* mainLayout_;
    QWidget* toolbarWidget_;
    QSplitter* mainSplitter_;

    // Toolbar
    QPushButton* newChatBtn_;
    QPushButton* loadChatBtn_;
    QPushButton* saveChatBtn_;
    QPushButton* deleteChatBtn_;
    QPushButton* exportChatBtn_;
    QPushButton* clearChatBtn_;
    QComboBox* modelCombo_;

    // Chat area
    QSplitter* chatSplitter_;
    QListWidget* sessionList_;
    QScrollArea* chatScrollArea_;
    QWidget* chatContainer_;
    QVBoxLayout* chatLayout_;

    // Message input
    QWidget* inputWidget_;
    QLineEdit* messageInput_;
    QPushButton* sendBtn_;
    QPushButton* stopBtn_;
    QLabel* statusLabel_;

    // Sidebar
    QGroupBox* settingsGroup_;
    QComboBox* modelSelector_;
    QLineEdit* temperatureInput_;
    QLineEdit* maxTokensInput_;
    QCheckBox* streamResponsesCheck_;
    QProgressBar* progressBar_;

    // Chat worker
    AIChatWorker* chatWorker_;
    QThread* workerThread_;

    // Data
    QList<ChatSession> sessions_;
    QString currentSessionId_;
    QString apiKey_;
    bool isGenerating_;
    QTimer* typingTimer_;
};
