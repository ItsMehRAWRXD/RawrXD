/**
 * @file inline_chat_widget.h
 * @brief Header for InlineChatWidget - Inline chat for code assistance
 */

#pragma once

#include <QWidget>
#include <QString>
#include <QList>

class QVBoxLayout;
class QHBoxLayout;
class QTextEdit;
class QPushButton;
class QLabel;
class QListWidget;
class QListWidgetItem;

struct InlineMessage {
    QString id;
    QString sender; // "user" or "ai"
    QString content;
    QString timestamp;
    QString codeContext;
};

class InlineChatWidget : public QWidget {
    Q_OBJECT
    
public:
    explicit InlineChatWidget(QWidget* parent = nullptr);
    ~InlineChatWidget();
    
public slots:
    void onSendMessage();
    void onClearChat();
    void onCopyResponse();
    void onInsertCodeBlock();
    void onShowContext();
    void onExportChat();
    void onMessageSelected(QListWidgetItem* item);
    
signals:
    void messageSent(const QString& message);
    void codeInserted(const QString& code);
    void chatExported(const QString& filename);
    
private:
    void setupUI();
    void connectSignals();
    void appendMessage(const QString& sender, const QString& content);
    void restoreState();
    void saveState();
    
    // UI Components
    QVBoxLayout* mMainLayout;
    QHBoxLayout* mButtonLayout;
    
    // Chat display
    QListWidget* mChatHistory;
    
    // Context display
    QTextEdit* mContextEditor;
    
    // Input area
    QTextEdit* mInputEditor;
    
    // Buttons
    QPushButton* mSendButton;
    QPushButton* mClearButton;
    QPushButton* mCopyButton;
    QPushButton* mInsertButton;
    QPushButton* mContextButton;
    QPushButton* mExportButton;
    
    // State tracking
    QList<InlineMessage> mMessages;
    QString mCurrentCode;
};


