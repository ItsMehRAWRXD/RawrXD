/**
 * @file inline_chat_widget.cpp
 * @brief Implementation of InlineChatWidget - Inline code assistance chat
 */

#include "inline_chat_widget.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QClipboard>
#include <QFileDialog>
#include <QSettings>
#include <QDebug>
#include <QDateTime>

InlineChatWidget::InlineChatWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
    connectSignals();
    restoreState();
    
    setWindowTitle("Inline Chat");
}

InlineChatWidget::~InlineChatWidget()
{
    saveState();
}

void InlineChatWidget::setupUI()
{
    mMainLayout = new QVBoxLayout(this);
    
    // Context display
    mContextEditor = new QTextEdit(this);
    mContextEditor->setReadOnly(true);
    mContextEditor->setFont(QFont("Courier", 9));
    mContextEditor->setMaximumHeight(80);
    mContextEditor->setPlaceholderText("Code context will appear here...");
    mMainLayout->addWidget(new QLabel("Context:", this));
    mMainLayout->addWidget(mContextEditor);
    
    // Chat history
    mChatHistory = new QListWidget(this);
    mChatHistory->setStyleSheet("QListWidget { border: 1px solid #ccc; border-radius: 4px; }");
    mMainLayout->addWidget(new QLabel("Chat History:", this));
    mMainLayout->addWidget(mChatHistory);
    
    // Input area
    mMainLayout->addWidget(new QLabel("Message:", this));
    mInputEditor = new QTextEdit(this);
    mInputEditor->setPlaceholderText("Type your question or code assistance request here...");
    mInputEditor->setMaximumHeight(100);
    mMainLayout->addWidget(mInputEditor);
    
    // Button layout
    mButtonLayout = new QHBoxLayout();
    
    mSendButton = new QPushButton("Send", this);
    mSendButton->setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;");
    mButtonLayout->addWidget(mSendButton);
    
    mCopyButton = new QPushButton("Copy Response", this);
    mButtonLayout->addWidget(mCopyButton);
    
    mInsertButton = new QPushButton("Insert Code", this);
    mButtonLayout->addWidget(mInsertButton);
    
    mContextButton = new QPushButton("Set Context", this);
    mButtonLayout->addWidget(mContextButton);
    
    mExportButton = new QPushButton("Export Chat", this);
    mButtonLayout->addWidget(mExportButton);
    
    mClearButton = new QPushButton("Clear", this);
    mButtonLayout->addWidget(mClearButton);
    
    mButtonLayout->addStretch();
    
    mMainLayout->addLayout(mButtonLayout);
}

void InlineChatWidget::connectSignals()
{
    connect(mSendButton, &QPushButton::clicked, this, &InlineChatWidget::onSendMessage);
    connect(mClearButton, &QPushButton::clicked, this, &InlineChatWidget::onClearChat);
    connect(mCopyButton, &QPushButton::clicked, this, &InlineChatWidget::onCopyResponse);
    connect(mInsertButton, &QPushButton::clicked, this, &InlineChatWidget::onInsertCodeBlock);
    connect(mContextButton, &QPushButton::clicked, this, &InlineChatWidget::onShowContext);
    connect(mExportButton, &QPushButton::clicked, this, &InlineChatWidget::onExportChat);
    connect(mChatHistory, &QListWidget::itemSelectionChanged, this, [this]() {
        QList<QListWidgetItem*> selected = mChatHistory->selectedItems();
        if (!selected.isEmpty()) {
            onMessageSelected(selected.first());
        }
    });
}

void InlineChatWidget::onSendMessage()
{
    QString message = mInputEditor->toPlainText().trimmed();
    if (message.isEmpty()) {
        QMessageBox::warning(this, "Empty Message", "Please enter a message.");
        return;
    }
    
    appendMessage("user", message);
    emit messageSent(message);
    
    // Simulate AI response
    QString response = "I understand your request about: \"" + message.left(30) + "...\". "
                      "This is a simulated response. In a real implementation, this would call an AI API.";
    appendMessage("ai", response);
    
    mInputEditor->clear();
}

void InlineChatWidget::onClearChat()
{
    int ret = QMessageBox::question(this, "Clear Chat", "Clear all chat history?");
    if (ret == QMessageBox::Yes) {
        mChatHistory->clear();
        mMessages.clear();
        mContextEditor->clear();
    }
}

void InlineChatWidget::onCopyResponse()
{
    QList<QListWidgetItem*> selected = mChatHistory->selectedItems();
    if (!selected.isEmpty()) {
        QString text = selected.first()->text();
        QApplication::clipboard()->setText(text);
        QMessageBox::information(this, "Copied", "Response copied to clipboard!");
    }
}

void InlineChatWidget::onInsertCodeBlock()
{
    QList<QListWidgetItem*> selected = mChatHistory->selectedItems();
    if (!selected.isEmpty()) {
        QString code = selected.first()->text();
        emit codeInserted(code);
        QMessageBox::information(this, "Inserted", "Code block inserted into editor!");
    }
}

void InlineChatWidget::onShowContext()
{
    QString context = mContextEditor->toPlainText();
    if (context.isEmpty()) {
        QMessageBox::warning(this, "No Context", "No code context set. Select code in the editor and click 'Set Context'.");
    } else {
        QMessageBox::information(this, "Current Context", "Current context:\n\n" + context);
    }
}

void InlineChatWidget::onExportChat()
{
    QString filename = QFileDialog::getSaveFileName(this, "Export Chat", "", "Text Files (*.txt);;HTML Files (*.html)");
    if (!filename.isEmpty()) {
        emit chatExported(filename);
        QMessageBox::information(this, "Exported", "Chat exported successfully!");
    }
}

void InlineChatWidget::onMessageSelected(QListWidgetItem* item)
{
    qDebug() << "Selected message:" << item->text();
}

void InlineChatWidget::appendMessage(const QString& sender, const QString& content)
{
    InlineMessage msg;
    msg.id = QString::number(mMessages.size());
    msg.sender = sender;
    msg.content = content;
    msg.timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    
    mMessages.append(msg);
    
    QString displayText = QString("[%1] %2: %3").arg(msg.timestamp, sender, content.left(80));
    if (content.length() > 80) displayText += "...";
    
    QListWidgetItem* item = new QListWidgetItem(displayText);
    if (sender == "ai") {
        item->setBackground(QColor(230, 245, 255));
    } else {
        item->setBackground(QColor(240, 255, 240));
    }
    
    mChatHistory->addItem(item);
    mChatHistory->scrollToBottom();
}

void InlineChatWidget::restoreState()
{
    QSettings settings("RawrXD", "IDE");
    // Restore last chat state if available
}

void InlineChatWidget::saveState()
{
    QSettings settings("RawrXD", "IDE");
    // Save current chat state for restoration
}
