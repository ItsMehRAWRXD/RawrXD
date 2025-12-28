#pragma once

#include <QWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace AmazonQ {

class BedrockClient;

class ChatWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ChatWidget(BedrockClient *client, QWidget *parent = nullptr);
    
    void focusInput();
    void sendMessage(const QString &message);

private slots:
    void onSendClicked();
    void onMessageReceived(const QString &response);
    void onErrorOccurred(const QString &error);

private:
    BedrockClient *m_client;
    QTextEdit *m_chatDisplay;
    QLineEdit *m_messageInput;
    QPushButton *m_sendButton;
    QVBoxLayout *m_layout;
};

} // namespace AmazonQ