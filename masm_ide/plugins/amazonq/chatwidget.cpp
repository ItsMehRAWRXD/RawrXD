#include "chatwidget.h"
#include "bedrocklient.h"
#include <QVBoxLayout>
#include <QHBoxLayout>

namespace AmazonQ {

ChatWidget::ChatWidget(BedrockClient *client, QWidget *parent)
    : QWidget(parent)
    , m_client(client)
{
    m_layout = new QVBoxLayout(this);
    
    m_chatDisplay = new QTextEdit(this);
    m_chatDisplay->setReadOnly(true);
    m_layout->addWidget(m_chatDisplay);
    
    QHBoxLayout *inputLayout = new QHBoxLayout();
    m_messageInput = new QLineEdit(this);
    m_messageInput->setPlaceholderText("Ask Amazon Q...");
    inputLayout->addWidget(m_messageInput);
    
    m_sendButton = new QPushButton("Send", this);
    inputLayout->addWidget(m_sendButton);
    
    m_layout->addLayout(inputLayout);
    
    connect(m_sendButton, &QPushButton::clicked, this, &ChatWidget::onSendClicked);
    connect(m_messageInput, &QLineEdit::returnPressed, this, &ChatWidget::onSendClicked);
    connect(m_client, &BedrockClient::messageReceived, this, &ChatWidget::onMessageReceived);
    connect(m_client, &BedrockClient::errorOccurred, this, &ChatWidget::onErrorOccurred);
}

void ChatWidget::focusInput()
{
    m_messageInput->setFocus();
}

void ChatWidget::sendMessage(const QString &message)
{
    m_chatDisplay->append("<b>You:</b> " + message);
    m_client->sendMessage(message);
}

void ChatWidget::onSendClicked()
{
    QString message = m_messageInput->text().trimmed();
    if (message.isEmpty()) return;
    
    sendMessage(message);
    m_messageInput->clear();
}

void ChatWidget::onMessageReceived(const QString &response)
{
    m_chatDisplay->append("<b>Amazon Q:</b> " + response);
}

void ChatWidget::onErrorOccurred(const QString &error)
{
    m_chatDisplay->append("<b style='color:red;'>Error:</b> " + error);
}

} // namespace AmazonQ