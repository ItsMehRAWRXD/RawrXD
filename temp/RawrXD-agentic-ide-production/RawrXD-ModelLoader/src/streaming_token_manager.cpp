#include "streaming_token_manager.h"
#include <QWidget>
#include <QVBoxLayout>
#include <QTimer>

StreamingTokenManager::StreamingTokenManager(QObject* parent)
    : QObject(parent)
{
    m_streamBuffer.reserve(STREAM_BUFFER_SIZE);
    m_currentCallBuffer.reserve(CALL_BUFFER_SIZE);
    m_thinkingBuffer.reserve(1024);
}

StreamingTokenManager::~StreamingTokenManager()
{
    destroyThinkingBox();
}

void StreamingTokenManager::initialize(QWidget* chatPanel, QTextEdit* richEdit)
{
    m_chatPanel = chatPanel;
    m_richEdit = richEdit;
}

void StreamingTokenManager::startCall(const QString& modelName)
{
    m_currentCallActive = true;
    m_currentCallBuffer.clear();
    m_currentCallPos = 0;
    m_streamBuffer.clear();
    m_streamPos = 0;
    m_isStreaming = true;
    
    if (m_thinkingEnabled) {
        showThinking();
    }
}

void StreamingTokenManager::finishCall(bool success)
{
    m_currentCallActive = false;
    m_isStreaming = false;
    hideThinking();
    
    if (success) {
        flushBuffer();
        emit streamFinished();
    }
}

void StreamingTokenManager::onToken(const QString& token)
{
    if (!m_currentCallActive) return;
    
    appendToStreamBuffer(token);
    appendToCallBuffer(token);
    emit streamToken(token);
}

void StreamingTokenManager::onToken(const char* token, int tokenLen)
{
    if (!m_currentCallActive || !token || tokenLen <= 0) return;
    
    QString tokenStr = QString::fromUtf8(token, tokenLen);
    onToken(tokenStr);
}

void StreamingTokenManager::showThinking(const QString& text)
{
    if (!m_thinkingEnabled || !m_chatPanel) return;
    
    if (!m_thinkingBox) {
        createThinkingBox();
    }
    
    if (m_thinkingBox) {
        m_thinkingBox->setPlainText(text);
        m_thinkingBox->show();
        m_thinkingVisible = true;
        emit thinkingVisibilityChanged(true);
    }
}

void StreamingTokenManager::hideThinking()
{
    if (m_thinkingBox) {
        m_thinkingBox->hide();
        m_thinkingVisible = false;
        emit thinkingVisibilityChanged(false);
    }
}

void StreamingTokenManager::setThinkingEnabled(bool enabled)
{
    m_thinkingEnabled = enabled;
    if (!enabled) {
        hideThinking();
    }
}

void StreamingTokenManager::flushBuffer()
{
    if (m_richEdit && m_streamPos > 0) {
        QString content = QString::fromUtf8(m_streamBuffer.constData(), m_streamPos);
        m_richEdit->append(content);
        m_streamBuffer.clear();
        m_streamPos = 0;
    }
}

void StreamingTokenManager::finishStream()
{
    flushBuffer();
    hideThinking();
    m_isStreaming = false;
}

QString StreamingTokenManager::getCurrentCallBuffer() const
{
    return QString::fromUtf8(m_currentCallBuffer.constData(), m_currentCallPos);
}

void StreamingTokenManager::appendToStreamBuffer(const QString& token)
{
    QByteArray tokenBytes = token.toUtf8();
    int tokenSize = tokenBytes.size();
    
    if (m_streamPos + tokenSize >= STREAM_BUFFER_SIZE) {
        flushBuffer();
    }
    
    if (tokenSize < STREAM_BUFFER_SIZE) {
        m_streamBuffer.append(tokenBytes);
        m_streamPos += tokenSize;
    }
}

void StreamingTokenManager::appendToCallBuffer(const QString& token)
{
    QByteArray tokenBytes = token.toUtf8();
    int tokenSize = tokenBytes.size();
    
    if (m_currentCallPos + tokenSize < CALL_BUFFER_SIZE) {
        m_currentCallBuffer.append(tokenBytes);
        m_currentCallPos += tokenSize;
    }
}

void StreamingTokenManager::appendToThinkingBuffer(const QString& token)
{
    QByteArray tokenBytes = token.toUtf8();
    int tokenSize = tokenBytes.size();
    
    if (m_thinkingPos + tokenSize < m_thinkingBuffer.capacity()) {
        m_thinkingBuffer.append(tokenBytes);
        m_thinkingPos += tokenSize;
    }
}

void StreamingTokenManager::createThinkingBox()
{
    if (!m_chatPanel || m_thinkingBox) return;
    
    m_thinkingBox = new QTextEdit(m_chatPanel);
    m_thinkingBox->setMaximumHeight(60);
    m_thinkingBox->setReadOnly(true);
    applyMessageStyle(m_thinkingBox);
    
    if (auto layout = m_chatPanel->layout()) {
        layout->addWidget(m_thinkingBox);
    }
}

void StreamingTokenManager::destroyThinkingBox()
{
    if (m_thinkingBox) {
        m_thinkingBox->deleteLater();
        m_thinkingBox = nullptr;
        m_thinkingVisible = false;
    }
}

void StreamingTokenManager::applyMessageStyle(QTextEdit* target)
{
    if (!target) return;
    
    target->setStyleSheet(
        "QTextEdit {"
        "    background-color: #f0f0f0;"
        "    border: 1px solid #ccc;"
        "    border-radius: 8px;"
        "    padding: 8px;"
        "    font-family: 'Segoe UI', Arial, sans-serif;"
        "    font-size: 12px;"
        "}"
    );
}