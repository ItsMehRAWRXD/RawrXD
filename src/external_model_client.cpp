#include "external_model_client.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QDebug>
#include <QRegularExpression>

ExternalModelClient::ExternalModelClient(QObject* parent)
    : QObject(parent)
{
    m_networkManager = new QNetworkAccessManager(this);
}

ExternalModelClient::~ExternalModelClient()
{
    if (m_currentReply) {
        m_currentReply->abort();
        m_currentReply->deleteLater();
    }
}

void ExternalModelClient::setConfiguration(Provider provider, const QString& endpoint, const QString& apiKey, const QString& model)
{
    m_provider = provider;
    m_endpoint = endpoint;
    m_apiKey = apiKey;
    m_model = model;
    
    if (m_endpoint.isEmpty()) {
        switch (m_provider) {
            case OpenAI: m_endpoint = "https://api.openai.com/v1/chat/completions"; break;
            case Anthropic: m_endpoint = "https://api.anthropic.com/v1/messages"; break;
            case Groq: m_endpoint = "https://api.groq.com/openai/v1/chat/completions"; break;
            case Ollama: m_endpoint = "http://localhost:11434/api/chat"; break;
            default: break;
        }
    }
}

void ExternalModelClient::sendMessage(const QString& prompt, const QJsonArray& history, bool streaming)
{
    if (m_currentReply) {
        m_currentReply->abort();
        m_currentReply->deleteLater();
    }
    
    m_accumulatedResponse.clear();
    
    QNetworkRequest request(m_endpoint);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    QJsonObject body;
    body["model"] = m_model;
    body["stream"] = streaming;
    
    QJsonArray messages = history;
    messages.append(QJsonObject{
        {"role", "user"},
        {"content", prompt}
    });
    
    if (m_provider == OpenAI || m_provider == Groq || m_provider == Ollama) {
        body["messages"] = messages;
        request.setRawHeader("Authorization", QString("Bearer %1").arg(m_apiKey).toUtf8());
    } else if (m_provider == Anthropic) {
        body["messages"] = messages;
        request.setRawHeader("x-api-key", m_apiKey.toUtf8());
        request.setRawHeader("anthropic-version", "2023-06-01");
    }
    
    QJsonDocument doc(body);
    m_currentReply = m_networkManager->post(request, doc.toJson());
    
    connect(m_currentReply, &QNetworkReply::readyRead, this, &ExternalModelClient::onReadyRead);
    connect(m_currentReply, &QNetworkReply::finished, this, &ExternalModelClient::onReplyFinished);
    connect(m_currentReply, &QNetworkReply::errorOccurred, this, &ExternalModelClient::onNetworkError);
}

void ExternalModelClient::onReadyRead()
{
    if (!m_currentReply) return;
    
    QByteArray data = m_currentReply->readAll();
    
    if (m_provider == OpenAI || m_provider == Groq) {
        processOpenAIStream(data);
    } else if (m_provider == Anthropic) {
        processAnthropicStream(data);
    } else if (m_provider == Ollama) {
        // Ollama stream is slightly different
        QList<QByteArray> lines = data.split('\n');
        for (const QByteArray& line : lines) {
            if (line.isEmpty()) continue;
            QJsonDocument doc = QJsonDocument::fromJson(line);
            if (doc.isObject()) {
                QString token = doc.object()["message"].toObject()["content"].toString();
                if (!token.isEmpty()) {
                    m_accumulatedResponse += token;
                    emit tokenReceived(token);
                }
            }
        }
    }
}

void ExternalModelClient::processOpenAIStream(const QByteArray& data)
{
    QString content = QString::fromUtf8(data);
    QStringList lines = content.split("\n");
    
    for (const QString& line : lines) {
        if (line.startsWith("data: ")) {
            QString jsonStr = line.mid(6).trimmed();
            if (jsonStr == "[DONE]") continue;
            
            QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8());
            if (doc.isObject()) {
                QJsonArray choices = doc.object()["choices"].toArray();
                if (!choices.isEmpty()) {
                    QJsonObject delta = choices[0].toObject()["delta"].toObject();
                    if (delta.contains("content")) {
                        QString token = delta["content"].toString();
                        m_accumulatedResponse += token;
                        emit tokenReceived(token);
                    }
                }
            }
        }
    }
}

void ExternalModelClient::processAnthropicStream(const QByteArray& data)
{
    // Anthropic SSE format is different
    QString content = QString::fromUtf8(data);
    QStringList events = content.split("\n\n");
    
    for (const QString& event : events) {
        if (event.contains("content_block_delta")) {
            // Extract JSON from data: line
            QRegularExpression re("data: (\\{.*\\})");
            QRegularExpressionMatch match = re.match(event);
            if (match.hasMatch()) {
                QJsonDocument doc = QJsonDocument::fromJson(match.captured(1).toUtf8());
                if (doc.isObject()) {
                    QJsonObject delta = doc.object()["delta"].toObject();
                    if (delta.contains("text")) {
                        QString token = delta["text"].toString();
                        m_accumulatedResponse += token;
                        emit tokenReceived(token);
                    }
                }
            }
        }
    }
}

void ExternalModelClient::onReplyFinished()
{
    if (!m_currentReply) return;
    
    if (m_currentReply->error() == QNetworkReply::NoError) {
        // If not streaming, the whole response is here
        if (m_accumulatedResponse.isEmpty()) {
            QByteArray data = m_currentReply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(data);
            if (doc.isObject()) {
                if (m_provider == OpenAI || m_provider == Groq) {
                    m_accumulatedResponse = doc.object()["choices"].toArray()[0].toObject()["message"].toObject()["content"].toString();
                } else if (m_provider == Anthropic) {
                    m_accumulatedResponse = doc.object()["content"].toArray()[0].toObject()["text"].toString();
                }
            }
        }
        emit responseFinished(m_accumulatedResponse);
    }
    
    m_currentReply->deleteLater();
    m_currentReply = nullptr;
}

void ExternalModelClient::onNetworkError(QNetworkReply::NetworkError code)
{
    if (code == QNetworkReply::OperationCanceledError) return;
    
    QString error = m_currentReply ? m_currentReply->errorString() : "Unknown network error";
    qWarning() << "[ExternalModelClient] Network error:" << error;
    emit errorOccurred(error);
}
