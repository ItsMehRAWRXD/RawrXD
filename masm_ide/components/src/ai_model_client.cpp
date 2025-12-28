#include "ai_model_client.h"
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDebug>

AIModelClient::AIModelClient(QObject* parent)
    : QObject(parent)
{
    m_network = new QNetworkAccessManager(this);
}

AIModelClient::~AIModelClient() = default;

void AIModelClient::callModel(const QString& prompt, const QString& context)
{
    if (prompt.isEmpty()) {
        emit errorOccurred("Empty prompt");
        return;
    }

    switch (m_provider) {
        case OPENAI:
            callOpenAI(prompt);
            break;
        case ANTHROPIC:
            callAnthropic(prompt);
            break;
        case LOCAL_GGUF:
            callLocalGGUF(prompt);
            break;
        case OLLAMA:
            callOllama(prompt);
            break;
    }
}

void AIModelClient::callOpenAI(const QString& prompt)
{
    QNetworkRequest request(QUrl("https://api.openai.com/v1/chat/completions"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", ("Bearer " + m_apiKey).toUtf8());

    QJsonObject message;
    message["role"] = "user";
    message["content"] = prompt;

    QJsonArray messages;
    messages.append(message);

    QJsonObject data;
    data["model"] = m_model;
    data["messages"] = messages;
    data["max_tokens"] = 1000;
    data["stream"] = false;

    QJsonDocument doc(data);
    QNetworkReply* reply = m_network->post(request, doc.toJson());
    connect(reply, &QNetworkReply::finished, this, &AIModelClient::onNetworkReply);
}

void AIModelClient::callAnthropic(const QString& prompt)
{
    QNetworkRequest request(QUrl("https://api.anthropic.com/v1/messages"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("x-api-key", m_apiKey.toUtf8());
    request.setRawHeader("anthropic-version", "2023-06-01");

    QJsonObject message;
    message["role"] = "user";
    message["content"] = prompt;

    QJsonArray messages;
    messages.append(message);

    QJsonObject data;
    data["model"] = m_model;
    data["messages"] = messages;
    data["max_tokens"] = 1000;

    QJsonDocument doc(data);
    QNetworkReply* reply = m_network->post(request, doc.toJson());
    connect(reply, &QNetworkReply::finished, this, &AIModelClient::onNetworkReply);
}

void AIModelClient::callLocalGGUF(const QString& prompt)
{
    // Call local inference engine
    QJsonObject data;
    data["prompt"] = prompt;
    data["max_tokens"] = 1000;

    QNetworkRequest request(QUrl("http://localhost:8080/v1/completions"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonDocument doc(data);
    QNetworkReply* reply = m_network->post(request, doc.toJson());
    connect(reply, &QNetworkReply::finished, this, &AIModelClient::onNetworkReply);
}

void AIModelClient::callOllama(const QString& prompt)
{
    QNetworkRequest request(QUrl("http://localhost:11434/api/generate"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject data;
    data["model"] = m_model;
    data["prompt"] = prompt;
    data["stream"] = false;

    QJsonDocument doc(data);
    QNetworkReply* reply = m_network->post(request, doc.toJson());
    connect(reply, &QNetworkReply::finished, this, &AIModelClient::onNetworkReply);
}

void AIModelClient::onNetworkReply()
{
    QNetworkReply* reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply) return;

    reply->deleteLater();

    if (reply->error() != QNetworkReply::NoError) {
        emit errorOccurred("Network error: " + reply->errorString());
        return;
    }

    QByteArray data = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    QJsonObject obj = doc.object();

    QString response;

    // Parse response based on provider
    switch (m_provider) {
        case OPENAI:
            if (obj.contains("choices")) {
                QJsonArray choices = obj["choices"].toArray();
                if (!choices.isEmpty()) {
                    QJsonObject choice = choices[0].toObject();
                    QJsonObject message = choice["message"].toObject();
                    response = message["content"].toString();
                }
            }
            break;

        case ANTHROPIC:
            if (obj.contains("content")) {
                QJsonArray content = obj["content"].toArray();
                if (!content.isEmpty()) {
                    QJsonObject contentObj = content[0].toObject();
                    response = contentObj["text"].toString();
                }
            }
            break;

        case LOCAL_GGUF:
            if (obj.contains("choices")) {
                QJsonArray choices = obj["choices"].toArray();
                if (!choices.isEmpty()) {
                    QJsonObject choice = choices[0].toObject();
                    response = choice["text"].toString();
                }
            }
            break;

        case OLLAMA:
            response = obj["response"].toString();
            break;
    }

    if (response.isEmpty()) {
        emit errorOccurred("Empty response from AI service");
    } else {
        emit responseReceived(response);
    }
}
