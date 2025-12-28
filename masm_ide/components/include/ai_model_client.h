#pragma once

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>

/**
 * @brief AIModelClient - The missing AI engine for RawrXD-AgenticIDE
 * 
 * Connects AgenticPlanner to real AI services (OpenAI, Anthropic, Local models)
 */
class AIModelClient : public QObject {
    Q_OBJECT

public:
    enum ModelProvider {
        OPENAI,
        ANTHROPIC,
        LOCAL_GGUF,
        OLLAMA
    };

    explicit AIModelClient(QObject* parent = nullptr);
    ~AIModelClient();

    // Configuration
    void setApiKey(const QString& key) { m_apiKey = key; }
    void setProvider(ModelProvider provider) { m_provider = provider; }
    void setModel(const QString& model) { m_model = model; }

    // Main AI calling interface
    void callModel(const QString& prompt, const QString& context = "");

signals:
    void responseReceived(const QString& response);
    void errorOccurred(const QString& error);
    void tokenReceived(const QString& token);

private slots:
    void onNetworkReply();

private:
    QNetworkAccessManager* m_network;
    QString m_apiKey;
    ModelProvider m_provider{OPENAI};
    QString m_model{"gpt-4"};

    // Provider-specific methods
    void callOpenAI(const QString& prompt);
    void callAnthropic(const QString& prompt);
    void callLocalGGUF(const QString& prompt);
    void callOllama(const QString& prompt);
};
