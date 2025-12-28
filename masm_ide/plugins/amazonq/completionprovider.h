#pragma once

#include <QObject>

namespace AmazonQ {

class BedrockClient;

class CompletionProvider : public QObject
{
    Q_OBJECT

public:
    explicit CompletionProvider(BedrockClient *client, QObject *parent = nullptr);
    
    void requestCompletion(const QString &code, int cursorPosition);

private slots:
    void onCompletionReceived(const QString &completion);
    void onErrorOccurred(const QString &error);

signals:
    void completionReady(const QString &completion);
    void completionError(const QString &error);

private:
    BedrockClient *m_client;
};

} // namespace AmazonQ