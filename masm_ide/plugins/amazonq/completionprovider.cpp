#include "completionprovider.h"
#include "bedrocklient.h"

namespace AmazonQ {

CompletionProvider::CompletionProvider(BedrockClient *client, QObject *parent)
    : QObject(parent)
    , m_client(client)
{
    connect(m_client, &BedrockClient::completionReceived, this, &CompletionProvider::onCompletionReceived);
    connect(m_client, &BedrockClient::errorOccurred, this, &CompletionProvider::onErrorOccurred);
}

void CompletionProvider::requestCompletion(const QString &code, int cursorPosition)
{
    m_client->requestCompletion(code, cursorPosition);
}

void CompletionProvider::onCompletionReceived(const QString &completion)
{
    emit completionReady(completion);
}

void CompletionProvider::onErrorOccurred(const QString &error)
{
    emit completionError(error);
}

} // namespace AmazonQ