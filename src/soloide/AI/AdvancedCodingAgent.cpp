#include "AdvancedCodingAgent.hpp"
#include "../Core/Bus.hpp"
#include <QDebug>
#include <QTimer>

namespace SoloIDE {

AdvancedCodingAgent::AdvancedCodingAgent(MultiModalModelRouter* router, QObject* parent)
    : QObject(parent), m_router(router)
{
}

AdvancedCodingAgent::~AdvancedCodingAgent() = default;

void AdvancedCodingAgent::chat(const QString& message) {
    qDebug() << "[Agent] Chat:" << message.left(80);

    QVariantMap request;
    request["prompt"] = message;
    request["max_tokens"] = 256;
    m_router->routeInference(request);

    // Simulated agent response
    QTimer::singleShot(100, this, [this, message]() {
        QString response = QString("[Sovereign Agent] Processing: \"%1\"\n→ Analysis complete. Ready for next action.")
            .arg(message.left(40));
        emit responseReady(response);

        BusMessage msg{Channel::AgentAction, "Agent", "UI",
            QVariantMap{{"response", response}}, 0};
        IntegrationBus::instance()->publish(msg);
    });
}

void AdvancedCodingAgent::explain(const QString& code) {
    chat("Explain this code:\n" + code);
}

void AdvancedCodingAgent::generateTests(const QString& code) {
    chat("Generate tests for:\n" + code);
}

void AdvancedCodingAgent::optimize(const QString& code) {
    chat("Optimize this code:\n" + code);
}

} // namespace SoloIDE
