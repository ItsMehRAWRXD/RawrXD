#include "CompletionEngine.hpp"
#include "../Core/Bus.hpp"
#include <QTimer>
#include <QDebug>

namespace SoloIDE {

CompletionEngine::CompletionEngine(MultiModalModelRouter* router, QObject* parent)
    : QObject(parent), m_router(router)
{
}

CompletionEngine::~CompletionEngine() = default;

void CompletionEngine::requestCompletion(const QString& text, const QPoint& cursorPos) {
    Q_UNUSED(cursorPos);
    if (m_computing) return;
    if (text.length() < 3) return; // minimum context

    m_computing = true;

    // Route through the model router with broken-link safety
    QVariantMap request;
    request["prompt"] = text;
    request["max_tokens"] = 32;
    m_router->routeInference(request);

    // Simulated completion result (in production, wire to real inference)
    QTimer::singleShot(50, this, [this, text]() {
        m_computing = false;
        QString completion = text.right(10) + " → [Sovereign inference pending]";
        emit completionReady(completion);

        BusMessage msg{Channel::CompletionReady, "CompletionEngine", "Editor",
            QVariant(completion), 0};
        IntegrationBus::instance()->publish(msg);
    });
}

void CompletionEngine::cancelCompletion() {
    m_computing = false;
}

} // namespace SoloIDE
