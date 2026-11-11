#pragma once
#include <QObject>
#include <QVariant>
#include <QString>
#include <functional>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace SoloIDE {

enum class Channel : uint32_t {
    EditorTextChanged   = 0x0001,
    CursorMoved         = 0x0002,
    CompletionReady     = 0x0004,
    GhostTextShow       = 0x0008,
    GhostTextAccept     = 0x0010,
    ChatMessage         = 0x0020,
    AgentAction         = 0x0040,
    DebugBreak          = 0x0080,
    LSPDiagnostic       = 0x0100,
    ModelLoadRequest    = 0x0200,
    ModelLoadComplete   = 0x0400,
    GPUInferenceStart   = 0x0800,
    GPUInferenceDone    = 0x1000,
    All                 = 0xFFFFFFFF
};

struct BusMessage {
    Channel channel;
    QString source;      // subsystem name
    QString target;      // empty = broadcast
    QVariant payload;
    uint64_t timestamp;
};

class IntegrationBus : public QObject {
    Q_OBJECT
public:
    static IntegrationBus* instance();
    void publish(const BusMessage& msg);
    void subscribe(Channel ch, std::function<void(const BusMessage&)> handler);
    void subscribe(Channel ch, QObject* receiver, const char* slot);

private:
    IntegrationBus(QObject* parent = nullptr) : QObject(parent) {}
    std::unordered_map<uint32_t, std::vector<std::function<void(const BusMessage&)>>> handlers;
};

} // namespace SoloIDE
