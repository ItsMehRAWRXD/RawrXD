#include "Bus.hpp"

SoloIDE::IntegrationBus* SoloIDE::IntegrationBus::instance() {
    static IntegrationBus bus;
    return &bus;
}

void SoloIDE::IntegrationBus::publish(const BusMessage& msg) {
    uint32_t mask = static_cast<uint32_t>(msg.channel);
    for (auto& [ch, cbList] : handlers) {
        if ((ch & mask) != 0) {
            for (auto& cb : cbList) cb(msg);
        }
    }
}

void SoloIDE::IntegrationBus::subscribe(Channel ch, std::function<void(const BusMessage&)> handler) {
    handlers[static_cast<uint32_t>(ch)].push_back(std::move(handler));
}

void SoloIDE::IntegrationBus::subscribe(Channel ch, QObject* receiver, const char* slot) {
    Q_UNUSED(receiver);
    Q_UNUSED(slot);
    // Qt meta-object subscription is handled via connect() externally
    // This method exists for API consistency
}
