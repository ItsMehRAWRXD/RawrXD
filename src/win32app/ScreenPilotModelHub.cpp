// ScreenPilotModelHub.cpp — Screen Pilot / Remote Control (Batch 6 C05)
#include "ScreenPilotModelHub.h"
#include <windows.h>
#include <string>

namespace ScreenPilot {

ModelHub& ModelHub::Instance() {
    static ModelHub inst;
    return inst;
}

bool ModelHub::Connect(const std::string& endpoint) {
    m_endpoint = endpoint;
    m_connected = true;
    return true;
}

void ModelHub::Disconnect() {
    m_connected = false;
}

bool ModelHub::IsConnected() const {
    return m_connected;
}

void ModelHub::SendControlCommand(const std::string& /*command*/) {
    // Stub
}

} // namespace ScreenPilot
