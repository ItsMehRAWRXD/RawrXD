// ScreenPilotModelHub.h — Screen Pilot / Remote Control (Batch 6 C05)
#pragma once

#include <string>

namespace ScreenPilot {

class ModelHub {
public:
    static ModelHub& Instance();

    bool Connect(const std::string& endpoint);
    void Disconnect();
    bool IsConnected() const;
    bool SendControlCommand(const std::string& command, std::string& response,
                            std::string& error);

private:
    ModelHub() = default;
    bool m_connected = false;
    std::string m_endpoint;
};

} // namespace ScreenPilot
