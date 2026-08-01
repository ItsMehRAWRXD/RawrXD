
#pragma once

#include <memory>
#include <string>
#include <utility>
#include <functional>

#include "agentic_agent_coordinator.h"

namespace RawrXD::IDE {

enum class AgenticError {
    None,
    BootstrapFailed,
    CoordinatorNotReady,
    InvalidState,
    CommunicationError
};

struct AgenticResult {
    bool success;
    AgenticError error;
    std::string message;

    static AgenticResult Ok(std::string msg = {}) {
        return {true, AgenticError::None, std::move(msg)};
    }

    static AgenticResult Fail(AgenticError err, std::string msg) {
        return {false, err, std::move(msg)};
    }
};

class AgenticController {
public:
    AgenticController();
    ~AgenticController();

    AgenticResult bootstrap();

    // Callbacks (Qt signal equivalents)
    using ReadyCallback = std::function<void()>;
    using ErrorCallback = std::function<void(const std::string&)>;
    using LayoutCallback = std::function<void(const std::string&)>;
    using TelemetryCallback = std::function<void(const std::string&)>;

    void setReadyCallback(ReadyCallback cb) { m_readyCb = cb; }
    void setErrorCallback(ErrorCallback cb) { m_errorCb = cb; }
    void setLayoutCallback(LayoutCallback cb) { m_layoutCb = cb; }
    void setTelemetryCallback(TelemetryCallback cb) { m_telemetryCb = cb; }

    void handleLayoutRestored(const std::string& snapshotId);
    void handleWindowActivated();

private:
    AgenticResult ensureCoordinator();
    std::string resolveSnapshotPreference() const;
    void publishHeartbeat();

    std::unique_ptr<AgenticAgentCoordinator> m_coordinator;
    ReadyCallback m_readyCb;
    ErrorCallback m_errorCb;
    LayoutCallback m_layoutCb;
    TelemetryCallback m_telemetryCb;
};

} // namespace RawrXD::IDE

