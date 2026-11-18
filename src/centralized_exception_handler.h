#pragma once

#include <nlohmann/json.hpp>
#include <exception>
#include <string>
#include <iostream>

using json = nlohmann::json;

namespace RawrXD {

class CentralizedExceptionHandler {
private:
    bool m_handlerInstalled{false};
    bool m_autoRecovery{false};

public:
    CentralizedExceptionHandler() = default;

    static CentralizedExceptionHandler& instance() {
        static CentralizedExceptionHandler handler;
        return handler;
    }

    void installHandler() {
        m_handlerInstalled = true;
        std::cerr << "[CentralizedExceptionHandler] Handler installed" << std::endl;
    }

    void uninstallHandler() {
        m_handlerInstalled = false;
        std::cerr << "[CentralizedExceptionHandler] Handler uninstalled" << std::endl;
    }

    void enableAutomaticRecovery(bool enabled) {
        m_autoRecovery = enabled;
    }

    void reportException(const std::exception& e) {
        std::cerr << "[CentralizedExceptionHandler] Exception: " << e.what() << std::endl;
        if (m_autoRecovery) {
            std::cerr << "[CentralizedExceptionHandler] Auto-recovery enabled" << std::endl;
        }
    }

    void reportError(const std::string& message, const std::string& code, const json& context = json()) {
        std::cerr << "[CentralizedExceptionHandler] Error [" << code << "]: " << message << std::endl;
        if (!context.empty()) {
            std::cerr << "[CentralizedExceptionHandler] Context: " << context.dump() << std::endl;
        }
    }

    bool hasActiveHandler() const { return m_handlerInstalled; }
};

} // namespace RawrXD