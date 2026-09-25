// Stub for ErrorRecoveryManager.cpp - created for build compatibility
// Original file was missing during build

#include <string>

namespace RawrXD {

class ErrorRecoveryManager {
public:
    static ErrorRecoveryManager& instance() {
        static ErrorRecoveryManager inst;
        return inst;
    }
    bool initialize() { return true; }
    void shutdown() {}
    void recordError(const std::string& category, const std::string& msg) {}
    bool attemptRecovery(const std::string& category) { return false; }
};

} // namespace RawrXD
