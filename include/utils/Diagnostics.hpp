#pragma once
#include <string>

namespace Diagnostics {
    inline void error(const std::string& msg, const std::string& ctx = "") {
        // Stub implementation - errors are logged elsewhere
        (void)msg;
        (void)ctx;
    }
}
