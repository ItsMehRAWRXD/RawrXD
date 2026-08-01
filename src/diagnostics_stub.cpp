#include <string>
#include <iostream>

namespace Diagnostics {
    void error(const std::string& msg, const std::string& detail) {
        std::cerr << "[Diagnostics] ERROR: " << msg << " | " << detail << "\n";
    }
}
