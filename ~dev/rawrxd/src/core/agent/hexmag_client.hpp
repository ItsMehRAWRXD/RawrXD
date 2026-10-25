// ============================================================================
// agent/hexmag_client.hpp — HEXMAG client transport stub
// ============================================================================
#pragma once

#include <string>

namespace RawrXD {
namespace HexMag {

struct ClientAskResult {
    struct AskResult {
        std::string error;
        std::string answer;
        bool success = false;
    };
    AskResult ask;
};

class HexMagClient {
public:
    HexMagClient() = default;
    ClientAskResult ask(const std::string& prompt,
                        const std::string& context) {
        ClientAskResult r;
        r.ask.error = "hexmag_client not implemented";
        r.ask.success = false;
        return r;
    }
};

} // namespace HexMag
} // namespace RawrXD
