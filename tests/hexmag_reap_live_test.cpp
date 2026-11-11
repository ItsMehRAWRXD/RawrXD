#include "hexmag/HexMagReapBridge.hpp"

#include <iostream>

int main() {
    RawrXD::HexMag::LiveRequest request;
    request.reapTarget = "not-a-target";
    request.evidenceBudgetBytes = 4096;
    const auto result = RawrXD::HexMag::RunLive(request);
    if (result.exitCode != 4 || result.receipt.find("INVALID_TARGET") == std::string::npos) {
        std::cerr << "HEXMag live bridge did not fail closed on an invalid target\n";
        return 1;
    }
    return 0;
}
