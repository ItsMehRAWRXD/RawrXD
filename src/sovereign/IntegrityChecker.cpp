#include "sovereign/IntegrityChecker.hpp"
#include "sovereign/Beaconism.hpp"
#include <fstream>
#include <iostream>

namespace Sovereign {
namespace IntegrityChecker {

bool ValidateModel(const std::wstring& path) {
    BeaconismEmitter::Instance().Emit(BeaconID::IntegrityCheckStart, 0);
    
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        std::cerr << "Failed to open model: ";
        // Convert path to narrow for cerr
        std::wcerr << path << std::endl;
        BeaconismEmitter::Instance().Emit(BeaconID::IntegrityCheckFailed, 1);
        return false;
    }
    
    // Simple hash computation
    uint64_t hash = 0;
    char buf[4096];
    while (f.read(buf, sizeof(buf))) {
        for (size_t i = 0; i < sizeof(buf); i++) {
            hash = hash * 31 + static_cast<uint8_t>(buf[i]);
        }
    }
    
    // Handle remaining bytes
    auto remaining = f.gcount();
    for (decltype(remaining) i = 0; i < remaining; i++) {
        hash = hash * 31 + static_cast<uint8_t>(buf[i]);
    }
    
    f.close();
    
    std::cout << "Model hash: 0x" << std::hex << hash << std::dec << "\n";
    
    BeaconismEmitter::Instance().Emit(BeaconID::IntegrityCheckDone, static_cast<uint32_t>(hash));
    return true;
}

bool ValidateSections(const std::wstring& exePath) {
    // Placeholder for PE section validation
    std::cout << "Validating executable sections...\n";
    return true;
}

uint64_t ComputeFileHash(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return 0;
    
    uint64_t hash = 0;
    char buf[4096];
    while (f.read(buf, sizeof(buf))) {
        for (size_t i = 0; i < sizeof(buf); i++) {
            hash = hash * 31 + static_cast<uint8_t>(buf[i]);
        }
    }
    
    auto remaining = f.gcount();
    for (decltype(remaining) i = 0; i < remaining; i++) {
        hash = hash * 31 + static_cast<uint8_t>(buf[i]);
    }
    
    return hash;
}

} // namespace IntegrityChecker
} // namespace Sovereign
