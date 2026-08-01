// src/orchestration/BackendFactory.cpp
// Factory implementation — instantiates concrete backend drivers.

#include "BackendFactory.hpp"
#include "PowerShellDriver.hpp"
#include "BareMetalDriver.hpp"
#include <iostream>

// ---------------------------------------------------------------------------
// CreateBackend — dispatch by BackendType enum
// ---------------------------------------------------------------------------
std::unique_ptr<IBackendProvider> BackendFactory::CreateBackend(BackendType type) {
    switch (type) {
        case BackendType::PowerShell:
            std::cout << "[BackendFactory] Creating PowerShellDriver\n";
            return std::make_unique<PowerShellDriver>();

        case BackendType::BareMetal:
            std::cout << "[BackendFactory] Creating BareMetalDriver\n";
            return std::make_unique<BareMetalDriver>();

        case BackendType::RemoteAgent:
            std::cout << "[BackendFactory] RemoteAgent not yet implemented, falling back to BareMetal\n";
            return std::make_unique<BareMetalDriver>();

        case BackendType::Sandbox:
            std::cout << "[BackendFactory] Sandbox not yet implemented, falling back to BareMetal\n";
            return std::make_unique<BareMetalDriver>();

        default:
            std::cerr << "[BackendFactory] Unknown backend type: " << static_cast<int>(type) << "\n";
            return nullptr;
    }
}

// ---------------------------------------------------------------------------
// CreateBackendByName — dispatch by string name
// ---------------------------------------------------------------------------
std::unique_ptr<IBackendProvider> BackendFactory::CreateBackendByName(const std::string& name) {
    return CreateBackend(StringToBackendType(name));
}

// ---------------------------------------------------------------------------
// Type <-> string conversion
// ---------------------------------------------------------------------------
std::string BackendFactory::BackendTypeToString(BackendType type) {
    switch (type) {
        case BackendType::PowerShell:   return "PowerShell";
        case BackendType::BareMetal:    return "BareMetal";
        case BackendType::RemoteAgent:  return "RemoteAgent";
        case BackendType::Sandbox:      return "Sandbox";
        default:                        return "Unknown";
    }
}

BackendType BackendFactory::StringToBackendType(const std::string& name) {
    if (name == "PowerShell")   return BackendType::PowerShell;
    if (name == "BareMetal")    return BackendType::BareMetal;
    if (name == "RemoteAgent")  return BackendType::RemoteAgent;
    if (name == "Sandbox")      return BackendType::Sandbox;
    return static_cast<BackendType>(0); // Unknown
}
