// src/orchestration/BackendFactory.hpp
// Factory pattern — creates backend drivers without header inclusion in BackendManager.
// Solves the ODR/link problem of #include "PowerShellDriver.cpp".

#pragma once
#include "IBackendProvider.hpp"
#include "BackendConfig.hpp"
#include <memory>

// ---------------------------------------------------------------------------
// Factory — single point of backend instantiation
// ---------------------------------------------------------------------------
class BackendFactory {
public:
    // Create a backend driver by type. Returns nullptr on unknown type.
    static std::unique_ptr<IBackendProvider> CreateBackend(BackendType type);

    // Create a backend driver by name string. Returns nullptr on unknown name.
    static std::unique_ptr<IBackendProvider> CreateBackendByName(const std::string& name);

    // Get the canonical name for a backend type
    static std::string BackendTypeToString(BackendType type);

    // Get the BackendType from a string
    static BackendType StringToBackendType(const std::string& name);
};
