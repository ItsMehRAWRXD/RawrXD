// Backend Adapter Factory
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "backends/sovereign_adapter.hpp"
#include "backends/ollama_adapter.hpp"

namespace rawrxd::benchmark {

// Factory function implementation
inline std::unique_ptr<BackendAdapter> CreateBackendAdapter(BackendType type) {
    switch (type) {
        case BackendType::SOVEREIGN:
            return std::make_unique<SovereignAdapter>();
        case BackendType::OLLAMA:
            return std::make_unique<OllamaAdapter>();
        default:
            return nullptr;
    }
}

} // namespace rawrxd::benchmark
