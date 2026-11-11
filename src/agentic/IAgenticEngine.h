/**
 * @file IAgenticEngine.h
 * @brief Minimal interface for agentic engine backends
 * 
 * Intentionally small interface - only what Core needs.
 * No GGML types, no CUDA handles, no AppState references.
 * 
 * Implementations:
 *   - MockAgenticEngine: L3 verified
 *   - GGMLAgenticEngine: target L4
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Agentic {

/**
 * @brief Minimal interface for inference backends
 * 
 * Design: The smallest surface area that supports end-to-end inference.
 * Everything else (streaming, cancellation, etc.) can be added later.
 */
class IAgenticEngine {
public:
    virtual ~IAgenticEngine() = default;

    // Lifecycle
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;

    // Model
    virtual bool LoadModel(const std::string& path) = 0;
    virtual bool IsModelLoaded() const = 0;

    // Tokenization
    virtual std::vector<int> Tokenize(const std::string& text) = 0;

    // Generation (synchronous - simplest contract)
    virtual std::string Generate(
        const std::vector<int>& tokens,
        size_t maxTokens
    ) = 0;
};

} // namespace Agentic
} // namespace RawrXD
