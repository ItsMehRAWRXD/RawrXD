// ============================================================================
// IExecutionBackend Interface
// ============================================================================
// Abstract base for all RawrXD execution backends
// ============================================================================

#pragma once

#include "ExecutionRequest.hpp"
#include "ExecutionResult.hpp"

#include <string>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Execution Backend Interface
// ============================================================================
// All backends (simulator, Vulkan, CPU, etc.) implement this contract
// ============================================================================

class IExecutionBackend {
public:
    virtual ~IExecutionBackend() = default;
    
    // Backend identification
    virtual const char* GetName() const = 0;
    virtual const char* GetVersion() const = 0;
    
    // Lifecycle
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;
    
    // Capability queries
    virtual bool SupportsModel(const std::string& model_path) const = 0;
    virtual bool SupportsStreaming() const = 0;
    virtual bool SupportsCancellation() const = 0;
    
    // Synchronous execution
    virtual ExecutionResult Execute(const ExecutionRequest& request) = 0;
    
    // Asynchronous execution with callback
    using TokenCallback = std::function<void(const std::string& token, bool is_last)>;
    using CompletionCallback = std::function<void(const ExecutionResult& result)>;
    
    virtual bool ExecuteAsync(const ExecutionRequest& request,
                               TokenCallback on_token,
                               CompletionCallback on_complete) = 0;
    
    // Cancellation
    virtual void Cancel() = 0;
    
    // Health check
    virtual bool IsHealthy() const = 0;
};

// Factory type for backend creation
using BackendFactory = std::function<std::unique_ptr<IExecutionBackend>()>;

} // namespace Execution
} // namespace RawrXD
