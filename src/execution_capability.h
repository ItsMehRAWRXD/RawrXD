#pragma once
#ifndef RAWRXD_EXECUTION_CAPABILITY_H
#define RAWRXD_EXECUTION_CAPABILITY_H

#include <memory>
#include <string>
#include <mutex>
#include <atomic>

namespace RawrXD {

// ============================================================================
// CAPABILITY TOKEN SYSTEM
// 
// Backends are ONLY accessible with a valid capability token.
// Tokens are non-copyable and non-forgeable.
// This is structural enforcement, not runtime convention.
// ============================================================================

// Forward declarations
class TokenAuthority;
class InferenceGateway;
class ExecutionPolicyRouter;

// ============================================================================
// Capability Token - The ONLY way to access backends
// ============================================================================
class ExecutionCapability {
public:
    // Token type - defined before use
    enum class Type { INVALID, LOCAL_GGUF, LOCAL_OLLAMA, REMOTE_CLOUD, HYBRID };

    // Tokens can only be created by TokenAuthority
    // TokenFactory is now in TokenAuthority to separate concerns
    friend class TokenAuthority;
    
    // Factory access is delegated to TokenAuthority
    // This prevents gateway from becoming monolithic authority

    // Non-copyable (prevents token duplication)
    ExecutionCapability(const ExecutionCapability&) = delete;
    ExecutionCapability& operator=(const ExecutionCapability&) = delete;

    // Movable (transfer ownership)
    ExecutionCapability(ExecutionCapability&&) noexcept;
    ExecutionCapability& operator=(ExecutionCapability&&) noexcept;

    // Token validation
    bool IsValid() const { return m_valid && !m_expired; }
    void Expire() { m_expired = true; }
    
    Type GetType() const { return m_type; }
    
    std::string ToString() const;

    // Comparison for containers
    bool operator==(const ExecutionCapability& other) const;
    bool operator<(const ExecutionCapability& other) const;

private:
    // Private constructor - only TokenFactory can create
    explicit ExecutionCapability(Type type, uint64_t nonce);
    
    Type m_type = Type::INVALID;
    uint64_t m_nonce = 0;
    bool m_valid = false;
    bool m_expired = false;
    
    // Friend access for verification
    friend class InferenceGateway;
    friend class ExecutionPolicyRouter;
};

// ============================================================================
// Scoped Capability - RAII guard
// ============================================================================
class ScopedCapability {
public:
    explicit ScopedCapability(ExecutionCapability& cap);
    ~ScopedCapability();
    
    // Non-copyable, non-movable
    ScopedCapability(const ScopedCapability&) = delete;
    ScopedCapability& operator=(const ScopedCapability&) = delete;
    ScopedCapability(ScopedCapability&&) = delete;
    ScopedCapability& operator=(ScopedCapability&&) = delete;

    bool IsValid() const { return m_valid; }

private:
    ExecutionCapability* m_cap;
    bool m_valid;
};

// ============================================================================
// Backend Access Control
// 
// All backends inherit from this to enforce capability-based access
// ============================================================================
class CapabilityControlledBackend {
protected:
    // Protected constructor - requires capability to instantiate (moves it)
    explicit CapabilityControlledBackend(ExecutionCapability&& cap);
    
    // Verify capability before any operation
    void VerifyCapability() const;
    
    // Check if capability is still valid
    bool HasValidCapability() const;

private:
    ExecutionCapability m_capability;
    mutable std::mutex m_verifyMutex;
};

// ============================================================================
// Compile-time enforcement helpers
// ============================================================================

// Mark functions that require capability
#define REQUIRES_CAPABILITY(cap) \
    static_assert(std::is_same_v<std::decay_t<decltype(cap)>, ExecutionCapability>, \
                  "REQUIRES_CAPABILITY expects ExecutionCapability");

// Mark backend classes
#define BACKEND_CLASS \
    : private CapabilityControlledBackend

} // namespace RawrXD

#endif // RAWRXD_EXECUTION_CAPABILITY_H
