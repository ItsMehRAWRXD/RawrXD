#include "execution_capability.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <stdexcept>

namespace RawrXD {

// ============================================================================
// ExecutionCapability Implementation
// ============================================================================

ExecutionCapability::ExecutionCapability(Type type, uint64_t nonce)
    : m_type(type)
    , m_nonce(nonce)
    , m_valid(type != Type::INVALID)
    , m_expired(false)
{
}

ExecutionCapability::ExecutionCapability(ExecutionCapability&& other) noexcept
    : m_type(other.m_type)
    , m_nonce(other.m_nonce)
    , m_valid(other.m_valid)
    , m_expired(other.m_expired)
{
    // Invalidate source
    other.m_valid = false;
    other.m_expired = true;
}

ExecutionCapability& ExecutionCapability::operator=(ExecutionCapability&& other) noexcept {
    if (this != &other) {
        m_type = other.m_type;
        m_nonce = other.m_nonce;
        m_valid = other.m_valid;
        m_expired = other.m_expired;
        
        // Invalidate source
        other.m_valid = false;
        other.m_expired = true;
    }
    return *this;
}

std::string ExecutionCapability::ToString() const {
    std::stringstream ss;
    ss << "Capability[";
    switch (m_type) {
        case Type::INVALID: ss << "INVALID"; break;
        case Type::LOCAL_GGUF: ss << "LOCAL_GGUF"; break;
        case Type::LOCAL_OLLAMA: ss << "LOCAL_OLLAMA"; break;
        case Type::REMOTE_CLOUD: ss << "REMOTE_CLOUD"; break;
        case Type::HYBRID: ss << "HYBRID"; break;
    }
    ss << ", nonce=" << std::hex << m_nonce;
    ss << ", valid=" << (IsValid() ? "yes" : "no") << "]";
    return ss.str();
}

bool ExecutionCapability::operator==(const ExecutionCapability& other) const {
    return m_type == other.m_type && m_nonce == other.m_nonce;
}

bool ExecutionCapability::operator<(const ExecutionCapability& other) const {
    if (m_type != other.m_type) return m_type < other.m_type;
    return m_nonce < other.m_nonce;
}

// ============================================================================
// TokenFactory Implementation
// 
// NOTE: TokenFactory is now in TokenAuthority to separate concerns.
// TokenAuthority is the ONLY entity that can mint capability tokens.
// This prevents the gateway from becoming a monolithic authority.
// ============================================================================

// ============================================================================
// ScopedCapability Implementation
// ============================================================================

ScopedCapability::ScopedCapability(ExecutionCapability& cap)
    : m_cap(&cap)
    , m_valid(cap.IsValid())
{
    if (!m_valid) {
        throw std::runtime_error("ScopedCapability created with invalid token");
    }
}

ScopedCapability::~ScopedCapability() {
    if (m_cap && m_valid) {
        m_cap->Expire();
    }
}

// ============================================================================
// CapabilityControlledBackend Implementation
// ============================================================================

CapabilityControlledBackend::CapabilityControlledBackend(ExecutionCapability&& cap)
    : m_capability(std::move(cap))
{
    if (!m_capability.IsValid()) {
        throw std::runtime_error("Backend created with invalid capability");
    }
}

void CapabilityControlledBackend::VerifyCapability() const {
    std::lock_guard<std::mutex> lock(m_verifyMutex);
    if (!m_capability.IsValid()) {
        throw std::runtime_error("Backend operation rejected: invalid capability");
    }
}

bool CapabilityControlledBackend::HasValidCapability() const {
    std::lock_guard<std::mutex> lock(m_verifyMutex);
    return m_capability.IsValid();
}

} // namespace RawrXD
