#include "token_authority.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace RawrXD {

// ============================================================================
// TokenAuthority Implementation
// ============================================================================

TokenAuthority& TokenAuthority::instance() {
    static TokenAuthority instance;
    return instance;
}

TokenAuthority::TokenAuthority() {
    // Initialize signing key with random bytes
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    for (size_t i = 0; i < m_signingKey.size(); i += 8) {
        uint64_t val = dis(gen);
        std::memcpy(&m_signingKey[i], &val, std::min(size_t(8), m_signingKey.size() - i));
    }
}

TokenAuthority::~TokenAuthority() = default;

std::string TokenAuthority::generateAuthorizationProof(RuntimeMode mode, const std::string& requesterId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    std::stringstream ss;
    ss << requesterId << ":" << static_cast<int>(mode) << ":" << timestamp;
    
    // HMAC-SHA256
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLen;
    
    HMAC(EVP_sha256(),
         m_signingKey.data(), static_cast<int>(m_signingKey.size()),
         reinterpret_cast<const unsigned char*>(ss.str().data()), ss.str().length(),
         hmac, &hmacLen);
    
    // Convert to hex string
    std::stringstream proof;
    proof << ss.str() << ":";
    for (unsigned int i = 0; i < hmacLen; ++i) {
        proof << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hmac[i]);
    }
    
    return proof.str();
}

bool TokenAuthority::verifyAuthorizationProof(const std::string& proof) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Parse proof: requesterId:mode:timestamp:hmac
    size_t lastColon = proof.rfind(':');
    if (lastColon == std::string::npos) return false;
    
    std::string payload = proof.substr(0, lastColon);
    std::string receivedHmac = proof.substr(lastColon + 1);
    
    // Recompute HMAC
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLen;
    
    HMAC(EVP_sha256(),
         m_signingKey.data(), static_cast<int>(m_signingKey.size()),
         reinterpret_cast<const unsigned char*>(payload.data()), payload.length(),
         hmac, &hmacLen);
    
    // Convert to hex for comparison
    std::stringstream computedHmac;
    for (unsigned int i = 0; i < hmacLen; ++i) {
        computedHmac << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hmac[i]);
    }
    
    // Check timestamp (proofs expire after 1 hour)
    size_t secondColon = payload.rfind(':');
    if (secondColon == std::string::npos) return false;
    
    try {
        long timestamp = std::stol(payload.substr(secondColon + 1));
        auto now = std::chrono::system_clock::now();
        auto current = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        
        if (current - timestamp > 3600) return false; // Expired
    } catch (...) {
        return false;
    }
    
    return computedHmac.str() == receivedHmac;
}

ExecutionCapability TokenAuthority::mintLocalGGUFCapability(const std::string& authorizationProof) {
    if (!verifyAuthorizationProof(authorizationProof)) {
        throw std::runtime_error("Invalid authorization proof");
    }
    return mintInternal(ExecutionCapability::Type::LOCAL_GGUF, "gateway");
}

ExecutionCapability TokenAuthority::mintLocalOllamaCapability(const std::string& authorizationProof) {
    if (!verifyAuthorizationProof(authorizationProof)) {
        throw std::runtime_error("Invalid authorization proof");
    }
    return mintInternal(ExecutionCapability::Type::LOCAL_OLLAMA, "gateway");
}

ExecutionCapability TokenAuthority::mintRemoteCloudCapability(const std::string& authorizationProof) {
    if (!verifyAuthorizationProof(authorizationProof)) {
        throw std::runtime_error("Invalid authorization proof");
    }
    return mintInternal(ExecutionCapability::Type::REMOTE_CLOUD, "gateway");
}

ExecutionCapability TokenAuthority::mintHybridCapability(const std::string& authorizationProof) {
    if (!verifyAuthorizationProof(authorizationProof)) {
        throw std::runtime_error("Invalid authorization proof");
    }
    return mintInternal(ExecutionCapability::Type::HYBRID, "gateway");
}

ExecutionCapability TokenAuthority::mintInternal(ExecutionCapability::Type type, 
                                                const std::string& requesterId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Generate unique nonce
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t nonce;
    do {
        nonce = dis(gen);
    } while (m_revokedNonces.count(nonce) > 0);
    
    // Record mint
    MintRecord record;
    record.timestamp = std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    record.type = type;
    record.requesterId = requesterId;
    record.revoked = false;
    m_mintHistory.push_back(record);
    
    return ExecutionCapability(type, nonce);
}

void TokenAuthority::revokeCapability(const ExecutionCapability& cap) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_revokedNonces.insert(cap.GetNonce());
    
    // Update history
    for (auto& record : m_mintHistory) {
        if (record.type == cap.GetType()) {
            record.revoked = true;
        }
    }
}

bool TokenAuthority::isRevoked(const ExecutionCapability& cap) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_revokedNonces.count(cap.GetNonce()) > 0;
}

std::vector<TokenAuthority::MintRecord> TokenAuthority::getMintHistory(int limit) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<MintRecord> result;
    int start = std::max(0, static_cast<int>(m_mintHistory.size()) - limit);
    
    for (size_t i = start; i < m_mintHistory.size(); ++i) {
        result.push_back(m_mintHistory[i]);
    }
    
    return result;
}

// ============================================================================
// CapabilityGrant Implementation
// ============================================================================

CapabilityGrant::CapabilityGrant(TokenAuthority& authority, 
                                  RuntimeMode allowedMode,
                                  const std::string& granteeId)
    : m_authority(authority)
    , m_allowedMode(allowedMode)
    , m_granteeId(granteeId)
{
}

std::optional<ExecutionCapability> CapabilityGrant::requestCapability(ExecutionCapability::Type type) {
    // Check if type is allowed for this mode
    bool allowed = false;
    switch (m_allowedMode) {
        case RuntimeMode::StrictLocal:
            allowed = (type == ExecutionCapability::Type::LOCAL_GGUF ||
                      type == ExecutionCapability::Type::LOCAL_OLLAMA);
            break;
        case RuntimeMode::HybridControlled:
            allowed = (type == ExecutionCapability::Type::LOCAL_GGUF ||
                      type == ExecutionCapability::Type::LOCAL_OLLAMA ||
                      type == ExecutionCapability::Type::HYBRID);
            break;
        case RuntimeMode::FullyDistributed:
            allowed = true;
            break;
    }
    
    if (!allowed) {
        return std::nullopt;
    }
    
    // Generate proof for delegation
    std::string proof = m_authority.generateAuthorizationProof(m_allowedMode, m_granteeId);
    
    ExecutionCapability cap = m_authority.mintInternal(type, m_granteeId);
    m_issuedNonces.push_back(cap.GetNonce());
    
    return cap;
}

void CapabilityGrant::revokeAll() {
    for (uint64_t nonce : m_issuedNonces) {
        // Find and revoke by nonce
        // Note: In real implementation, would need to track full capability objects
    }
    m_issuedNonces.clear();
}

} // namespace RawrXD
