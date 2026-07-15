#pragma once
#ifndef RAWRXD_TOKEN_AUTHORITY_H
#define RAWRXD_TOKEN_AUTHORITY_H

#include "execution_capability.h"
#include <memory>
#include <mutex>

namespace RawrXD {

// ============================================================================
// TOKEN AUTHORITY - Separated from Gateway
// 
// This is the ONLY entity that can mint capability tokens.
// It is intentionally separate from ExecutionPolicyRouter and InferenceGateway
// to prevent authority monolith.
// ============================================================================

class TokenAuthority {
public:
    // Singleton access - but with restricted delegation
    static TokenAuthority& instance();

    // Token minting - requires explicit authorization proof
    ExecutionCapability mintLocalGGUFCapability(const std::string& authorizationProof);
    ExecutionCapability mintLocalOllamaCapability(const std::string& authorizationProof);
    ExecutionCapability mintRemoteCloudCapability(const std::string& authorizationProof);
    ExecutionCapability mintHybridCapability(const std::string& authorizationProof);

    // Authorization proof generation (for delegation)
    std::string generateAuthorizationProof(RuntimeMode mode, const std::string& requesterId);
    
    // Verification
    bool verifyAuthorizationProof(const std::string& proof) const;
    
    // Revocation
    void revokeCapability(const ExecutionCapability& cap);
    bool isRevoked(const ExecutionCapability& cap) const;

    // Audit
    struct MintRecord {
        std::string timestamp;
        ExecutionCapability::Type type;
        std::string requesterId;
        bool revoked;
    };
    std::vector<MintRecord> getMintHistory(int limit = 100) const;

private:
    TokenAuthority() = default;
    ~TokenAuthority() = default;
    
    TokenAuthority(const TokenAuthority&) = delete;
    TokenAuthority& operator=(const TokenAuthority&) = delete;

    mutable std::mutex m_mutex;
    std::set<uint64_t> m_revokedNonces;
    std::vector<MintRecord> m_mintHistory;
    
    // Cryptographic secret for proof validation
    std::array<uint8_t, 32> m_signingKey;
    
    ExecutionCapability mintInternal(ExecutionCapability::Type type, 
                                      const std::string& requesterId);
};

// ============================================================================
// Capability Grant - Delegation pattern
// ============================================================================
class CapabilityGrant {
public:
    CapabilityGrant(TokenAuthority& authority, 
                     RuntimeMode allowedMode,
                     const std::string& granteeId);
    
    // Delegated minting with restrictions
    std::optional<ExecutionCapability> requestCapability(ExecutionCapability::Type type);
    
    // Revoke all capabilities issued under this grant
    void revokeAll();

private:
    TokenAuthority& m_authority;
    RuntimeMode m_allowedMode;
    std::string m_granteeId;
    std::vector<uint64_t> m_issuedNonces;
};

} // namespace RawrXD

#endif // RAWRXD_TOKEN_AUTHORITY_H
