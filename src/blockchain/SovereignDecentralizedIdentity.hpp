// Phase D.17 Batch 5/5: Decentralized Identity
// DID and verifiable credentials
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Blockchain {

// Forward declarations
struct DIDDocument;
struct VerifiableCredential;
struct IdentityClaim;

// ============================================================================
// Decentralized Identity Types
// ============================================================================

enum class DIDMethod {
    ETHR = 0,
    WEB = 1,
    KEY = 2,
    SOV = 3,
    SOVEREIGN = 4
};

enum class CredentialStatus {
    ACTIVE = 0,
    REVOKED = 1,
    EXPIRED = 2,
    SUSPENDED = 3
};

enum class ProofType {
    ECDSA = 0,
    ED25519 = 1,
    BLS = 2,
    JWT = 3,
    LD_PROOF = 4
};

struct DID {
    std::string did;
    DIDMethod method;
    std::string identifier;
    std::chrono::steady_clock::time_point created_at;
    bool is_active;
};

struct DIDDocument {
    std::string id;
    std::vector<std::string> context;
    std::vector<std::map<std::string, std::any>> verification_method;
    std::vector<std::string> authentication;
    std::vector<std::string> assertion_method;
    std::vector<std::string> key_agreement;
    std::vector<std::string> capability_invocation;
    std::vector<std::string> capability_delegation;
    std::vector<std::map<std::string, std::any>> service;
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point updated;
};

struct VerifiableCredential {
    std::string id;
    std::vector<std::string> context;
    std::vector<std::string> type;
    std::string issuer;
    std::string subject;
    std::chrono::steady_clock::time_point issuance_date;
    std::chrono::steady_clock::time_point expiration_date;
    std::map<std::string, std::any> claims;
    std::map<std::string, std::any> proof;
    CredentialStatus status;
};

struct IdentityClaim {
    std::string claim_id;
    std::string did;
    std::string claim_type;
    std::map<std::string, std::any> data;
    std::vector<std::string> attestors;
    std::chrono::steady_clock::time_point issued_at;
    std::chrono::steady_clock::time_point expires_at;
    bool verified;
};

// ============================================================================
// DID Registry
// ============================================================================

class DIDRegistry {
public:
    struct Config {
        DIDMethod default_method = DIDMethod::SOVEREIGN;
        std::string registry_contract;
        bool enable_resolution = true;
    };
    
    struct RegistrationResult {
        bool success;
        DID did;
        std::string error_message;
    };
    
    explicit DIDRegistry(const Config& config);
    ~DIDRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Registration
    RegistrationResult RegisterDID(const std::string& public_key);
    RegistrationResult RegisterDIDWithMethod(const std::string& public_key, DIDMethod method);
    bool DeactivateDID(const std::string& did);
    bool ReactivateDID(const std::string& did);
    
    // Resolution
    DIDDocument ResolveDID(const std::string& did);
    std::optional<DID> ResolveDIDDocument(const std::string& did);
    bool ValidateDID(const std::string& did);
    
    // Document management
    bool UpdateDIDDocument(const std::string& did, const DIDDocument& document);
    bool AddVerificationMethod(const std::string& did, const std::map<std::string, std::any>& method);
    bool RemoveVerificationMethod(const std::string& did, const std::string& method_id);
    bool AddService(const std::string& did, const std::map<std::string, std::any>& service);
    bool RemoveService(const std::string& did, const std::string& service_id);
    
    // Queries
    std::vector<DID> GetDIDsByController(const std::string& controller) const;
    std::vector<DID> GetDIDsByPublicKey(const std::string& public_key) const;
    
private:
    Config config_;
    std::map<std::string, DIDDocument> documents_;
    mutable std::mutex registry_mutex_;
    
    std::string GenerateDID(DIDMethod method, const std::string& public_key);
    std::string GenerateIdentifier(DIDMethod method, const std::string& public_key);
};

// ============================================================================
// Credential Manager
// ============================================================================

class CredentialManager {
public:
    struct Config {
        bool verify_signatures = true;
        bool check_revocation = true;
        std::chrono::seconds verification_timeout{30};
    };
    
    struct IssuanceResult {
        bool success;
        VerifiableCredential credential;
        std::string error_message;
    };
    
    struct VerificationResult {
        bool valid;
        std::vector<std::string> checks;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };
    
    explicit CredentialManager(const Config& config);
    ~CredentialManager();
    
    bool Initialize();
    void Shutdown();
    
    // Issuance
    IssuanceResult IssueCredential(const std::string& issuer_did, const std::string& subject_did,
                                    const std::vector<std::string>& types,
                                    const std::map<std::string, std::any>& claims,
                                    std::chrono::years validity);
    IssuanceResult IssueVerifiableCredential(const std::string& issuer_did, const std::string& subject_did,
                                              const std::map<std::string, std::any>& credential_data);
    
    // Verification
    VerificationResult VerifyCredential(const VerifiableCredential& credential);
    bool VerifySignature(const VerifiableCredential& credential);
    bool VerifyIssuer(const VerifiableCredential& credential);
    bool VerifyExpiration(const VerifiableCredential& credential);
    bool CheckRevocationStatus(const VerifiableCredential& credential);
    
    // Revocation
    bool RevokeCredential(const std::string& credential_id, const std::string& reason);
    bool SuspendCredential(const std::string& credential_id, const std::string& reason);
    bool ReactivateCredential(const std::string& credential_id);
    
    // Queries
    std::vector<VerifiableCredential> GetCredentialsBySubject(const std::string& subject_did) const;
    std::vector<VerifiableCredential> GetCredentialsByIssuer(const std::string& issuer_did) const;
    std::vector<VerifiableCredential> GetCredentialsByType(const std::string& type) const;
    VerifiableCredential GetCredential(const std::string& credential_id) const;
    
private:
    Config config_;
    std::map<std::string, VerifiableCredential> credentials_;
    std::map<std::string, CredentialStatus> revocation_list_;
    mutable std::mutex credentials_mutex_;
    
    std::string GenerateCredentialId();
    std::map<std::string, std::any> CreateProof(const VerifiableCredential& credential,
                                                 const std::string& issuer_did);
};

// ============================================================================
// Identity Resolver
// ============================================================================

class IdentityResolver {
public:
    struct Config {
        std::vector<std::string> resolver_endpoints;
        std::chrono::seconds cache_ttl{3600};
        bool enable_caching = true;
    };
    
    struct ResolutionResult {
        bool success;
        DIDDocument document;
        std::vector<std::string> did_resolution_metadata;
        std::vector<std::string> did_document_metadata;
        std::string error_message;
    };
    
    explicit IdentityResolver(const Config& config);
    ~IdentityResolver();
    
    bool Initialize();
    void Shutdown();
    
    // Resolution
    ResolutionResult Resolve(const std::string& did);
    ResolutionResult ResolveWithAccept(const std::string& did, const std::string& accept_type);
    std::vector<uint8_t> ResolveRepresentation(const std::string& did, const std::string& representation);
    
    // Dereferencing
    std::optional<std::any> Dereference(const std::string& did_url);
    std::vector<std::any> DereferenceContent(const std::string& did_url);
    
    // Caching
    void CacheDocument(const std::string& did, const DIDDocument& document);
    void InvalidateCache(const std::string& did);
    void ClearCache();
    
private:
    Config config_;
    std::map<std::string, std::pair<DIDDocument, std::chrono::steady_clock::time_point>> cache_;
    mutable std::mutex cache_mutex_;
    
    ResolutionResult ResolveFromChain(const std::string& did);
    ResolutionResult ResolveFromHTTP(const std::string& did, const std::string& endpoint);
};

// ============================================================================
// Identity Claims Registry
// ============================================================================

class IdentityClaimsRegistry {
public:
    struct Config {
        bool require_attestation = true;
        int min_attestors = 1;
        std::chrono::days claim_validity{365};
    };
    
    struct ClaimResult {
        bool success;
        IdentityClaim claim;
        std::string error_message;
    };
    
    explicit IdentityClaimsRegistry(const Config& config);
    ~IdentityClaimsRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Claim registration
    ClaimResult RegisterClaim(const std::string& did, const std::string& claim_type,
                               const std::map<std::string, std::any>& data);
    bool AttestClaim(const std::string& claim_id, const std::string& attestor_did);
    bool RevokeClaim(const std::string& claim_id, const std::string& reason);
    
    // Verification
    bool VerifyClaim(const std::string& claim_id);
    bool VerifyClaimData(const std::string& claim_id, const std::map<std::string, std::any>& expected_data);
    std::vector<std::string> GetAttestors(const std::string& claim_id) const;
    
    // Queries
    std::vector<IdentityClaim> GetClaimsByDID(const std::string& did) const;
    std::vector<IdentityClaim> GetClaimsByType(const std::string& claim_type) const;
    std::vector<IdentityClaim> GetVerifiedClaims(const std::string& did) const;
    IdentityClaim GetClaim(const std::string& claim_id) const;
    
private:
    Config config_;
    std::map<std::string, IdentityClaim> claims_;
    mutable std::mutex claims_mutex_;
    
    std::string GenerateClaimId();
    bool ValidateClaimData(const std::string& claim_type, const std::map<std::string, std::any>& data);
};

// ============================================================================
// Decentralized Identity Runtime
// ============================================================================

class DecentralizedIdentityRuntime {
public:
    struct Config {
        DIDRegistry::Config registry;
        CredentialManager::Config credentials;
        IdentityResolver::Config resolver;
        IdentityClaimsRegistry::Config claims;
    };
    
    explicit DecentralizedIdentityRuntime(const Config& config);
    ~DecentralizedIdentityRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    DIDRegistry* GetRegistry();
    CredentialManager* GetCredentialManager();
    IdentityResolver* GetResolver();
    IdentityClaimsRegistry* GetClaimsRegistry();
    
    // High-level API
    std::string CreateIdentity(const std::string& public_key);
    std::string IssueCredential(const std::string& issuer_did, const std::string& subject_did,
                                 const std::map<std::string, std::any>& claims);
    bool VerifyIdentity(const std::string& did);
    bool VerifyCredential(const std::string& credential_id);
    
    DIDDocument GetDocument(const std::string& did);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<DIDRegistry> registry_;
    std::unique_ptr<CredentialManager> credential_manager_;
    std::unique_ptr<IdentityResolver> resolver_;
    std::unique_ptr<IdentityClaimsRegistry> claims_registry_;
};

} // namespace Blockchain
} // namespace Sovereign
