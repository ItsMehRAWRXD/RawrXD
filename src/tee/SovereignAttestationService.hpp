// Phase D.16 Batch 3/5: Attestation Service
// Remote attestation and verification framework
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
namespace TEE {

// Forward declarations
struct AttestationReport;
struct VerificationPolicy;
struct AttestationResult;

// ============================================================================
// Attestation Types
// ============================================================================

enum class AttestationType {
    LOCAL = 0,
    REMOTE = 1,
    MUTUAL = 2,
    CHAINED = 3
};

enum class AttestationStatus {
    UNVERIFIED = 0,
    IN_PROGRESS = 1,
    VERIFIED = 2,
    FAILED = 3,
    EXPIRED = 4,
    REVOKED = 5
};

enum class VerificationLevel {
    NONE = 0,
    BASIC = 1,
    STANDARD = 2,
    STRICT = 3,
    MAXIMUM = 4
};

struct AttestationReport {
    std::string report_id;
    std::string enclave_id;
    AttestationType type;
    std::vector<uint8_t> quote;
    std::vector<uint8_t> report_data;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> certificate_chain;
    std::chrono::steady_clock::time_point generated_at;
    std::chrono::steady_clock::time_point expires_at;
    std::map<std::string, std::any> claims;
    std::map<std::string, std::any> platform_info;
};

struct VerificationPolicy {
    std::string policy_id;
    std::string name;
    VerificationLevel level;
    std::vector<std::string> required_claims;
    std::map<std::string, std::string> claim_values;
    std::vector<std::string> trusted_issuers;
    std::chrono::seconds max_age;
    bool require_revocation_check;
    bool require_tcb_up_to_date;
    std::map<std::string, std::any> custom_rules;
};

struct AttestationResult {
    std::string report_id;
    AttestationStatus status;
    bool verified;
    std::vector<std::string> passed_checks;
    std::vector<std::string> failed_checks;
    std::map<std::string, std::any> extracted_claims;
    std::chrono::steady_clock::time_point verified_at;
    std::string verifier_identity;
    std::vector<uint8_t> verification_signature;
};

// ============================================================================
// Quote Generator
// ============================================================================

class QuoteGenerator {
public:
    struct Config {
        std::string pce_path;
        std::string aesm_socket;
        bool use_dcap = true;
        int quote_version = 3;
    };
    
    explicit QuoteGenerator(const Config& config);
    ~QuoteGenerator();
    
    bool Initialize();
    void Shutdown();
    
    // Quote generation
    AttestationReport GenerateQuote(const std::string& enclave_id,
                                    const std::vector<uint8_t>& report_data);
    AttestationReport GenerateQuoteWithNonce(const std::string& enclave_id,
                                              const std::vector<uint8_t>& report_data,
                                              const std::vector<uint8_t>& nonce);
    
    // Report data
    std::vector<uint8_t> HashReportData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> CreateReportData(const std::map<std::string, std::any>& claims);
    
    // Platform info
    std::map<std::string, std::any> GetPlatformInfo();
    std::vector<uint8_t> GetTargetInfo();
    
private:
    Config config_;
    void* generator_context_;
    
    bool InitializeDCAP();
    bool InitializeEPID();
    std::vector<uint8_t> FetchQuoteDCAP(const std::vector<uint8_t>& report_data);
    std::vector<uint8_t> FetchQuoteEPID(const std::vector<uint8_t>& report_data);
};

// ============================================================================
// Quote Verifier
// ============================================================================

class QuoteVerifier {
public:
    struct Config {
        std::string pck_cache_dir;
        std::string tcb_info_url;
        std::string qe_identity_url;
        std::chrono::hours cache_ttl{24};
        bool allow_outdated_tcb = false;
        bool allow_debug_enclaves = false;
    };
    
    struct VerificationDetails {
        bool signature_valid;
        bool certificate_valid;
        bool tcb_up_to_date;
        bool enclave_identity_valid;
        bool qe_identity_valid;
        std::string tcb_level;
        std::vector<std::string> advisory_ids;
        std::chrono::steady_clock::time_point verification_time;
    };
    
    explicit QuoteVerifier(const Config& config);
    ~QuoteVerifier();
    
    bool Initialize();
    void Shutdown();
    
    // Verification
    AttestationResult VerifyQuote(const AttestationReport& report);
    AttestationResult VerifyQuoteWithPolicy(const AttestationReport& report,
                                            const VerificationPolicy& policy);
    
    // Detailed verification
    VerificationDetails GetVerificationDetails(const AttestationReport& report);
    bool VerifySignature(const AttestationReport& report);
    bool VerifyTCB(const AttestationReport& report);
    bool VerifyEnclaveIdentity(const AttestationReport& report);
    
    // Certificate validation
    bool ValidateCertificateChain(const std::vector<uint8_t>& chain);
    bool ValidatePCKCertificate(const std::vector<uint8_t>& cert);
    
    // TCB management
    bool UpdateTCBInfo();
    bool UpdateQEIdentity();
    std::map<std::string, std::any> GetCurrentTCBInfo();
    
private:
    Config config_;
    void* verifier_context_;
    std::map<std::string, std::any> tcb_cache_;
    mutable std::mutex cache_mutex_;
    
    bool FetchTCBInfoFromIntel();
    bool FetchQEIdentityFromIntel();
    bool VerifyQuoteSignature(const std::vector<uint8_t>& quote);
    std::map<std::string, std::any> ParseQuote(const std::vector<uint8_t>& quote);
};

// ============================================================================
// Attestation Service
// ============================================================================

class AttestationService {
public:
    struct Config {
        QuoteGenerator::Config generator;
        QuoteVerifier::Config verifier;
        std::string service_id;
        std::string service_key;
        bool enable_caching = true;
        std::chrono::minutes cache_duration{60};
    };
    
    struct AttestationRequest {
        std::string request_id;
        std::string enclave_id;
        AttestationType type;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> challenge;
        VerificationPolicy policy;
        std::chrono::steady_clock::time_point requested_at;
    };
    
    struct AttestationResponse {
        std::string request_id;
        AttestationResult result;
        std::vector<uint8_t> service_signature;
        std::chrono::steady_clock::time_point responded_at;
    };
    
    explicit AttestationService(const Config& config);
    ~AttestationService();
    
    bool Initialize();
    void Shutdown();
    
    // Service operations
    AttestationResponse ProcessRequest(const AttestationRequest& request);
    AttestationResponse GenerateAttestation(const std::string& enclave_id,
                                             const std::vector<uint8_t>& user_data);
    
    // Verification
    bool VerifyAttestation(const AttestationResult& result);
    bool VerifyAttestationChain(const std::vector<AttestationResult>& chain);
    
    // Policy management
    bool RegisterPolicy(const VerificationPolicy& policy);
    bool UpdatePolicy(const std::string& policy_id, const VerificationPolicy& policy);
    bool RemovePolicy(const std::string& policy_id);
    VerificationPolicy GetPolicy(const std::string& policy_id) const;
    std::vector<VerificationPolicy> GetAllPolicies() const;
    
    // Caching
    void CacheAttestation(const std::string& enclave_id, const AttestationResult& result);
    std::optional<AttestationResult> GetCachedAttestation(const std::string& enclave_id);
    void InvalidateCache(const std::string& enclave_id);
    
private:
    Config config_;
    std::unique_ptr<QuoteGenerator> generator_;
    std::unique_ptr<QuoteVerifier> verifier_;
    std::map<std::string, VerificationPolicy> policies_;
    std::map<std::string, std::pair<AttestationResult, std::chrono::steady_clock::time_point>> cache_;
    mutable std::mutex policies_mutex_;
    mutable std::mutex cache_mutex_;
    
    std::vector<uint8_t> SignResult(const AttestationResult& result);
    bool VerifyServiceSignature(const AttestationResult& result);
};

// ============================================================================
// Mutual Attestation
// ============================================================================

class MutualAttestation {
public:
    struct Config {
        std::chrono::seconds challenge_timeout{30};
        bool require_both_sides = true;
        bool bind_to_session = true;
    };
    
    struct AttestationChallenge {
        std::string challenge_id;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> expected_report_data;
        std::chrono::steady_clock::time_point expires_at;
    };
    
    struct MutualAttestationResult {
        std::string session_id;
        bool local_verified;
        bool remote_verified;
        AttestationResult local_result;
        AttestationResult remote_result;
        std::vector<uint8_t> session_key;
        std::chrono::steady_clock::time_point established_at;
    };
    
    explicit MutualAttestation(const Config& config);
    ~MutualAttestation();
    
    bool Initialize();
    void Shutdown();
    
    // Challenge/Response
    AttestationChallenge GenerateChallenge(const std::string& enclave_id);
    AttestationReport GenerateResponse(const AttestationChallenge& challenge,
                                        const std::string& enclave_id);
    bool VerifyResponse(const AttestationReport& response,
                       const AttestationChallenge& challenge);
    
    // Mutual attestation protocol
    MutualAttestationResult PerformMutualAttestation(const std::string& local_enclave_id,
                                                      const std::string& remote_enclave_id);
    
    // Session establishment
    std::vector<uint8_t> DeriveSessionKey(const MutualAttestationResult& result);
    bool BindToSession(const std::string& session_id, const MutualAttestationResult& result);
    
private:
    Config config_;
    std::map<std::string, AttestationChallenge> pending_challenges_;
    mutable std::mutex challenges_mutex_;
    std::unique_ptr<AttestationService> attestation_service_;
    
    void CleanupExpiredChallenges();
    std::vector<uint8_t> GenerateNonce();
};

// ============================================================================
// Attestation Runtime
// ============================================================================

class AttestationRuntime {
public:
    struct Config {
        AttestationService::Config service;
        MutualAttestation::Config mutual;
    };
    
    explicit AttestationRuntime(const Config& config);
    ~AttestationRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    AttestationService* GetService();
    MutualAttestation* GetMutualAttestation();
    
    // High-level API
    AttestationResult Attest(const std::string& enclave_id,
                             const std::vector<uint8_t>& user_data);
    bool Verify(const AttestationResult& result);
    
    MutualAttestationResult MutualAttest(const std::string& local_enclave_id,
                                         const std::string& remote_enclave_id);
    
    // Batch operations
    std::vector<AttestationResult> AttestMultiple(const std::vector<std::string>& enclave_ids,
                                                 const std::vector<uint8_t>& user_data);
    bool VerifyMultiple(const std::vector<AttestationResult>& results);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<AttestationService> service_;
    std::unique_ptr<MutualAttestation> mutual_attestation_;
};

} // namespace TEE
} // namespace Sovereign
