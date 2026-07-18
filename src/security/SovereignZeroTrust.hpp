// Phase D.7 Batch 1/5: Zero-Trust Architecture
// Identity-Based Security and Micro-Segmentation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace Sovereign {
namespace Security {

// ============================================================================
// Identity Types
// ============================================================================

enum class IdentityType {
    SERVICE = 0,
    USER = 1,
    WORKLOAD = 2,
    DEVICE = 3,
    NODE = 4
};

enum class TrustLevel {
    UNTRUSTED = 0,
    BASIC = 1,
    VERIFIED = 2,
    HIGH = 3,
    MAXIMUM = 4
};

struct ServiceIdentity {
    std::string service_id;
    std::string service_name;
    std::string namespace_;
    std::string version;
    std::vector<std::string> labels;
    std::string spiffe_id;
    std::string certificate_fingerprint;
    TrustLevel trust_level = TrustLevel::UNTRUSTED;
    std::chrono::steady_clock::time_point issued_at;
    std::chrono::steady_clock::time_point expires_at;
    std::map<std::string, std::string> claims;
};

struct UserIdentity {
    std::string user_id;
    std::string username;
    std::string email;
    std::vector<std::string> groups;
    std::vector<std::string> roles;
    std::string mfa_status;
    TrustLevel trust_level = TrustLevel::UNTRUSTED;
    std::chrono::steady_clock::time_point last_authenticated;
    std::map<std::string, std::string> attributes;
};

// ============================================================================
// Policy Engine
// ============================================================================

enum class PolicyEffect {
    ALLOW = 0,
    DENY = 1,
    AUDIT = 2
};

struct AccessPolicy {
    std::string policy_id;
    std::string name;
    std::string description;
    PolicyEffect effect = PolicyEffect::DENY;
    
    // Principals (who)
    std::vector<std::string> principals;  // service IDs, user IDs, groups
    std::vector<std::string> principal_types;
    
    // Actions (what)
    std::vector<std::string> actions;  // "read", "write", "delete", "execute"
    
    // Resources (where)
    std::vector<std::string> resources;
    std::vector<std::string> resource_types;
    
    // Conditions (when/where/how)
    struct Conditions {
        std::vector<std::string> time_ranges;  // "09:00-17:00"
        std::vector<std::string> ip_ranges;
        std::vector<std::string> required_mfa;
        int min_trust_level = 0;
        bool require_device_trust = false;
        std::map<std::string, std::string> custom;
    } conditions;
    
    int priority = 0;
    bool enabled = true;
};

class PolicyEngine {
public:
    struct Config {
        bool enable_policy_caching = true;
        int cache_ttl_seconds = 300;
        bool enforce_strict_ordering = true;
        int max_policy_evaluation_ms = 100;
    };
    
    explicit PolicyEngine(const Config& config);
    
    bool Initialize();
    
    // Policy management
    bool CreatePolicy(const AccessPolicy& policy);
    bool UpdatePolicy(const std::string& policy_id, const AccessPolicy& policy);
    bool DeletePolicy(const std::string& policy_id);
    AccessPolicy GetPolicy(const std::string& policy_id) const;
    std::vector<AccessPolicy> GetPolicies() const;
    
    // Authorization
    struct AuthorizationRequest {
        std::string principal_id;
        IdentityType principal_type;
        std::string action;
        std::string resource;
        std::map<std::string, std::string> context;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    struct AuthorizationResponse {
        bool allowed = false;
        std::string policy_id;
        PolicyEffect effect;
        std::string reason;
        std::vector<std::string> matched_policies;
        std::chrono::steady_clock::time_point evaluated_at;
    };
    
    AuthorizationResponse Authorize(const AuthorizationRequest& request);
    
    // Bulk evaluation
    std::vector<AuthorizationResponse> AuthorizeBulk(
        const std::vector<AuthorizationRequest>& requests);
    
private:
    Config config_;
    
    mutable std::mutex policies_mutex_;
    std::map<std::string, AccessPolicy> policies_;
    
    AuthorizationResponse EvaluatePolicy(const AccessPolicy& policy,
                                         const AuthorizationRequest& request);
    bool EvaluateConditions(const AccessPolicy::Conditions& conditions,
                           const AuthorizationRequest& request);
};

// ============================================================================
// Certificate Authority
// ============================================================================

class CertificateAuthority {
public:
    struct Config {
        std::string ca_cert_path;
        std::string ca_key_path;
        int cert_ttl_hours = 24;
        int rotation_buffer_hours = 2;
        bool enable_auto_rotation = true;
    };
    
    struct CertificateRequest {
        std::string identity;
        IdentityType type;
        std::vector<std::string> sans;  // Subject Alternative Names
        std::string spiffe_id;
        int ttl_hours = 24;
    };
    
    struct CertificateResponse {
        std::string certificate_pem;
        std::string private_key_pem;
        std::string ca_chain_pem;
        std::string serial_number;
        std::chrono::steady_clock::time_point issued_at;
        std::chrono::steady_clock::time_point expires_at;
    };
    
    explicit CertificateAuthority(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Certificate issuance
    CertificateResponse IssueCertificate(const CertificateRequest& request);
    bool RevokeCertificate(const std::string& serial_number);
    bool RenewCertificate(const std::string& serial_number);
    
    // Validation
    bool ValidateCertificate(const std::string& certificate_pem);
    ServiceIdentity ExtractIdentity(const std::string& certificate_pem);
    
    // Rotation
    void ScheduleRotation(const std::string& identity, int hours_before_expiry);
    std::vector<std::string> GetExpiringCertificates(int hours_threshold);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread rotation_thread_;
    
    void RotationLoop();
};

// ============================================================================
// Micro-Segmentation
// ============================================================================

struct SecuritySegment {
    std::string segment_id;
    std::string name;
    std::string description;
    std::vector<std::string> selector_labels;
    std::vector<std::string> allowed_ingress_segments;
    std::vector<std::string> allowed_egress_segments;
    bool default_deny = true;
    bool enable_logging = true;
};

class MicroSegmentation {
public:
    struct Config {
        bool enable_default_deny = true;
        bool enable_segment_isolation = true;
        int policy_sync_interval_seconds = 30;
    };
    
    explicit MicroSegmentation(const Config& config);
    
    bool Initialize();
    
    // Segment management
    bool CreateSegment(const SecuritySegment& segment);
    bool UpdateSegment(const std::string& segment_id, const SecuritySegment& segment);
    bool DeleteSegment(const std::string& segment_id);
    SecuritySegment GetSegment(const std::string& segment_id) const;
    std::vector<SecuritySegment> GetSegments() const;
    
    // Workload assignment
    bool AssignWorkload(const std::string& workload_id, const std::string& segment_id);
    bool RemoveWorkload(const std::string& workload_id);
    std::string GetWorkloadSegment(const std::string& workload_id) const;
    
    // Traffic evaluation
    struct TrafficRequest {
        std::string source_workload;
        std::string destination_workload;
        int destination_port = 0;
        std::string protocol;
        std::map<std::string, std::string> labels;
    };
    
    struct TrafficDecision {
        bool allowed = false;
        std::string source_segment;
        std::string destination_segment;
        std::string reason;
        bool log = true;
    };
    
    TrafficDecision EvaluateTraffic(const TrafficRequest& request);
    
private:
    Config config_;
    
    mutable std::mutex segments_mutex_;
    std::map<std::string, SecuritySegment> segments_;
    std::map<std::string, std::string> workload_assignments_;
};

// ============================================================================
// Zero-Trust Runtime
// ============================================================================

class ZeroTrustRuntime {
public:
    struct Config {
        PolicyEngine::Config policy_engine;
        CertificateAuthority::Config certificate_authority;
        MicroSegmentation::Config micro_segmentation;
        bool enforce_mtls = true;
        bool enable_continuous_auth = true;
        int auth_refresh_interval_seconds = 300;
    };
    
    explicit ZeroTrustRuntime(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Identity verification
    bool VerifyIdentity(const std::string& identity, IdentityType type);
    TrustLevel GetTrustLevel(const std::string& identity);
    bool UpdateTrustLevel(const std::string& identity, TrustLevel level);
    
    // Access control
    bool AuthorizeAccess(const std::string& principal,
                         const std::string& action,
                         const std::string& resource);
    
    // Network segmentation
    bool AllowTraffic(const std::string& source,
                      const std::string& destination,
                      int port);
    
    // Certificate management
    std::string GetServiceCertificate(const std::string& service_id);
    bool RotateServiceCertificate(const std::string& service_id);
    
private:
    Config config_;
    std::unique_ptr<PolicyEngine> policy_engine_;
    std::unique_ptr<CertificateAuthority> certificate_authority_;
    std::unique_ptr<MicroSegmentation> micro_segmentation_;
};

} // namespace Security
} // namespace Sovereign
