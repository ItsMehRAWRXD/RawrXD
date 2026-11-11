/**
 * TenantSecurity.hpp
 *
 * Phase P Batch 4/5: Tenant Security & Data Isolation
 *
 * Security features for multi-tenant environments including data isolation,
 * encryption, and access control.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace MultiTenancy {

// ============================================================================
// Forward Declarations
// ============================================================================

class TenantEncryption;
class TenantAccessControl;
class DataMasking;
class AuditLogger;

// ============================================================================
// Encryption Level
// ============================================================================

enum class EncryptionLevel {
    NONE,
    DATABASE,
    TABLE,
    COLUMN,
    ROW,
    FIELD
};

// ============================================================================
// Tenant Encryption
// ============================================================================

/**
 * Per-tenant encryption management.
 */
class TenantEncryption {
public:
    struct Config {
        std::string tenantId;
        EncryptionLevel level;
        std::string algorithm;  // AES-256-GCM, ChaCha20-Poly1305
        std::optional<std::string> masterKeyId;
        bool enableKeyRotation;
        std::chrono::days keyRotationInterval;
        std::vector<std::string> encryptedFields;
    };
    
    struct EncryptionKey {
        std::string keyId;
        std::vector<uint8_t> keyData;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
        bool isActive;
    };
    
    explicit TenantEncryption(const Config& config);
    
    // Key management
    void GenerateKey();
    void RotateKey();
    void RevokeKey(const std::string& keyId);
    std::vector<EncryptionKey> GetKeys() const;
    EncryptionKey GetActiveKey() const;
    
    // Encryption/Decryption
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext,
                                     const std::string& fieldName);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext);
    std::string EncryptField(const std::string& fieldName,
                             const std::string& value);
    std::string DecryptField(const std::string& fieldName,
                             const std::string& ciphertext);
    
    // Searchable encryption
    std::string GenerateSearchIndex(const std::string& fieldName,
                                     const std::string& value);
    bool MatchesSearchIndex(const std::string& fieldName,
                            const std::string& ciphertext,
                            const std::string& searchValue);
    
    // Tokenization
    std::string Tokenize(const std::string& sensitiveData);
    std::string Detokenize(const std::string& token);
    
    // Key wrapping
    std::vector<uint8_t> WrapKey(const std::vector<uint8_t>& keyToWrap,
                                  const std::string& wrappingKeyId);
    std::vector<uint8_t> UnwrapKey(const std::vector<uint8_t>& wrappedKey,
                                    const std::string& wrappingKeyId);
    
    // Statistics
    struct EncryptionStats {
        uint64_t bytesEncrypted;
        uint64_t bytesDecrypted;
        uint64_t encryptionOperations;
        uint64_t decryptionOperations;
        double averageEncryptionTimeMs;
        double averageDecryptionTimeMs;
    };
    EncryptionStats GetStats() const;
    
private:
    Config config_;
    std::vector<EncryptionKey> keys_;
    mutable std::mutex mutex_;
    
    EncryptionStats stats_;
    mutable std::mutex statsMutex_;
    
    std::map<std::string, std::string> tokenVault_;
    mutable std::mutex vaultMutex_;
    
    EncryptionKey GenerateNewKey();
    void ReEncryptData(const std::string& oldKeyId, const std::string& newKeyId);
};

// ============================================================================
// Access Control
// ============================================================================

/**
 * Tenant-scoped access control.
 */
class TenantAccessControl {
public:
    struct Permission {
        std::string resource;
        std::string action;  // read, write, delete, execute
        std::optional<std::string> condition;
    };
    
    struct Role {
        std::string roleId;
        std::string name;
        std::string description;
        std::vector<Permission> permissions;
        std::map<std::string, std::string> metadata;
    };
    
    struct Policy {
        std::string policyId;
        std::string name;
        std::vector<std::string> subjects;  // users, groups, roles
        std::vector<Permission> permissions;
        std::vector<std::string> resources;
        std::optional<std::string> condition;
        std::string effect;  // allow, deny
    };
    
    explicit TenantAccessControl(const std::string& tenantId);
    
    // Role management
    void CreateRole(const Role& role);
    void UpdateRole(const std::string& roleId, const Role& role);
    void DeleteRole(const std::string& roleId);
    std::optional<Role> GetRole(const std::string& roleId) const;
    std::vector<Role> GetRoles() const;
    
    // Policy management
    void CreatePolicy(const Policy& policy);
    void UpdatePolicy(const std::string& policyId, const Policy& policy);
    void DeletePolicy(const std::string& policyId);
    std::optional<Policy> GetPolicy(const std::string& policyId) const;
    std::vector<Policy> GetPolicies() const;
    
    // User-role assignment
    void AssignRole(const std::string& userId, const std::string& roleId);
    void RevokeRole(const std::string& userId, const std::string& roleId);
    std::vector<std::string> GetUserRoles(const std::string& userId) const;
    bool HasRole(const std::string& userId, const std::string& roleId) const;
    
    // Permission checking
    bool CheckPermission(const std::string& userId,
                         const std::string& resource,
                         const std::string& action) const;
    bool CheckPermission(const std::string& userId,
                         const std::string& resource,
                         const std::string& action,
                         const std::map<std::string, std::any>& context) const;
    
    // Resource-level permissions
    void GrantResourcePermission(const std::string& userId,
                                  const std::string& resource,
                                  const std::string& action);
    void RevokeResourcePermission(const std::string& userId,
                                     const std::string& resource,
                                     const std::string& action);
    
    // Inheritance
    void SetRoleHierarchy(const std::string& parentRoleId,
                          const std::string& childRoleId);
    std::vector<std::string> GetInheritedRoles(const std::string& roleId) const;
    
    // Validation
    bool ValidatePolicy(const Policy& policy) const;
    std::vector<std::string> GetPolicyConflicts() const;
    
private:
    std::string tenantId_;
    std::map<std::string, Role> roles_;
    std::map<std::string, Policy> policies_;
    std::map<std::string, std::vector<std::string>> userRoles_;
    std::map<std::string, std::vector<std::string>> roleHierarchy_;
    mutable std::mutex mutex_;
    
    std::vector<Permission> GetEffectivePermissions(const std::string& userId) const;
    bool EvaluateCondition(const std::string& condition,
                           const std::map<std::string, std::any>& context) const;
};

// ============================================================================
// Data Masking
// ============================================================================

/**
 * Data masking for sensitive information.
 */
class DataMasking {
public:
    enum class MaskingType {
        FULL,
        PARTIAL,
        HASH,
        TOKENIZE,
        REDACT,
        SHUFFLE,
        RANDOMIZE,
        NULLIFY
    };
    
    struct MaskingRule {
        std::string field;
        MaskingType type;
        std::optional<uint32_t> visibleChars;
        std::optional<std::string> maskChar;
        std::optional<std::string> format;
        std::vector<std::string> roles;  // Roles that can see unmasked
        std::optional<std::string> condition;
    };
    
    explicit DataMasking(const std::string& tenantId);
    
    // Rule management
    void AddRule(const MaskingRule& rule);
    void RemoveRule(const std::string& field);
    void UpdateRule(const std::string& field, const MaskingRule& rule);
    std::optional<MaskingRule> GetRule(const std::string& field) const;
    std::vector<MaskingRule> GetRules() const;
    
    // Masking
    std::string Mask(const std::string& field, const std::string& value) const;
    std::string Mask(const std::string& field,
                      const std::string& value,
                      const std::string& userRole) const;
    
    std::map<std::string, std::string> MaskRecord(
        const std::map<std::string, std::string>& record) const;
    std::map<std::string, std::string> MaskRecord(
        const std::map<std::string, std::string>& record,
        const std::string& userRole) const;
    
    // Specific maskers
    std::string MaskEmail(const std::string& email) const;
    std::string MaskPhone(const std::string& phone) const;
    std::string MaskCreditCard(const std::string& card) const;
    std::string MaskSSN(const std::string& ssn) const;
    std::string MaskName(const std::string& name) const;
    std::string MaskIP(const std::string& ip) const;
    
    // Dynamic masking
    void SetDynamicMasking(bool enabled);
    bool IsDynamicMaskingEnabled() const;
    
private:
    std::string tenantId_;
    std::map<std::string, MaskingRule> rules_;
    bool dynamicMasking_;
    mutable std::mutex mutex_;
    
    std::string ApplyMasking(const std::string& value, const MaskingRule& rule) const;
    bool CanUnmask(const MaskingRule& rule, const std::string& userRole) const;
};

// ============================================================================
// Audit Logger
// ============================================================================

/**
 * Tenant-scoped audit logging.
 */
class AuditLogger {
public:
    enum class EventType {
        CREATE,
        READ,
        UPDATE,
        DELETE,
        LOGIN,
        LOGOUT,
        PERMISSION_CHANGE,
        CONFIG_CHANGE,
        EXPORT,
        IMPORT,
        BACKUP,
        RESTORE
    };
    
    struct AuditEvent {
        std::string eventId;
        EventType type;
        std::string tenantId;
        std::string userId;
        std::optional<std::string> sessionId;
        std::string resource;
        std::string action;
        std::optional<std::string> resourceId;
        std::map<std::string, std::any> beforeState;
        std::map<std::string, std::any> afterState;
        std::chrono::system_clock::time_point timestamp;
        std::optional<std::string> ipAddress;
        std::optional<std::string> userAgent;
        bool success;
        std::optional<std::string> error;
        std::map<std::string, std::string> metadata;
    };
    
    struct Config {
        std::string storagePath;
        std::chrono::seconds retentionPeriod;
        uint64_t maxEventsPerFile;
        bool encryptLogs;
        bool compressLogs;
        std::vector<EventType> loggedEvents;
    };
    
    explicit AuditLogger(const Config& config);
    ~AuditLogger();
    
    // Logging
    void Log(const AuditEvent& event);
    void Log(EventType type,
             const std::string& tenantId,
             const std::string& userId,
             const std::string& resource,
             const std::string& action);
    
    // Querying
    std::vector<AuditEvent> Query(const std::string& tenantId,
                                     std::chrono::system_clock::time_point from,
                                     std::chrono::system_clock::time_point to) const;
    std::vector<AuditEvent> QueryByUser(const std::string& tenantId,
                                          const std::string& userId) const;
    std::vector<AuditEvent> QueryByResource(const std::string& tenantId,
                                               const std::string& resource) const;
    std::vector<AuditEvent> QueryByEventType(const std::string& tenantId,
                                                EventType type) const;
    
    // Export
    void ExportToCsv(const std::string& filePath,
                     const std::string& tenantId,
                     std::chrono::system_clock::time_point from,
                     std::chrono::system_clock::time_point to) const;
    void ExportToJson(const std::string& filePath,
                      const std::string& tenantId,
                      std::chrono::system_clock::time_point from,
                      std::chrono::system_clock::time_point to) const;
    
    // Retention
    void PurgeOldLogs();
    void PurgeTenantLogs(const std::string& tenantId);
    
    // Statistics
    struct AuditStats {
        uint64_t totalEventsLogged;
        uint64_t eventsByType[12];  // One per EventType
        std::map<std::string, uint64_t> eventsByTenant;
        uint64_t storageUsedBytes;
    };
    AuditStats GetStats() const;
    
private:
    Config config_;
    
    std::queue<AuditEvent> eventQueue_;
    mutable std::mutex queueMutex_;
    
    std::thread writerThread_;
    std::atomic<bool> stopWriter_;
    
    AuditStats stats_;
    mutable std::mutex statsMutex_;
    
    void WriterLoop();
    void FlushEvents();
    void WriteEvent(const AuditEvent& event);
    std::string EventToString(const AuditEvent& event) const;
    std::string EventTypeToString(EventType type) const;
};

// ============================================================================
// Tenant Security Manager
// ============================================================================

/**
 * Central tenant security manager.
 */
class TenantSecurityManager {
public:
    struct Config {
        bool enableEncryptionByDefault;
        EncryptionLevel defaultEncryptionLevel;
        bool enableAuditLogging;
        bool enableDataMasking;
        std::chrono::seconds auditRetention;
        bool requireMFA;
        uint32_t maxLoginAttempts;
        std::chrono::minutes lockoutDuration;
    };
    
    explicit TenantSecurityManager(const Config& config);
    ~TenantSecurityManager();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Per-tenant security
    std::shared_ptr<TenantEncryption> GetEncryption(const std::string& tenantId);
    std::shared_ptr<TenantAccessControl> GetAccessControl(const std::string& tenantId);
    std::shared_ptr<DataMasking> GetDataMasking(const std::string& tenantId);
    std::shared_ptr<AuditLogger> GetAuditLogger(const std::string& tenantId);
    
    // Security policies
    void SetTenantSecurityPolicy(const std::string& tenantId,
                                  const Config& policy);
    Config GetTenantSecurityPolicy(const std::string& tenantId) const;
    
    // Compliance
    enum class ComplianceStandard {
        SOC2,
        ISO27001,
        GDPR,
        HIPAA,
        PCI_DSS
    };
    
    bool CheckCompliance(const std::string& tenantId,
                         ComplianceStandard standard) const;
    std::vector<std::string> GetComplianceViolations(
        const std::string& tenantId,
        ComplianceStandard standard) const;
    
    // Security reports
    struct SecurityReport {
        std::string tenantId;
        std::chrono::system_clock::time_point generatedAt;
        bool encryptionEnabled;
        EncryptionLevel encryptionLevel;
        uint64_t activeUsers;
        uint64_t failedLogins;
        uint64_t permissionViolations;
        std::vector<std::string> recommendations;
    };
    
    SecurityReport GenerateSecurityReport(const std::string& tenantId) const;
    std::vector<SecurityReport> GenerateAllReports() const;
    
    // Incident response
    void ReportSecurityIncident(const std::string& tenantId,
                                 const std::string& incidentType,
                                 const std::string& description);
    void LockdownTenant(const std::string& tenantId,
                        const std::string& reason);
    void UnlockTenant(const std::string& tenantId);
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<TenantEncryption>> encryptions_;
    std::map<std::string, std::shared_ptr<TenantAccessControl>> accessControls_;
    std::map<std::string, std::shared_ptr<DataMasking>> maskings_;
    std::map<std::string, std::shared_ptr<AuditLogger>> auditLoggers_;
    mutable std::mutex mutex_;
    
    void InitializeTenantSecurity(const std::string& tenantId);
};

} // namespace MultiTenancy
