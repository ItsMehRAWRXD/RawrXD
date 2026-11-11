/**
 * Authentication.hpp
 *
 * Phase G Batch 1/5: Authentication & Identity Management
 *
 * Multi-factor authentication with support for passwords, tokens, OAuth2,
 * OIDC, LDAP, and SAML. Provides secure identity verification.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <optional>
#include <functional>

namespace Security {

// ============================================================================
// Forward Declarations
// ============================================================================

class Identity;
class Credential;
class AuthenticationProvider;
class SessionManager;

// ============================================================================
// Identity
// ============================================================================

/**
 * Represents a user or service identity.
 */
class Identity {
public:
    enum class Type {
        USER,           // Human user
        SERVICE,        // Service account
        APPLICATION,    // Application identity
        DEVICE          // IoT/device identity
    };
    
    std::string id;                 // Unique identifier
    std::string username;           // Human-readable name
    std::string email;              // Email address
    Type type;                      // Identity type
    std::vector<std::string> roles; // Assigned roles
    std::map<std::string, std::string> attributes; // Custom attributes
    bool enabled;                   // Account status
    uint64_t createdAt;
    uint64_t updatedAt;
    uint64_t lastLoginAt;
    
    Identity();
    
    // Check if identity has role
    bool HasRole(const std::string& role) const;
    
    // Get attribute
    std::string GetAttribute(const std::string& key) const;
    void SetAttribute(const std::string& key, const std::string& value);
    
    // Serialization
    std::string ToJson() const;
    static Identity FromJson(const std::string& json);
};

// ============================================================================
// Credential Types
// ============================================================================

enum class CredentialType {
    PASSWORD,       // Password-based
    TOKEN,          // API token
    CERTIFICATE,    // X.509 certificate
    OTP,            // One-time password
    WEBAUTHN,       // FIDO2/WebAuthn
    OAUTH2,         // OAuth2 token
    OIDC,           // OpenID Connect
    LDAP,           // LDAP bind
    SAML            // SAML assertion
};

std::string CredentialTypeToString(CredentialType type);

// ============================================================================
// Credential
// ============================================================================

/**
 * Base class for authentication credentials.
 */
class Credential {
public:
    virtual ~Credential() = default;
    virtual CredentialType GetType() const = 0;
    virtual std::string GetIdentifier() const = 0;
    virtual bool IsValid() const = 0;
};

/**
 * Password credential.
 */
class PasswordCredential : public Credential {
public:
    std::string username;
    std::string password;
    
    CredentialType GetType() const override { return CredentialType::PASSWORD; }
    std::string GetIdentifier() const override { return username; }
    bool IsValid() const override { return !username.empty() && !password.empty(); }
};

/**
 * Token credential.
 */
class TokenCredential : public Credential {
public:
    std::string token;
    std::string tokenType;  // bearer, basic, etc.
    
    CredentialType GetType() const override { return CredentialType::TOKEN; }
    std::string GetIdentifier() const override { return token.substr(0, 16); }
    bool IsValid() const override { return !token.empty(); }
};

/**
 * Certificate credential.
 */
class CertificateCredential : public Credential {
public:
    std::string certificatePem;
    std::string commonName;
    std::string fingerprint;
    
    CredentialType GetType() const override { return CredentialType::CERTIFICATE; }
    std::string GetIdentifier() const override { return fingerprint; }
    bool IsValid() const override { return !certificatePem.empty(); }
};

/**
 * WebAuthn credential.
 */
class WebAuthnCredential : public Credential {
public:
    std::string credentialId;
    std::string clientDataJSON;
    std::string authenticatorData;
    std::string signature;
    
    CredentialType GetType() const override { return CredentialType::WEBAUTHN; }
    std::string GetIdentifier() const override { return credentialId; }
    bool IsValid() const override { return !credentialId.empty(); }
};

// ============================================================================
// Authentication Result
// ============================================================================

/**
 * Result of authentication attempt.
 */
struct AuthenticationResult {
    bool success;
    std::string identityId;
    std::string sessionToken;
    std::vector<std::string> factorsUsed;
    uint64_t expiresAt;
    std::string errorMessage;
    std::map<std::string, std::string> metadata;
    
    static AuthenticationResult Success(const std::string& identityId,
                                         const std::string& sessionToken);
    static AuthenticationResult Failure(const std::string& error);
};

// ============================================================================
// Authentication Provider
// ============================================================================

/**
 * Base class for authentication providers.
 */
class AuthenticationProvider {
public:
    virtual ~AuthenticationProvider() = default;
    
    // Provider info
    virtual std::string GetName() const = 0;
    virtual std::string GetType() const = 0;
    
    // Authentication
    virtual AuthenticationResult Authenticate(const Credential& credential) = 0;
    
    // Identity management
    virtual bool CreateIdentity(const Identity& identity);
    virtual bool UpdateIdentity(const Identity& identity);
    virtual bool DeleteIdentity(const std::string& identityId);
    virtual std::optional<Identity> GetIdentity(const std::string& identityId);
    virtual std::optional<Identity> FindByUsername(const std::string& username);
    
    // Credential management
    virtual bool SetPassword(const std::string& identityId, const std::string& password);
    virtual bool ValidatePassword(const std::string& identityId, const std::string& password);
    virtual bool ChangePassword(const std::string& identityId,
                                 const std::string& oldPassword,
                                 const std::string& newPassword);
    
    // MFA
    virtual bool EnableMFA(const std::string& identityId, CredentialType factor);
    virtual bool DisableMFA(const std::string& identityId, CredentialType factor);
    virtual std::vector<CredentialType> GetEnabledMFA(const std::string& identityId);
};

// ============================================================================
// Password Provider
// ============================================================================

/**
 * Local password-based authentication.
 */
class PasswordProvider : public AuthenticationProvider {
public:
    struct Config {
        uint32_t minLength = 12;
        bool requireUppercase = true;
        bool requireLowercase = true;
        bool requireDigits = true;
        bool requireSpecial = true;
        uint32_t maxAgeDays = 90;
        uint32_t historyCount = 5;
        uint32_t maxAttempts = 5;
        uint64_t lockoutDurationMs = 900000;  // 15 minutes
    };
    
    explicit PasswordProvider(const Config& config);
    
    std::string GetName() const override { return "password"; }
    std::string GetType() const override { return "local"; }
    
    AuthenticationResult Authenticate(const Credential& credential) override;
    
    bool SetPassword(const std::string& identityId, const std::string& password) override;
    bool ValidatePassword(const std::string& identityId, const std::string& password) override;
    bool ChangePassword(const std::string& identityId,
                         const std::string& oldPassword,
                         const std::string& newPassword) override;
    
    // Password policy
    bool ValidatePasswordPolicy(const std::string& password);
    std::string GetPasswordPolicyDescription() const;
    
private:
    Config config_;
    
    struct PasswordEntry {
        std::string hash;
        uint64_t createdAt;
        uint64_t expiresAt;
    };
    
    std::map<std::string, PasswordEntry> passwords_;  // identityId -> password
    std::map<std::string, std::vector<std::string>> passwordHistory_;
    std::map<std::string, uint32_t> failedAttempts_;
    std::map<std::string, uint64_t> lockoutUntil_;
    mutable std::mutex mutex_;
    
    std::string HashPassword(const std::string& password);
    bool VerifyPassword(const std::string& password, const std::string& hash);
    bool IsLockedOut(const std::string& identityId);
    void RecordFailedAttempt(const std::string& identityId);
    void ClearFailedAttempts(const std::string& identityId);
};

// ============================================================================
// Token Provider
// ============================================================================

/**
 * API token-based authentication.
 */
class TokenProvider : public AuthenticationProvider {
public:
    struct Config {
        uint64_t tokenLifetimeMs = 86400000;  // 24 hours
        uint64_t refreshLifetimeMs = 604800000; // 7 days
        uint32_t maxTokensPerIdentity = 10;
    };
    
    explicit TokenProvider(const Config& config);
    
    std::string GetName() const override { return "token"; }
    std::string GetType() const override { return "bearer"; }
    
    AuthenticationResult Authenticate(const Credential& credential) override;
    
    // Token management
    std::string GenerateToken(const std::string& identityId);
    std::string GenerateRefreshToken(const std::string& identityId);
    bool RevokeToken(const std::string& token);
    bool RevokeAllTokens(const std::string& identityId);
    std::optional<std::string> ValidateToken(const std::string& token);
    std::optional<std::string> RefreshToken(const std::string& refreshToken);
    
private:
    Config config_;
    
    struct TokenEntry {
        std::string identityId;
        uint64_t createdAt;
        uint64_t expiresAt;
        bool revoked;
    };
    
    std::map<std::string, TokenEntry> tokens_;
    mutable std::mutex mutex_;
    
    std::string GenerateSecureToken();
    void CleanupExpiredTokens();
};

// ============================================================================
// Certificate Provider
// ============================================================================

/**
 * X.509 certificate-based authentication.
 */
class CertificateProvider : public AuthenticationProvider {
public:
    struct Config {
        std::string caCertPath;
        bool verifyChain = true;
        bool verifyCRL = false;
        uint64_t crlUpdateIntervalMs = 86400000;
    };
    
    explicit CertificateProvider(const Config& config);
    
    std::string GetName() const override { return "certificate"; }
    std::string GetType() const override { return "x509"; }
    
    AuthenticationResult Authenticate(const Credential& credential) override;
    
    // Certificate management
    bool RegisterCertificate(const std::string& identityId, const std::string& certificatePem);
    bool RevokeCertificate(const std::string& fingerprint);
    std::optional<Identity> FindByCertificate(const std::string& certificatePem);
    
private:
    Config config_;
    
    struct CertificateEntry {
        std::string identityId;
        std::string certificatePem;
        std::string fingerprint;
        uint64_t expiresAt;
        bool revoked;
    };
    
    std::map<std::string, CertificateEntry> certificates_;  // fingerprint -> entry
    mutable std::mutex mutex_;
    
    std::string CalculateFingerprint(const std::string& certificatePem);
    bool VerifyCertificate(const std::string& certificatePem);
    std::string ExtractCommonName(const std::string& certificatePem);
};

// ============================================================================
// WebAuthn Provider
// ============================================================================

/**
 * FIDO2/WebAuthn authentication provider.
 */
class WebAuthnProvider : public AuthenticationProvider {
public:
    struct Config {
        std::string rpId;           // Relying party ID
        std::string rpName;         // Relying party name
        std::string origin;         // Expected origin
        bool requireResidentKey = false;
        std::string userVerification = "preferred";  // required, preferred, discouraged
    };
    
    explicit WebAuthnProvider(const Config& config);
    
    std::string GetName() const override { return "webauthn"; }
    std::string GetType() const override { return "fido2"; }
    
    AuthenticationResult Authenticate(const Credential& credential) override;
    
    // Registration
    struct RegistrationOptions {
        std::string challenge;
        std::map<std::string, std::string> user;
        std::vector<std::string> pubKeyCredParams;
        std::map<std::string, std::string> authenticatorSelection;
    };
    
    RegistrationOptions BeginRegistration(const std::string& identityId);
    bool FinishRegistration(const std::string& identityId,
                            const WebAuthnCredential& credential);
    
    // Authentication
    struct AuthenticationOptions {
        std::string challenge;
        std::vector<std::string> allowCredentials;
    };
    
    AuthenticationOptions BeginAuthentication(const std::string& identityId);
    
private:
    Config config_;
    
    struct WebAuthnEntry {
        std::string identityId;
        std::string credentialId;
        std::string publicKey;
        uint64_t signCount;
        uint64_t createdAt;
    };
    
    std::map<std::string, WebAuthnEntry> credentials_;  // credentialId -> entry
    mutable std::mutex mutex_;
    
    std::string GenerateChallenge();
    bool VerifySignature(const WebAuthnCredential& credential,
                         const WebAuthnEntry& entry);
};

// ============================================================================
// OAuth2/OIDC Provider
// ============================================================================

/**
 * OAuth2/OpenID Connect authentication provider.
 */
class OAuth2Provider : public AuthenticationProvider {
public:
    struct Config {
        std::string issuer;                 // OIDC issuer URL
        std::string clientId;
        std::string clientSecret;
        std::string redirectUri;
        std::vector<std::string> scopes;
        std::map<std::string, std::string> endpoints;
    };
    
    explicit OAuth2Provider(const Config& config);
    
    std::string GetName() const override { return "oauth2"; }
    std::string GetType() const override { return "oidc"; }
    
    AuthenticationResult Authenticate(const Credential& credential) override;
    
    // OAuth2 flow
    std::string GetAuthorizationUrl(const std::string& state);
    AuthenticationResult HandleCallback(const std::string& code,
                                         const std::string& state);
    
    // Token validation
    std::optional<Identity> ValidateAccessToken(const std::string& token);
    std::optional<Identity> ValidateIdToken(const std::string& token);
    
private:
    Config config_;
    
    struct OAuth2State {
        std::string state;
        uint64_t expiresAt;
        std::string pkceCodeVerifier;
    };
    
    std::map<std::string, OAuth2State> states_;
    mutable std::mutex mutex_;
    
    std::string GenerateState();
    std::string GeneratePKCE();
    std::optional<std::string> ExchangeCode(const std::string& code);
    Identity ParseIdToken(const std::string& token);
};

// ============================================================================
// Multi-Factor Authentication
// ============================================================================

/**
 * MFA coordinator for multiple authentication factors.
 */
class MultiFactorAuth {
public:
    struct Config {
        uint32_t requiredFactors = 2;
        uint64_t mfaTimeoutMs = 300000;  // 5 minutes
        bool allowRememberDevice = true;
        uint64_t rememberDeviceDays = 30;
    };
    
    explicit MultiFactorAuth(const Config& config);
    
    // Register factor for identity
    bool RegisterFactor(const std::string& identityId,
                        CredentialType factor,
                        std::unique_ptr<Credential> credential);
    
    // Begin MFA challenge
    struct MFAChallenge {
        std::string challengeId;
        std::vector<CredentialType> requiredFactors;
        uint64_t expiresAt;
    };
    
    MFAChallenge BeginChallenge(const std::string& identityId);
    
    // Verify MFA factor
    bool VerifyFactor(const std::string& challengeId,
                      CredentialType factor,
                      const Credential& credential);
    
    // Check if MFA complete
    bool IsComplete(const std::string& challengeId);
    
    // Complete MFA and get result
    AuthenticationResult Complete(const std::string& challengeId);
    
private:
    Config config_;
    
    struct MFAState {
        std::string identityId;
        std::set<CredentialType> verifiedFactors;
        std::set<CredentialType> requiredFactors;
        uint64_t expiresAt;
    };
    
    std::map<std::string, MFAState> challenges_;
    mutable std::mutex mutex_;
    
    std::map<std::string, std::map<CredentialType, std::unique_ptr<Credential>>> registeredFactors_;
};

// ============================================================================
// Session Manager
// ============================================================================

/**
 * Manages authenticated sessions.
 */
class SessionManager {
public:
    struct Config {
        uint64_t sessionLifetimeMs = 3600000;      // 1 hour
        uint64_t idleTimeoutMs = 900000;           // 15 minutes
        bool slidingExpiration = true;
        uint32_t maxSessionsPerIdentity = 5;
    };
    
    explicit SessionManager(const Config& config);
    
    // Session lifecycle
    std::string CreateSession(const std::string& identityId,
                               const std::vector<std::string>& factors);
    bool ValidateSession(const std::string& sessionToken);
    bool RefreshSession(const std::string& sessionToken);
    bool TerminateSession(const std::string& sessionToken);
    void TerminateAllSessions(const std::string& identityId);
    
    // Session info
    struct SessionInfo {
        std::string sessionToken;
        std::string identityId;
        std::vector<std::string> factors;
        uint64_t createdAt;
        uint64_t expiresAt;
        uint64_t lastActivityAt;
        std::string ipAddress;
        std::string userAgent;
    };
    
    std::optional<SessionInfo> GetSessionInfo(const std::string& sessionToken);
    std::vector<SessionInfo> GetActiveSessions(const std::string& identityId);
    
    // Cleanup
    void CleanupExpiredSessions();
    
private:
    Config config_;
    
    struct Session {
        SessionInfo info;
        bool revoked;
    };
    
    std::map<std::string, Session> sessions_;
    mutable std::mutex mutex_;
    
    std::string GenerateSessionToken();
    void UpdateActivity(const std::string& sessionToken);
};

// ============================================================================
// Authentication Manager
// ============================================================================

/**
 * Central authentication coordinator.
 */
class AuthenticationManager {
public:
    struct Config {
        bool enableMFA = true;
        bool enableSessionManagement = true;
        bool enablePasswordPolicy = true;
        std::vector<CredentialType> allowedMethods;
    };
    
    AuthenticationManager();
    ~AuthenticationManager();
    
    // Initialize
    bool Initialize(const Config& config);
    void Shutdown();
    
    // Provider management
    void RegisterProvider(std::unique_ptr<AuthenticationProvider> provider);
    void UnregisterProvider(const std::string& name);
    AuthenticationProvider* GetProvider(const std::string& name);
    std::vector<std::string> GetProviderNames() const;
    
    // Authentication
    AuthenticationResult Authenticate(const Credential& credential);
    AuthenticationResult AuthenticateWithProvider(const std::string& providerName,
                                                   const Credential& credential);
    
    // MFA
    bool RequiresMFA(const std::string& identityId);
    MultiFactorAuth::MFAChallenge BeginMFA(const std::string& identityId);
    AuthenticationResult CompleteMFA(const std::string& challengeId,
                                    CredentialType factor,
                                    const Credential& credential);
    
    // Session management
    std::string CreateSession(const std::string& identityId,
                               const std::vector<std::string>& factors);
    bool ValidateSession(const std::string& sessionToken);
    bool TerminateSession(const std::string& sessionToken);
    
    // Identity lookup
    std::optional<Identity> GetIdentity(const std::string& identityId);
    std::optional<Identity> FindByUsername(const std::string& username);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    
    std::map<std::string, std::unique_ptr<AuthenticationProvider>> providers_;
    mutable std::mutex providersMutex_;
    
    std::unique_ptr<MultiFactorAuth> mfa_;
    std::unique_ptr<SessionManager> sessions_;
    
    std::map<std::string, Identity> identities_;
    mutable std::mutex identitiesMutex_;
};

} // namespace Security
