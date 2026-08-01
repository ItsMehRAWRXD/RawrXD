// src/security/CapabilityToken.hpp
// Every backend call is checked against a capability token before execution.
// Tokens are immutable after issuance and carry an audit trail.

#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <chrono>

// ---------------------------------------------------------------------------
// Permission scope — what a token allows
// ---------------------------------------------------------------------------
enum class PermissionScope : uint64_t {
    None          = 0x0000000000000000,
    Build         = 0x0000000000000001,  // Can invoke compiler / assembler
    Filesystem    = 0x0000000000000002,  // Can read/write project files
    Network       = 0x0000000000000004,  // Can make outbound connections
    Admin         = 0x0000000000000008,  // Can request elevation
    GpuAccess     = 0x0000000000000010,  // Can dispatch GPU compute
    DriverLoad    = 0x0000000000000020,  // Can load kernel drivers
    AuditRead     = 0x0000000000000040,  // Can read audit logs
    All           = 0xFFFFFFFFFFFFFFFF
};

inline PermissionScope operator|(PermissionScope a, PermissionScope b) {
    return static_cast<PermissionScope>(
        static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}
inline bool HasPermission(PermissionScope flags, PermissionScope perm) {
    return (static_cast<uint64_t>(flags) & static_cast<uint64_t>(perm)) != 0;
}

// ---------------------------------------------------------------------------
// A single capability token — issued per-backend, checked per-call
// ---------------------------------------------------------------------------
struct CapabilityToken {
    std::string     backendName;        // Which backend this token governs
    PermissionScope grantedPermissions; // What the backend is allowed to do
    PermissionScope deniedPermissions;  // Explicitly forbidden operations
    std::string     issuedBy;           // "system" | "user" | "admin"
    uint64_t        issuedAt;           // Unix timestamp ms
    uint64_t        expiresAt;          // 0 = no expiry
    std::string     tokenId;            // Unique identifier for audit trail

    bool IsAllowed(PermissionScope perm) const {
        if (HasPermission(deniedPermissions, perm)) return false;
        return HasPermission(grantedPermissions, perm);
    }

    bool IsExpired() const {
        if (expiresAt == 0) return false;
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return now > expiresAt;
    }

    std::string ToString() const {
        std::string s = "Token[" + tokenId + "] for " + backendName;
        s += " | Granted: " + std::to_string(static_cast<uint64_t>(grantedPermissions));
        s += " | Denied: " + std::to_string(static_cast<uint64_t>(deniedPermissions));
        s += " | Issuer: " + issuedBy;
        return s;
    }
};

// ---------------------------------------------------------------------------
// Token factory — creates scoped tokens for each backend type
// ---------------------------------------------------------------------------
struct CapabilityTokenFactory {
    static uint64_t NowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static CapabilityToken ForPowerShell() {
        CapabilityToken token;
        token.backendName        = "PowerShell";
        token.grantedPermissions = PermissionScope::Build
                                 | PermissionScope::Filesystem
                                 | PermissionScope::AuditRead;
        token.deniedPermissions  = PermissionScope::Network
                                 | PermissionScope::Admin
                                 | PermissionScope::DriverLoad
                                 | PermissionScope::GpuAccess;
        token.issuedBy           = "system";
        token.issuedAt           = NowMs();
        token.expiresAt          = 0;  // Session lifetime
        token.tokenId            = "TOKEN_PS_001";
        return token;
    }

    static CapabilityToken ForBareMetal() {
        CapabilityToken token;
        token.backendName        = "BareMetal";
        token.grantedPermissions = PermissionScope::Build
                                 | PermissionScope::Filesystem
                                 | PermissionScope::GpuAccess
                                 | PermissionScope::AuditRead;
        token.deniedPermissions  = PermissionScope::Network
                                 | PermissionScope::Admin
                                 | PermissionScope::DriverLoad;
        token.issuedBy           = "system";
        token.issuedAt           = NowMs();
        token.expiresAt          = 0;
        token.tokenId            = "TOKEN_BM_001";
        return token;
    }

    static CapabilityToken ForRemoteAgent() {
        CapabilityToken token;
        token.backendName        = "RemoteAgent";
        token.grantedPermissions = PermissionScope::Build
                                 | PermissionScope::Network
                                 | PermissionScope::AuditRead;
        token.deniedPermissions  = PermissionScope::Filesystem
                                 | PermissionScope::Admin
                                 | PermissionScope::DriverLoad
                                 | PermissionScope::GpuAccess;
        token.issuedBy           = "admin";
        token.issuedAt           = NowMs();
        token.expiresAt          = NowMs() + 3600000;  // 1 hour
        token.tokenId            = "TOKEN_RA_001";
        return token;
    }

    static CapabilityToken ForSandbox() {
        CapabilityToken token;
        token.backendName        = "Sandbox";
        token.grantedPermissions = PermissionScope::Build;
        token.deniedPermissions  = PermissionScope::Filesystem
                                 | PermissionScope::Network
                                 | PermissionScope::Admin
                                 | PermissionScope::DriverLoad
                                 | PermissionScope::GpuAccess
                                 | PermissionScope::AuditRead;
        token.issuedBy           = "system";
        token.issuedAt           = NowMs();
        token.expiresAt          = NowMs() + 300000;  // 5 minutes
        token.tokenId            = "TOKEN_SB_001";
        return token;
    }
};
