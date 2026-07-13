# Phase D.4 Batch 3/5 — Production Security Layer

## Overview

This batch implements a comprehensive production security layer for the RawrXD sovereign runtime, providing authentication, authorization, API key management, audit logging, and security policy enforcement. This is essential for production deployment and enterprise use.

## Architecture

```
SovereignSecurityLayer (Singleton)
├── APIKeyManager
│   ├── GenerateKey() — Create new API keys
│   ├── ValidateKey() — Verify key authenticity
│   ├── RevokeKey() — Deactivate keys
│   ├── RotateKey() — Key rotation
│   └── Persistence (Save/Load from file)
├── PermissionManager
│   ├── HasPermission() — Check individual permissions
│   ├── HasAnyPermission() — Check permission sets
│   ├── Grant/Revoke operations
│   └── Role-based permissions (viewer, operator, admin, auditor)
├── Authenticator
│   ├── AuthenticateAPIKey() — API key auth
│   ├── AuthenticateJWT() — JWT token auth
│   ├── AuthenticateCertificate() — Certificate auth
│   ├── Session management
│   └── Rate limiting
├── AuditLogger
│   ├── LogAuthSuccess/Failure() — Authentication events
│   ├── LogAuthorizationDenied() — Access control events
│   ├── LogKeyEvent() — Key lifecycle events
│   ├── LogSecurityAlert() — Security incidents
│   ├── Query() — Audit log querying
│   └── Export/Rotation
├── SecurityPolicyManager
│   ├── Policy configuration
│   ├── IP whitelisting
│   └── Key rotation policies
└── Security Exceptions
    ├── SecurityException (base)
    ├── AuthenticationException
    ├── AuthorizationException
    └── RateLimitException
```

## Components

### 1. API Key Management

The `APIKeyManager` provides secure API key lifecycle management:

```cpp
// Generate a new API key
auto [raw_key, key_info] = security.GetKeyManager().GenerateKey(
    "Production Key",
    "user@example.com",
    PermissionManager::GetRolePermissions("operator"),
    SecurityLevel::STANDARD,
    std::chrono::hours(720) // 30 days
);

// The raw_key is returned once - store it securely!
std::cout << "New API Key: " << raw_key << std::endl;

// Validate a key
if (security.GetKeyManager().ValidateKey(user_provided_key)) {
    // Key is valid and not expired
}

// Revoke a key
security.GetKeyManager().RevokeKey(key_id);

// Rotate a key
auto [new_raw_key, new_key_info] = security.GetKeyManager().RotateKey(key_id);
```

**Key Features:**
- Secure key generation (48-character random strings)
- SHA-256 hashing (keys stored hashed, not plaintext)
- Expiration tracking
- Usage counting
- IP and origin restrictions
- Key rotation support

### 2. Permission System

The `PermissionManager` implements a granular permission system:

**Available Permissions:**
| Permission | Description |
|------------|-------------|
| `INFERENCE_READ` | Query inference results |
| `INFERENCE_WRITE` | Submit inference requests |
| `AGENT_CREATE` | Create new agents |
| `AGENT_EXECUTE` | Execute agent tasks |
| `AGENT_DELETE` | Remove agents |
| `SWARM_CREATE` | Create agent swarms |
| `SWARM_COORDINATE` | Coordinate swarm operations |
| `SYSTEM_CONFIG_READ` | Read system configuration |
| `SYSTEM_CONFIG_WRITE` | Modify system configuration |
| `SYSTEM_MONITOR` | Access monitoring data |
| `SYSTEM_ADMIN` | Full administrative access |
| `AUDIT_READ` | Read audit logs |
| `AUDIT_EXPORT` | Export audit data |

**Role-Based Access:**
```cpp
// Predefined roles
auto viewer_perms = PermissionManager::GetRolePermissions("viewer");
auto operator_perms = PermissionManager::GetRolePermissions("operator");
auto admin_perms = PermissionManager::GetRolePermissions("admin");
auto auditor_perms = PermissionManager::GetRolePermissions("auditor");

// Check permissions
if (ctx.HasPermission(Permission::INFERENCE_WRITE)) {
    // Allowed to submit inference
}

// Grant permissions
uint32_t perms = PermissionManager::GrantPermission(
    current_perms, Permission::AGENT_CREATE);
```

### 3. Authentication

The `Authenticator` supports multiple authentication methods:

```cpp
// API Key authentication
auto ctx = security.Authenticate(api_key, AuthMethod::API_KEY);

// JWT authentication
auto ctx = security.Authenticate(jwt_token, AuthMethod::JWT_TOKEN);

// Certificate authentication
auto ctx = security.Authenticate(cert_pem, AuthMethod::CERTIFICATE);

// Session management
std::string session_id = security.GetAuthenticator().CreateSession(ctx);
auto validated_ctx = security.GetAuthenticator().ValidateSession(session_id);
security.GetAuthenticator().TerminateSession(session_id);

// Rate limiting
if (security.GetAuthenticator().CheckRateLimit(principal, 100)) {
    // Within rate limit (100 requests/minute)
}
```

### 4. Audit Logging

The `AuditLogger` provides comprehensive security event logging:

```cpp
// Automatic logging
security.GetAuditLogger().LogAuthSuccess("user@example.com", "api_key");
security.GetAuditLogger().LogAuthFailure("user@example.com", "invalid_key");
security.GetAuditLogger().LogAuthorizationDenied("user@example.com", 
    "agent:create", "production");

// Security alerts
security.GetAuditLogger().LogSecurityAlert(
    "Multiple failed login attempts from IP 192.168.1.100", 5);

// Query audit log
auto events = security.GetAuditLogger().Query(
    AuditEventType::AUTHENTICATION_FAILURE,
    std::nullopt, // any principal
    start_time,
    end_time,
    100 // limit
);

// Export to file
security.GetAuditLogger().ExportToFile("audit_export.log", start_time, end_time);

// Get statistics
auto stats = security.GetAuditLogger().GetStatistics();
std::cout << "Total events: " << stats.total_events << std::endl;
std::cout << "Auth failures: " << stats.auth_failures << std::endl;
```

**Audit Event Types:**
- `AUTHENTICATION_SUCCESS` / `AUTHENTICATION_FAILURE`
- `AUTHORIZATION_DENIED`
- `KEY_CREATED` / `KEY_REVOKED` / `KEY_ROTATED`
- `PERMISSION_CHANGED`
- `SESSION_CREATED` / `SESSION_TERMINATED`
- `CONFIG_CHANGED`
- `SYSTEM_STARTUP` / `SYSTEM_SHUTDOWN`
- `SECURITY_ALERT`

### 5. Security Policy

The `SecurityPolicyManager` enforces security policies:

```cpp
// Configure policy
SecurityPolicy policy;
policy.minimum_level = SecurityLevel::STANDARD;
policy.require_https = true;
policy.require_mfa_for_admin = true;
policy.max_failed_attempts = 5;
policy.lockout_duration = std::chrono::minutes(30);
policy.session_timeout = std::chrono::hours(8);
policy.key_rotation_interval = std::chrono::hours(720); // 30 days
policy.audit_all_requests = true;
policy.ip_whitelist_enabled = true;
policy.allowed_ips = {"10.0.0.0/8", "192.168.1.0/24"};

security.GetPolicyManager().SetPolicy(policy);

// Check policy compliance
if (security.GetPolicyManager().CheckSecurityLevel(SecurityLevel::STANDARD)) {
    // Request meets minimum security level
}

if (security.GetPolicyManager().CheckIPAllowed(client_ip)) {
    // IP is whitelisted
}

if (security.GetPolicyManager().ShouldRotateKey(api_key)) {
    // Key needs rotation
}
```

### 6. Main Security Layer

The `SovereignSecurityLayer` singleton provides unified access:

```cpp
// Initialize
SovereignSecurityLayer& security = SovereignSecurityLayer::GetInstance();
security.Initialize("security.conf");

// Authenticate
auto ctx = security.Authenticate(api_key, AuthMethod::API_KEY);
if (!ctx) {
    throw AuthenticationException("Invalid credentials");
}

// Authorize
if (!security.Authorize(*ctx, Permission::AGENT_CREATE)) {
    throw AuthorizationException("Insufficient permissions");
}

// Validate request
if (!security.ValidateRequest(credential, ip_address, user_agent)) {
    throw SecurityException("Request validation failed");
}

// Check session
if (security.IsAuthenticated(session_id)) {
    auto ctx = security.GetSessionContext(session_id);
}

// Get status
auto status = security.GetStatus();
std::cout << "Active keys: " << status.active_keys << std::endl;
std::cout << "Audit events: " << status.total_audit_events << std::endl;

// Shutdown
security.Shutdown();
```

## Security Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `NONE` | No authentication | Development only |
| `BASIC` | API key only | Internal services |
| `STANDARD` | API key + permissions | Production APIs |
| `HIGH` | Multi-factor auth | Sensitive operations |
| `MAXIMUM` | Hardware-backed | Financial/government |

## Files Created

1. `SovereignSecurityLayer.hpp` (~700 lines) — Complete header
2. `SovereignSecurityLayer.cpp` (~1100 lines) — Full implementation
3. `PHASE_D4_BATCH3_SECURITY_LAYER.md` — This documentation

## Integration

The security layer integrates with:
- **SovereignUnifiedRuntime** (Batch 1/5) — Runtime security context
- **SovereignAPIGateway** (D.2) — API authentication/authorization
- **Benchmark Framework** (Batch 2/5) — Secure benchmark execution

## Production Checklist

✅ API key generation with secure hashing
✅ Permission system with role-based access
✅ Multiple authentication methods (API key, JWT, certificate)
✅ Session management with expiration
✅ Rate limiting
✅ Comprehensive audit logging
✅ Security policy enforcement
✅ IP whitelisting
✅ Key rotation support
✅ Security exceptions

## Next Steps

After completing Batch 3/5:
1. **Batch 4/5**: Observability & Operations (metrics, Prometheus, health checks)
2. **Batch 5/5**: Full System Qualification (`rawrxd qualify --full`)

## Usage Example

```cpp
#include "SovereignSecurityLayer.hpp"
using namespace Sovereign;

int main() {
    // Initialize security layer
    auto& security = SovereignSecurityLayer::GetInstance();
    security.Initialize("security.conf");
    
    // Create an API key for a new user
    auto [raw_key, key_info] = security.GetKeyManager().GenerateKey(
        "Production API Key",
        "ops@company.com",
        PermissionManager::GetRolePermissions("operator"),
        SecurityLevel::STANDARD,
        std::chrono::hours(720)
    );
    
    std::cout << "API Key: " << raw_key << std::endl;
    
    // Authenticate a request
    auto ctx = security.Authenticate(raw_key, AuthMethod::API_KEY);
    if (!ctx) {
        std::cerr << "Authentication failed" << std::endl;
        return 1;
    }
    
    // Check permissions
    if (!security.Authorize(*ctx, Permission::AGENT_CREATE)) {
        security.GetAuditLogger().LogAuthorizationDenied(
            ctx->principal, "agent:create", "");
        std::cerr << "Access denied" << std::endl;
        return 1;
    }
    
    // Execute operation
    std::cout << "Creating agent..." << std::endl;
    
    // Query audit log
    auto stats = security.GetAuditLogger().GetStatistics();
    std::cout << "Total audit events: " << stats.total_events << std::endl;
    
    // Cleanup
    security.Shutdown();
    
    return 0;
}
```

---

**Status**: ✅ Complete
**Date**: 2026-07-08
**Phase**: D.4 Batch 3/5
