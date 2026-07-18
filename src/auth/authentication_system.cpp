// RawrXD Authentication System
// Phase 9 - Task 8: Authentication System

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <jwt-cpp/jwt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// Authentication methods
enum AuthMethod {
    AUTH_API_KEY,
    AUTH_JWT,
    AUTH_OAUTH2,
    AUTH_MUTUAL_TLS
};

// User roles
enum UserRole {
    ROLE_ADMIN,
    ROLE_USER,
    ROLE_GUEST,
    ROLE_SERVICE
};

// API Key structure
struct ApiKey {
    std::string key;
    std::string userId;
    std::string name;
    UserRole role;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point expires;
    bool active;
    uint64_t requestCount;
    uint64_t lastUsed;
};

// JWT claims
struct JwtClaims {
    std::string sub;           // Subject (user ID)
    std::string iss;           // Issuer
    std::string aud;           // Audience
    std::chrono::system_clock::time_point iat;  // Issued at
    std::chrono::system_clock::time_point exp;  // Expiration
    std::chrono::system_clock::time_point nbf;  // Not before
    std::string jti;           // JWT ID
    UserRole role;
    std::vector<std::string> permissions;
};

// OAuth2 token
struct OAuth2Token {
    std::string accessToken;
    std::string refreshToken;
    std::string tokenType;
    int expiresIn;
    std::string scope;
    std::chrono::system_clock::time_point created;
};

// Authentication manager
class AuthenticationManager {
private:
    std::map<std::string, ApiKey> apiKeys;
    std::map<std::string, std::string> userPasswords;  // Hashed
    std::string jwtSecret;
    std::string issuer;
    int jwtExpiryHours;
    std::mutex authMutex;
    
public:
    AuthenticationManager() : jwtExpiryHours(24), issuer("rawrxd") {}
    
    bool Initialize(const std::string& secret) {
        jwtSecret = secret;
        
        // Generate default admin key if none exist
        if (apiKeys.empty()) {
            GenerateApiKey("admin", "Default Admin Key", ROLE_ADMIN);
        }
        
        printf("Authentication system initialized\n");
        printf("  JWT issuer: %s\n", issuer.c_str());
        printf("  JWT expiry: %d hours\n", jwtExpiryHours);
        
        return true;
    }
    
    // Generate new API key
    std::string GenerateApiKey(const std::string& userId, const std::string& name, UserRole role) {
        std::lock_guard<std::mutex> lock(authMutex);
        
        // Generate random key
        std::string key = "rxd_" + GenerateRandomString(32);
        
        ApiKey apiKey;
        apiKey.key = key;
        apiKey.userId = userId;
        apiKey.name = name;
        apiKey.role = role;
        apiKey.created = std::chrono::system_clock::now();
        apiKey.expires = apiKey.created + std::chrono::hours(24 * 365);  // 1 year
        apiKey.active = true;
        apiKey.requestCount = 0;
        apiKey.lastUsed = 0;
        
        apiKeys[key] = apiKey;
        
        printf("Generated API key for user '%s' with role %d\n", userId.c_str(), role);
        return key;
    }
    
    // Validate API key
    bool ValidateApiKey(const std::string& key, ApiKey& outKey) {
        std::lock_guard<std::mutex> lock(authMutex);
        
        auto it = apiKeys.find(key);
        if (it == apiKeys.end()) {
            return false;
        }
        
        if (!it->second.active) {
            return false;
        }
        
        auto now = std::chrono::system_clock::now();
        if (now > it->second.expires) {
            return false;
        }
        
        // Update usage stats
        it->second.requestCount++;
        it->second.lastUsed = GetTickCount64();
        
        outKey = it->second;
        return true;
    }
    
    // Revoke API key
    bool RevokeApiKey(const std::string& key) {
        std::lock_guard<std::mutex> lock(authMutex);
        
        auto it = apiKeys.find(key);
        if (it == apiKeys.end()) {
            return false;
        }
        
        it->second.active = false;
        printf("Revoked API key: %s...\n", key.substr(0, 8).c_str());
        return true;
    }
    
    // Create JWT token
    std::string CreateJwtToken(const std::string& userId, UserRole role) {
        auto now = std::chrono::system_clock::now();
        auto exp = now + std::chrono::hours(jwtExpiryHours);
        
        std::string token = jwt::create()
            .set_issuer(issuer)
            .set_type("JWT")
            .set_issued_at(now)
            .set_expires_at(exp)
            .set_subject(userId)
            .set_payload_claim("role", jwt::claim(std::to_string(role)))
            .sign(jwt::algorithm::hs256{jwtSecret});
        
        return token;
    }
    
    // Validate JWT token
    bool ValidateJwtToken(const std::string& token, JwtClaims& outClaims) {
        try {
            auto decoded = jwt::decode(token);
            
            // Verify signature
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{jwtSecret})
                .with_issuer(issuer);
            
            verifier.verify(decoded);
            
            // Extract claims
            outClaims.sub = decoded.get_subject();
            outClaims.iss = decoded.get_issuer();
            outClaims.iat = decoded.get_issued_at();
            outClaims.exp = decoded.get_expires_at();
            
            // Get role from claims
            auto roleClaim = decoded.get_payload_claim("role");
            outClaims.role = (UserRole)std::stoi(roleClaim.as_string());
            
            return true;
        } catch (const std::exception& e) {
            printf("JWT validation failed: %s\n", e.what());
            return false;
        }
    }
    
    // OAuth2 authorization
    OAuth2Token CreateOAuth2Token(const std::string& userId, const std::string& scope) {
        OAuth2Token token;
        token.accessToken = GenerateRandomString(32);
        token.refreshToken = GenerateRandomString(32);
        token.tokenType = "Bearer";
        token.expiresIn = 3600;  // 1 hour
        token.scope = scope;
        token.created = std::chrono::system_clock::now();
        
        return token;
    }
    
    // Validate OAuth2 token
    bool ValidateOAuth2Token(const std::string& accessToken) {
        // In production, would check against token store
        return !accessToken.empty();
    }
    
    // Hash password (simplified - use bcrypt in production)
    std::string HashPassword(const std::string& password) {
        // Simple hash - replace with proper bcrypt/argon2
        std::string hash = password;  // Placeholder
        return hash;
    }
    
    // Verify password
    bool VerifyPassword(const std::string& userId, const std::string& password) {
        std::lock_guard<std::mutex> lock(authMutex);
        
        auto it = userPasswords.find(userId);
        if (it == userPasswords.end()) {
            return false;
        }
        
        return it->second == HashPassword(password);
    }
    
    // Create user
    bool CreateUser(const std::string& userId, const std::string& password, UserRole role) {
        std::lock_guard<std::mutex> lock(authMutex);
        
        if (userPasswords.find(userId) != userPasswords.end()) {
            return false;  // User already exists
        }
        
        userPasswords[userId] = HashPassword(password);
        printf("Created user: %s with role %d\n", userId.c_str(), role);
        return true;
    }
    
    // Check permission
    bool CheckPermission(UserRole role, const std::string& permission) {
        switch (role) {
            case ROLE_ADMIN:
                return true;  // Admin has all permissions
            case ROLE_USER:
                return permission != "admin";
            case ROLE_GUEST:
                return permission == "read";
            case ROLE_SERVICE:
                return permission == "inference" || permission == "read";
            default:
                return false;
        }
    }
    
    // Get API key stats
    void GetApiKeyStats(const std::string& key, uint64_t& requestCount, uint64_t& lastUsed) {
        std::lock_guard<std::mutex> lock(authMutex);
        
        auto it = apiKeys.find(key);
        if (it != apiKeys.end()) {
            requestCount = it->second.requestCount;
            lastUsed = it->second.lastUsed;
        }
    }
    
    // List all API keys for user
    std::vector<std::string> ListUserApiKeys(const std::string& userId) {
        std::lock_guard<std::mutex> lock(authMutex);
        
        std::vector<std::string> keys;
        for (const auto& pair : apiKeys) {
            if (pair.second.userId == userId && pair.second.active) {
                keys.push_back(pair.first);
            }
        }
        return keys;
    }
    
private:
    std::string GenerateRandomString(size_t length) {
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string result;
        result.reserve(length);
        
        // Use Windows Crypto API for secure random
        HCRYPTPROV hProv;
        if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            for (size_t i = 0; i < length; i++) {
                BYTE randomByte;
                CryptGenRandom(hProv, 1, &randomByte);
                result += charset[randomByte % (sizeof(charset) - 1)];
            }
            CryptReleaseContext(hProv, 0);
        }
        
        return result;
    }
};

// Global instance
static AuthenticationManager g_AuthManager;

// C API
extern "C" {

bool Auth_Init(const char* jwtSecret) {
    return g_AuthManager.Initialize(jwtSecret);
}

const char* Auth_GenerateApiKey(const char* userId, const char* name, int role) {
    static std::string key;
    key = g_AuthManager.GenerateApiKey(userId, name, (UserRole)role);
    return key.c_str();
}

bool Auth_ValidateApiKey(const char* key, char* userId, int* role) {
    ApiKey apiKey;
    if (!g_AuthManager.ValidateApiKey(key, apiKey)) {
        return false;
    }
    
    strcpy_s(userId, 256, apiKey.userId.c_str());
    *role = apiKey.role;
    return true;
}

bool Auth_RevokeApiKey(const char* key) {
    return g_AuthManager.RevokeApiKey(key);
}

const char* Auth_CreateJwtToken(const char* userId, int role) {
    static std::string token;
    token = g_AuthManager.CreateJwtToken(userId, (UserRole)role);
    return token.c_str();
}

bool Auth_ValidateJwtToken(const char* token, char* userId, int* role) {
    JwtClaims claims;
    if (!g_AuthManager.ValidateJwtToken(token, claims)) {
        return false;
    }
    
    strcpy_s(userId, 256, claims.sub.c_str());
    *role = claims.role;
    return true;
}

bool Auth_CreateUser(const char* userId, const char* password, int role) {
    return g_AuthManager.CreateUser(userId, password, (UserRole)role);
}

bool Auth_VerifyPassword(const char* userId, const char* password) {
    return g_AuthManager.VerifyPassword(userId, password);
}

bool Auth_CheckPermission(int role, const char* permission) {
    return g_AuthManager.CheckPermission((UserRole)role, permission);
}

} // extern "C"
