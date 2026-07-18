// RawrXD Secret Manager Implementation
// Phase Q.4: Secure credential and secret management

#include "SecretManager.hpp"
#include "EncryptionManager.hpp"
#include "AuditLogger.hpp"

#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>

namespace RawrXD {
namespace Security {

// ============================================================================
// SecretManager Implementation
// ============================================================================

SecretManager::SecretManager(EncryptionManager* encryption, AuditLogger* audit)
    : encryption_(encryption)
    , audit_(audit)
    , running_(false)
    , initialized_(false)
    , sealed_(true) {
}

SecretManager::~SecretManager() {
    if (running_) {
        shutdown();
    }
}

bool SecretManager::initialize(const SecretManagerConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Start background threads
    running_ = true;
    rotationThread_ = std::thread(&SecretManager::rotationLoop, this);
    leaseThread_ = std::thread(&SecretManager::leaseCleanupLoop, this);
    
    initialized_ = true;
    
    // Seal on startup if configured
    if (config_.sealOnStartup) {
        seal();
    }
    
    return true;
}

bool SecretManager::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    if (rotationThread_.joinable()) {
        rotationThread_.join();
    }
    if (leaseThread_.joinable()) {
        leaseThread_.join();
    }
    
    // Clear sensitive data
    std::lock_guard<std::mutex> lock(mutex_);
    secrets_.clear();
    leases_.clear();
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Seal/Unseal
// ============================================================================

std::vector<std::string> SecretManager::generateUnsealKeys() {
    std::vector<std::string> keys;
    
    for (uint32_t i = 0; i < config_.unsealShares; ++i) {
        keys.push_back(SecretGenerator::generatePassword(32, true, true, true, true));
    }
    
    return keys;
}

bool SecretManager::unseal(const std::vector<std::string>& keys) {
    if (keys.size() < config_.unsealThreshold) {
        return false;
    }
    
    // In production, would reconstruct master key from Shamir shares
    sealed_ = false;
    return true;
}

bool SecretManager::seal() {
    sealed_ = true;
    return true;
}

// ============================================================================
// Secret CRUD
// ============================================================================

bool SecretManager::createSecret(const std::string& path, const Secret& secret) {
    if (sealed_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (secrets_.count(path)) {
        return false; // Already exists
    }
    
    Secret newSecret = secret;
    newSecret.metadata.path = path;
    newSecret.metadata.createdAt = std::chrono::system_clock::now();
    newSecret.metadata.updatedAt = newSecret.metadata.createdAt;
    newSecret.metadata.version = 1;
    newSecret.metadata.isActive = true;
    
    // Encrypt and persist
    persistSecret(path, newSecret);
    secrets_[path] = newSecret;
    
    // Audit log
    if (audit_) {
        // Would log secret creation
    }
    
    return true;
}

bool SecretManager::updateSecret(const std::string& path, const Secret& secret) {
    if (sealed_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = secrets_.find(path);
    if (it == secrets_.end()) {
        return false;
    }
    
    Secret updated = secret;
    updated.metadata.path = path;
    updated.metadata.updatedAt = std::chrono::system_clock::now();
    updated.metadata.version = it->second.metadata.version + 1;
    
    persistSecret(path, updated);
    it->second = updated;
    
    return true;
}

Secret SecretManager::readSecret(const std::string& path) {
    if (sealed_) {
        return Secret{};
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check cache first
    auto cacheIt = cache_.find(path);
    if (cacheIt != cache_.end()) {
        if (cacheIt->second.expiry > std::chrono::steady_clock::now()) {
            return cacheIt->second.secret;
        }
    }
    
    // Load from storage
    auto it = secrets_.find(path);
    if (it != secrets_.end()) {
        // Add to cache
        CacheEntry entry;
        entry.secret = it->second;
        entry.expiry = std::chrono::steady_clock::now() + 
                      std::chrono::seconds(config_.cacheTTLSeconds);
        cache_[path] = entry;
        
        return it->second;
    }
    
    return Secret{};
}

Secret SecretManager::readSecretVersion(const std::string& path, uint32_t version) {
    // In production, would load specific version from versioned storage
    return readSecret(path);
}

bool SecretManager::deleteSecret(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    secrets_.erase(path);
    cache_.erase(path);
    
    return true;
}

bool SecretManager::destroySecretVersion(const std::string& path, uint32_t version) {
    // In production, would securely destroy specific version
    return true;
}

bool SecretManager::undeleteSecretVersion(const std::string& path, uint32_t version) {
    // In production, would restore soft-deleted version
    return true;
}

// ============================================================================
// Secret Metadata
// ============================================================================

SecretMetadata SecretManager::getSecretMetadata(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = secrets_.find(path);
    if (it != secrets_.end()) {
        return it->second.metadata;
    }
    
    return SecretMetadata{};
}

std::vector<SecretVersion> SecretManager::listSecretVersions(const std::string& path) {
    // In production, would list all versions from storage
    std::vector<SecretVersion> versions;
    
    auto it = secrets_.find(path);
    if (it != secrets_.end()) {
        SecretVersion v;
        v.version = it->second.metadata.version;
        v.createdAt = it->second.metadata.createdAt;
        v.isDestroyed = false;
        v.data = it->second.data;
        versions.push_back(v);
    }
    
    return versions;
}

std::vector<std::string> SecretManager::listSecrets(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [secretPath, secret] : secrets_) {
        if (secretPath.find(path) == 0) {
            result.push_back(secretPath);
        }
    }
    
    return result;
}

// ============================================================================
// Patch Operations
// ============================================================================

bool SecretManager::patchSecret(const std::string& path, 
                                 const std::map<std::string, std::string>& updates) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = secrets_.find(path);
    if (it == secrets_.end()) {
        return false;
    }
    
    // Merge updates
    for (const auto& [key, value] : updates) {
        it->second.data[key] = value;
    }
    
    it->second.metadata.updatedAt = std::chrono::system_clock::now();
    it->second.metadata.version++;
    
    persistSecret(path, it->second);
    
    return true;
}

// ============================================================================
// Rotation
// ============================================================================

bool SecretManager::setRotationPolicy(const std::string& path, const RotationPolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    rotationPolicies_[path] = policy;
    return true;
}

RotationPolicy SecretManager::getRotationPolicy(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = rotationPolicies_.find(path);
    if (it != rotationPolicies_.end()) {
        return it->second;
    }
    
    return RotationPolicy{};
}

bool SecretManager::rotateSecret(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = secrets_.find(path);
    if (it == secrets_.end()) {
        return false;
    }
    
    auto policyIt = rotationPolicies_.find(path);
    if (policyIt == rotationPolicies_.end() || !policyIt->second.enabled) {
        return false;
    }
    
    // Generate new secret data
    std::map<std::string, std::string> newData;
    
    if (policyIt->second.rotationFunction) {
        newData = policyIt->second.rotationFunction(it->second.data);
    } else {
        // Default rotation: generate new password
        for (const auto& [key, value] : it->second.data) {
            if (key.find("password") != std::string::npos || 
                key.find("key") != std::string::npos) {
                newData[key] = SecretGenerator::generatePassword();
            } else {
                newData[key] = value;
            }
        }
    }
    
    it->second.data = newData;
    it->second.metadata.updatedAt = std::chrono::system_clock::now();
    it->second.metadata.lastRotatedAt = it->second.metadata.updatedAt;
    it->second.metadata.rotationCount++;
    it->second.metadata.version++;
    
    persistSecret(path, it->second);
    totalRotations_++;
    
    return true;
}

bool SecretManager::rotateSecretNow(const std::string& path) {
    return rotateSecret(path);
}

std::vector<std::string> SecretManager::getSecretsNeedingRotation(uint32_t days) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() - std::chrono::days(days);
    std::vector<std::string> result;
    
    for (const auto& [path, policy] : rotationPolicies_) {
        if (!policy.enabled) continue;
        
        auto secretIt = secrets_.find(path);
        if (secretIt != secrets_.end()) {
            auto nextRotation = secretIt->second.metadata.lastRotatedAt + 
                               std::chrono::days(policy.rotationIntervalDays);
            if (nextRotation <= std::chrono::system_clock::now() + std::chrono::days(days)) {
                result.push_back(path);
            }
        }
    }
    
    return result;
}

// ============================================================================
// Leases
// ============================================================================

Lease SecretManager::createLease(const std::string& secretPath, 
                                  const std::string& entityId,
                                  uint32_t ttlSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Lease lease;
    lease.id = generateLeaseId();
    lease.secretPath = secretPath;
    lease.entityId = entityId;
    lease.issuedAt = std::chrono::system_clock::now();
    lease.expiresAt = lease.issuedAt + std::chrono::seconds(ttlSeconds);
    lease.isRenewable = true;
    lease.ttlSeconds = ttlSeconds;
    lease.maxTtlSeconds = ttlSeconds * 2; // Default max TTL
    
    leases_[lease.id] = lease;
    
    return lease;
}

Lease SecretManager::renewLease(const std::string& leaseId, uint32_t incrementSeconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = leases_.find(leaseId);
    if (it == leases_.end()) {
        return Lease{};
    }
    
    if (!it->second.isRenewable) {
        return Lease{};
    }
    
    auto newExpiry = it->second.expiresAt + std::chrono::seconds(incrementSeconds);
    auto maxExpiry = it->second.issuedAt + std::chrono::seconds(it->second.maxTtlSeconds);
    
    if (newExpiry > maxExpiry) {
        newExpiry = maxExpiry;
    }
    
    it->second.expiresAt = newExpiry;
    it->second.ttlSeconds = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(newExpiry - 
        std::chrono::system_clock::now()).count());
    
    return it->second;
}

bool SecretManager::revokeLease(const std::string& leaseId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return leases_.erase(leaseId) > 0;
}

bool SecretManager::revokePrefix(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> toRemove;
    for (const auto& [id, lease] : leases_) {
        if (lease.secretPath.find(prefix) == 0) {
            toRemove.push_back(id);
        }
    }
    
    for (const auto& id : toRemove) {
        leases_.erase(id);
    }
    
    return true;
}

Lease SecretManager::getLease(const std::string& leaseId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = leases_.find(leaseId);
    if (it != leases_.end()) {
        return it->second;
    }
    
    return Lease{};
}

std::vector<Lease> SecretManager::listLeases(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Lease> result;
    auto now = std::chrono::system_clock::now();
    
    for (const auto& [id, lease] : leases_) {
        if (lease.secretPath.find(prefix) == 0 && lease.expiresAt > now) {
            result.push_back(lease);
        }
    }
    
    return result;
}

// ============================================================================
// Secret Engines
// ============================================================================

bool SecretManager::mountEngine(const std::string& path, const SecretEngineConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SecretEngineConfig cfg = config;
    cfg.path = path;
    cfg.isActive = true;
    
    engines_[path] = cfg;
    return true;
}

bool SecretManager::unmountEngine(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return engines_.erase(path) > 0;
}

std::vector<SecretEngineConfig> SecretManager::listEngines() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<SecretEngineConfig> result;
    for (const auto& [path, engine] : engines_) {
        result.push_back(engine);
    }
    
    return result;
}

// ============================================================================
// Database Secrets
// ============================================================================

Secret SecretManager::generateDatabaseCredentials(const std::string& role,
                                                   const std::string& database) {
    Secret secret;
    secret.metadata.path = "database/creds/" + role;
    secret.metadata.type = SecretType::DATABASE;
    secret.metadata.createdAt = std::chrono::system_clock::now();
    
    auto creds = SecretGenerator::generateDBCredentials(database, role);
    secret.data["username"] = creds.username;
    secret.data["password"] = creds.password;
    secret.data["connection_string"] = creds.connectionString;
    
    return secret;
}

bool SecretManager::revokeDatabaseCredentials(const std::string& leaseId) {
    // In production, would actually revoke credentials in database
    return revokeLease(leaseId);
}

// ============================================================================
// Transit Encryption
// ============================================================================

std::vector<uint8_t> SecretManager::encryptTransit(const std::string& keyName,
                                                    const std::vector<uint8_t>& plaintext,
                                                    const std::string& context) {
    if (!encryption_) {
        return {};
    }
    
    encryptionOps_++;
    
    // In production, would use transit key for encryption
    // For now, use regular encryption
    auto encrypted = encryption_->encrypt(plaintext, "transit-" + keyName);
    return encrypted.ciphertext;
}

std::vector<uint8_t> SecretManager::decryptTransit(const std::string& keyName,
                                                    const std::vector<uint8_t>& ciphertext,
                                                    const std::string& context) {
    if (!encryption_) {
        return {};
    }
    
    decryptionOps_++;
    
    // In production, would use transit key for decryption
    EncryptedData encrypted;
    encrypted.ciphertext = ciphertext;
    encrypted.keyId = "transit-" + keyName;
    
    return encryption_->decrypt(encrypted);
}

std::string SecretManager::signTransit(const std::string& keyName,
                                      const std::vector<uint8_t>& data) {
    if (!encryption_) {
        return "";
    }
    
    // In production, would use transit key for signing
    auto hmac = encryption_->hmacSHA256(data, std::vector<uint8_t>(32, 0));
    
    std::stringstream ss;
    for (auto b : hmac) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    
    return ss.str();
}

bool SecretManager::verifyTransit(const std::string& keyName,
                                 const std::vector<uint8_t>& data,
                                 const std::string& signature) {
    auto computed = signTransit(keyName, data);
    return computed == signature;
}

bool SecretManager::rotateTransitKey(const std::string& keyName) {
    // In production, would rotate transit key
    totalRotations_++;
    return true;
}

// ============================================================================
// Statistics
// ============================================================================

SecretManager::SecretStats SecretManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SecretStats stats{};
    stats.totalSecrets = secrets_.size();
    stats.totalRotations = totalRotations_.load();
    stats.encryptionOperations = encryptionOps_.load();
    stats.decryptionOperations = decryptionOps_.load();
    
    for (const auto& [path, secret] : secrets_) {
        if (secret.metadata.isActive) {
            stats.activeSecrets++;
        }
    }
    
    auto now = std::chrono::system_clock::now();
    for (const auto& [id, lease] : leases_) {
        if (lease.expiresAt > now) {
            stats.activeLeases++;
        }
    }
    
    return stats;
}

// ============================================================================
// Health
// ============================================================================

bool SecretManager::isHealthy() const {
    return initialized_ && !sealed_;
}

std::map<std::string, std::string> SecretManager::getHealthStatus() const {
    std::map<std::string, std::string> status;
    status["initialized"] = initialized_ ? "true" : "false";
    status["sealed"] = sealed_ ? "true" : "false";
    status["healthy"] = isHealthy() ? "true" : "false";
    status["total_secrets"] = std::to_string(secrets_.size());
    status["active_leases"] = std::to_string(leases_.size());
    return status;
}

// ============================================================================
// Internal Methods
// ============================================================================

void SecretManager::rotationLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::hours(24)); // Check daily
        
        if (!running_) break;
        if (sealed_) continue;
        
        auto toRotate = getSecretsNeedingRotation(1); // Due within 1 day
        for (const auto& path : toRotate) {
            rotateSecret(path);
        }
    }
}

void SecretManager::leaseCleanupLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        
        if (!running_) break;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::system_clock::now();
        std::vector<std::string> expired;
        
        for (const auto& [id, lease] : leases_) {
            if (lease.expiresAt <= now) {
                expired.push_back(id);
            }
        }
        
        for (const auto& id : expired) {
            leases_.erase(id);
        }
    }
}

std::string SecretManager::generateSecretId() {
    return "secret-" + SecretGenerator::generateApiKey("", 16);
}

std::string SecretManager::generateLeaseId() {
    return "lease-" + SecretGenerator::generateApiKey("", 16);
}

bool SecretManager::checkAccess(const std::string& path, const std::string& entityId) {
    // In production, would check if entity has access to path
    return true;
}

void SecretManager::persistSecret(const std::string& path, const Secret& secret) {
    // In production, would encrypt and write to storage
}

Secret SecretManager::loadSecret(const std::string& path) {
    // In production, would read from storage and decrypt
    return Secret{};
}

// ============================================================================
// SecretGenerator Implementation
// ============================================================================

std::string SecretGenerator::generatePassword(uint32_t length,
                                               bool includeUpper,
                                               bool includeLower,
                                               bool includeDigits,
                                               bool includeSpecial) {
    std::string chars;
    if (includeLower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (includeUpper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (includeDigits) chars += "0123456789";
    if (includeSpecial) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    if (chars.empty()) chars = "abcdefghijklmnopqrstuvwxyz";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    
    std::string password;
    for (uint32_t i = 0; i < length; ++i) {
        password += chars[dis(gen)];
    }
    
    return password;
}

std::string SecretGenerator::generateApiKey(const std::string& prefix, uint32_t length) {
    std::string key;
    if (!prefix.empty()) {
        key = prefix + "_";
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    for (uint32_t i = 0; i < length; ++i) {
        key += "0123456789abcdef"[dis(gen)];
    }
    
    return key;
}

SecretGenerator::DBCredentials SecretGenerator::generateDBCredentials(
    const std::string& database, const std::string& role) {
    
    DBCredentials creds;
    creds.username = "v-" + role + "-" + generateApiKey("", 8);
    creds.password = generatePassword(32);
    creds.connectionString = "postgresql://" + creds.username + ":" + creds.password + 
                             "@localhost/" + database;
    
    return creds;
}

} // namespace Security
} // namespace RawrXD
