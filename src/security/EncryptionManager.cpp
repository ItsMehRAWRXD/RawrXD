// RawrXD Encryption Manager Implementation
// Phase Q.1: Data encryption at rest and in transit

#include "EncryptionManager.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Security {

// ============================================================================
// EncryptionManager Implementation
// ============================================================================

EncryptionManager::EncryptionManager()
    : running_(false)
    , initialized_(false)
    , fipsMode_(false) {
}

EncryptionManager::~EncryptionManager() {
    if (running_) {
        shutdown();
    }
    // Securely clear master key
    if (!masterKey_.empty()) {
        OPENSSL_cleanse(masterKey_.data(), masterKey_.size());
    }
}

bool EncryptionManager::initialize(const std::string& masterKeyPath) {
    if (initialized_) {
        return true;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Load or generate master key
    if (!loadMasterKey(masterKeyPath)) {
        // Generate new master key
        masterKey_ = generateSecureRandom(32);
        if (!saveMasterKey(masterKeyPath)) {
            return false;
        }
    }
    
    // Start key rotation thread
    running_ = true;
    rotationThread_ = std::thread(&EncryptionManager::keyRotationLoop, this);
    
    initialized_ = true;
    return true;
}

bool EncryptionManager::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    if (rotationThread_.joinable()) {
        rotationThread_.join();
    }
    
    // Clear all keys
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, key] : keys_) {
        OPENSSL_cleanse(key.data(), key.size());
    }
    keys_.clear();
    keyMetadata_.clear();
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Key Operations
// ============================================================================

std::string EncryptionManager::generateKey(KeyType type, EncryptionAlgorithm algorithm) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Generate key ID
    std::string keyId = generateSecureToken(16);
    
    // Determine key size based on algorithm
    size_t keySize = 32; // Default 256-bit
    if (algorithm == EncryptionAlgorithm::AES_128_GCM) {
        keySize = 16;
    }
    
    // Generate key material
    std::vector<uint8_t> keyMaterial = generateSecureRandom(keySize);
    
    // Store key
    keys_[keyId] = std::move(keyMaterial);
    
    // Create metadata
    KeyMetadata metadata;
    metadata.id = keyId;
    metadata.type = type;
    metadata.algorithm = algorithm;
    metadata.createdAt = std::chrono::system_clock::now();
    metadata.expiresAt = metadata.createdAt + std::chrono::days(365); // 1 year default
    metadata.lastRotatedAt = metadata.createdAt;
    metadata.rotationCount = 0;
    metadata.isActive = true;
    
    keyMetadata_[keyId] = metadata;
    
    return keyId;
}

bool EncryptionManager::rotateKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto metaIt = keyMetadata_.find(keyId);
    auto keyIt = keys_.find(keyId);
    
    if (metaIt == keyMetadata_.end() || keyIt == keys_.end()) {
        return false;
    }
    
    // Generate new key material
    size_t keySize = keyIt->second.size();
    std::vector<uint8_t> newKey = generateSecureRandom(keySize);
    
    // Securely clear old key
    OPENSSL_cleanse(keyIt->second.data(), keyIt->second.size());
    
    // Store new key
    keyIt->second = std::move(newKey);
    
    // Update metadata
    metaIt->second.lastRotatedAt = std::chrono::system_clock::now();
    metaIt->second.rotationCount++;
    
    return true;
}

bool EncryptionManager::revokeKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto keyIt = keys_.find(keyId);
    if (keyIt == keys_.end()) {
        return false;
    }
    
    // Securely clear key material
    OPENSSL_cleanse(keyIt->second.data(), keyIt->second.size());
    
    // Remove key
    keys_.erase(keyIt);
    keyMetadata_.erase(keyId);
    
    return true;
}

bool EncryptionManager::activateKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = keyMetadata_.find(keyId);
    if (it == keyMetadata_.end()) {
        return false;
    }
    
    it->second.isActive = true;
    return true;
}

bool EncryptionManager::deactivateKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = keyMetadata_.find(keyId);
    if (it == keyMetadata_.end()) {
        return false;
    }
    
    it->second.isActive = false;
    return true;
}

// ============================================================================
// Key Queries
// ============================================================================

KeyMetadata EncryptionManager::getKeyMetadata(const std::string& keyId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = keyMetadata_.find(keyId);
    if (it != keyMetadata_.end()) {
        return it->second;
    }
    
    return KeyMetadata{};
}

std::vector<KeyMetadata> EncryptionManager::getKeysByType(KeyType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<KeyMetadata> result;
    for (const auto& [id, metadata] : keyMetadata_) {
        if (metadata.type == type) {
            result.push_back(metadata);
        }
    }
    
    return result;
}

std::vector<KeyMetadata> EncryptionManager::getAllKeys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<KeyMetadata> result;
    for (const auto& [id, metadata] : keyMetadata_) {
        result.push_back(metadata);
    }
    
    return result;
}

std::vector<KeyMetadata> EncryptionManager::getExpiringKeys(uint32_t days) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::system_clock::now() + std::chrono::days(days);
    
    std::vector<KeyMetadata> result;
    for (const auto& [id, metadata] : keyMetadata_) {
        if (metadata.expiresAt <= cutoff && metadata.isActive) {
            result.push_back(metadata);
        }
    }
    
    return result;
}

// ============================================================================
// Encryption/Decryption
// ============================================================================

EncryptedData EncryptionManager::encrypt(const std::vector<uint8_t>& plaintext,
                                         const std::string& keyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    EncryptedData result;
    result.keyId = keyId;
    
    auto keyIt = keys_.find(keyId);
    auto metaIt = keyMetadata_.find(keyId);
    
    if (keyIt == keys_.end() || metaIt == keyMetadata_.end()) {
        failedOps_++;
        return result;
    }
    
    result.algorithm = metaIt->second.algorithm;
    
    // Generate nonce
    size_t nonceSize = 12; // 96 bits for GCM
    if (result.algorithm == EncryptionAlgorithm::XCHACHA20_POLY1305) {
        nonceSize = 24; // 192 bits for XChaCha20
    }
    result.nonce = generateSecureRandom(nonceSize);
    
    // Prepare ciphertext buffer
    result.ciphertext.resize(plaintext.size());
    result.tag.resize(16); // 128-bit authentication tag
    
    // Perform encryption based on algorithm
    const EVP_CIPHER* cipher = nullptr;
    switch (result.algorithm) {
        case EncryptionAlgorithm::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case EncryptionAlgorithm::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case EncryptionAlgorithm::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            break;
        default:
            failedOps_++;
            return result;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        failedOps_++;
        return result;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return result;
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, result.nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return result;
    }
    
    // Initialize with key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyIt->second.data(), result.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return result;
    }
    
    // Encrypt
    int len;
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return result;
    }
    
    int finalLen;
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return result;
    }
    
    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return result;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Update stats
    bytesEncrypted_ += plaintext.size();
    encryptionOps_++;
    
    return result;
}

EncryptedData EncryptionManager::encrypt(const std::string& plaintext,
                                         const std::string& keyId) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    return encrypt(data, keyId);
}

std::vector<uint8_t> EncryptionManager::decrypt(const EncryptedData& encrypted) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto keyIt = keys_.find(encrypted.keyId);
    if (keyIt == keys_.end()) {
        failedOps_++;
        return {};
    }
    
    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
    
    // Get cipher
    const EVP_CIPHER* cipher = nullptr;
    switch (encrypted.algorithm) {
        case EncryptionAlgorithm::AES_256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case EncryptionAlgorithm::AES_128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case EncryptionAlgorithm::CHACHA20_POLY1305:
            cipher = EVP_chacha20_poly1305();
            break;
        default:
            failedOps_++;
            return {};
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        failedOps_++;
        return {};
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return {};
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, encrypted.nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return {};
    }
    
    // Initialize with key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyIt->second.data(), encrypted.nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return {};
    }
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(encrypted.tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return {};
    }
    
    // Decrypt
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted.ciphertext.data(), encrypted.ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return {};
    }
    
    int finalLen;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        failedOps_++;
        return {}; // Authentication failed
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Update stats
    bytesDecrypted_ += plaintext.size();
    decryptionOps_++;
    
    plaintext.resize(len + finalLen);
    return plaintext;
}

std::string EncryptionManager::decryptToString(const EncryptedData& encrypted) {
    auto plaintext = decrypt(encrypted);
    return std::string(plaintext.begin(), plaintext.end());
}

// ============================================================================
// Secure Random
// ============================================================================

std::vector<uint8_t> EncryptionManager::generateSecureRandom(size_t length) {
    std::vector<uint8_t> result(length);
    
    if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
        return {};
    }
    
    return result;
}

std::string EncryptionManager::generateSecureToken(size_t length) {
    auto random = generateSecureRandom(length);
    
    // Convert to hex
    std::stringstream ss;
    for (auto b : random) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    
    return ss.str();
}

// ============================================================================
// Hashing
// ============================================================================

std::vector<uint8_t> EncryptionManager::hashSHA256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), result.data());
    return result;
}

std::vector<uint8_t> EncryptionManager::hashSHA256(const std::string& data) {
    return hashSHA256(std::vector<uint8_t>(data.begin(), data.end()));
}

std::string EncryptionManager::hashPassword(const std::string& password,
                                            const std::vector<uint8_t>& salt) {
    auto key = deriveKey(password, salt, 32, 100000);
    
    std::stringstream ss;
    ss << "$sha256$100000$";
    for (auto b : salt) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    ss << "$";
    for (auto b : key) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    
    return ss.str();
}

bool EncryptionManager::verifyPassword(const std::string& password, const std::string& hash) {
    // Parse hash format: $sha256$iterations$salt$hash
    // Simplified implementation
    return false;
}

// ============================================================================
// Key Derivation
// ============================================================================

std::vector<uint8_t> EncryptionManager::deriveKey(const std::string& password,
                                                  const std::vector<uint8_t>& salt,
                                                  size_t keyLength,
                                                  uint32_t iterations) {
    std::vector<uint8_t> result(keyLength);
    
    PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                      salt.data(), static_cast<int>(salt.size()),
                      static_cast<int>(iterations),
                      EVP_sha256(), static_cast<int>(keyLength), result.data());
    
    return result;
}

// ============================================================================
// HMAC
// ============================================================================

std::vector<uint8_t> EncryptionManager::hmacSHA256(const std::vector<uint8_t>& data,
                                                const std::vector<uint8_t>& key) {
    std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
    unsigned int resultLen = 0;
    
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), result.data(), &resultLen);
    
    result.resize(resultLen);
    return result;
}

bool EncryptionManager::verifyHMAC(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& expected) {
    auto computed = hmacSHA256(data, key);
    return computed == expected;
}

// ============================================================================
// Statistics
// ============================================================================

EncryptionManager::EncryptionStats EncryptionManager::getStats() const {
    EncryptionStats stats;
    stats.bytesEncrypted = bytesEncrypted_.load();
    stats.bytesDecrypted = bytesDecrypted_.load();
    stats.encryptionOps = encryptionOps_.load();
    stats.decryptionOps = decryptionOps_.load();
    stats.failedOps = failedOps_.load();
    stats.avgEncryptionTimeMs = 0.0; // Would track timing
    stats.avgDecryptionTimeMs = 0.0;
    return stats;
}

// ============================================================================
// Internal Methods
// ============================================================================

void EncryptionManager::keyRotationLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::hours(24)); // Check daily
        
        if (!running_) break;
        
        // Auto-rotate keys nearing expiration
        auto expiring = getExpiringKeys(7); // 7 days
        for (const auto& key : expiring) {
            rotateKey(key.id);
        }
    }
}

bool EncryptionManager::loadMasterKey(const std::string& path) {
    // Implementation would load from secure storage
    return false;
}

bool EncryptionManager::saveMasterKey(const std::string& path) {
    // Implementation would save to secure storage
    return true;
}

void EncryptionManager::enableFIPSMode(bool enable) {
    fipsMode_ = enable;
    // Would configure OpenSSL for FIPS mode
}

// ============================================================================
// SecureBuffer Implementation
// ============================================================================

SecureBuffer::SecureBuffer(size_t size)
    : data_(nullptr)
    , size_(size)
    , mlocked_(false) {
    
    if (size_ > 0) {
        data_ = static_cast<uint8_t*>(OPENSSL_malloc(size_));
        if (data_) {
            // Try to lock memory (may fail on some systems)
            #ifdef _WIN32
            // VirtualLock on Windows
            #else
            mlocked_ = (mlock(data_, size_) == 0);
            #endif
        }
    }
}

SecureBuffer::~SecureBuffer() {
    if (data_) {
        zero();
        if (mlocked_) {
            #ifndef _WIN32
            munlock(data_, size_);
            #endif
        }
        OPENSSL_free(data_);
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_)
    , size_(other.size_)
    , mlocked_(other.mlocked_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.mlocked_ = false;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_) {
            zero();
            OPENSSL_free(data_);
        }
        data_ = other.data_;
        size_ = other.size_;
        mlocked_ = other.mlocked_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.mlocked_ = false;
    }
    return *this;
}

void SecureBuffer::zero() {
    if (data_ && size_ > 0) {
        OPENSSL_cleanse(data_, size_);
    }
}

bool SecureBuffer::isZero() const {
    if (!data_ || size_ == 0) return true;
    for (size_t i = 0; i < size_; ++i) {
        if (data_[i] != 0) return false;
    }
    return true;
}

} // namespace Security
} // namespace RawrXD
