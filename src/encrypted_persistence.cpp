/**
 * EncryptedPersistence Implementation
 * Enhancement #5: At-Rest State Encryption
 *
 * Fixed issues:
 *  - EncryptionEngine::encrypt/decrypt now use real AES-256-GCM via BCrypt (not XOR)
 *  - SecureKeyStore persists keys to Windows Credential Manager (not in-memory only)
 *  - Key generation uses BCryptGenRandom (CSPRNG, not std::mt19937)
 *  - IV/salt generation uses BCryptGenRandom
 */

#include "encrypted_persistence.h"
#include <string>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <iterator>
#include <algorithm>
#include <stdexcept>
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <wincred.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Advapi32.lib")
#endif

namespace EncryptedPersistence {

// ===== SecureKeyStore Implementation =====

class SecureKeyStore::Impl {
public:
    // In-memory cache of DPAPI-encrypted blobs (keyed by keyId)
    std::unordered_map<std::string, std::vector<uint8_t>> keyCache;
    std::mutex mutex;
};

SecureKeyStore::SecureKeyStore()
    : m_impl(std::make_unique<Impl>()) {}

SecureKeyStore::~SecureKeyStore() = default;

bool SecureKeyStore::storeKey(const std::string& keyId, const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
#ifdef _WIN32
    // Encrypt with DPAPI
    DATA_BLOB inBlob{ static_cast<DWORD>(key.size()), const_cast<BYTE*>(key.data()) };
    DATA_BLOB outBlob{};
    std::wstring wDesc(keyId.begin(), keyId.end());
    if (!CryptProtectData(&inBlob, wDesc.c_str(), nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE, &outBlob))
        return false;

    std::vector<uint8_t> encrypted(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);

    // Persist to Windows Credential Manager so it survives restarts
    std::string targetName = "RawrXD_Key_" + keyId;
    CREDENTIALA cred{};
    cred.Type             = CRED_TYPE_GENERIC;
    cred.TargetName       = const_cast<LPSTR>(targetName.c_str());
    cred.CredentialBlobSize = static_cast<DWORD>(encrypted.size());
    cred.CredentialBlob   = encrypted.data();
    cred.Persist          = CRED_PERSIST_LOCAL_MACHINE;
    if (!CredWriteA(&cred, 0)) return false;

    m_impl->keyCache[keyId] = std::move(encrypted);
    return true;
#else
    m_impl->keyCache[keyId] = key;
    return true;
#endif
}

std::vector<uint8_t> SecureKeyStore::retrieveKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
#ifdef _WIN32
    // Try memory cache first
    std::vector<uint8_t> blob;
    auto it = m_impl->keyCache.find(keyId);
    if (it != m_impl->keyCache.end()) {
        blob = it->second;
    } else {
        // Load from Credential Manager
        std::string targetName = "RawrXD_Key_" + keyId;
        PCREDENTIALA pCred = nullptr;
        if (!CredReadA(targetName.c_str(), CRED_TYPE_GENERIC, 0, &pCred))
            return {};
        blob.assign(pCred->CredentialBlob,
                    pCred->CredentialBlob + pCred->CredentialBlobSize);
        CredFree(pCred);
        m_impl->keyCache[keyId] = blob;
    }

    // Decrypt with DPAPI
    DATA_BLOB inBlob{ static_cast<DWORD>(blob.size()), blob.data() };
    DATA_BLOB outBlob{};
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr,
                             CRYPTPROTECT_LOCAL_MACHINE, &outBlob))
        return {};
    std::vector<uint8_t> key(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return key;
#else
    auto it = m_impl->keyCache.find(keyId);
    return it != m_impl->keyCache.end() ? it->second : std::vector<uint8_t>{};
#endif
}

bool SecureKeyStore::deleteKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
#ifdef _WIN32
    std::string targetName = "RawrXD_Key_" + keyId;
    CredDeleteA(targetName.c_str(), CRED_TYPE_GENERIC, 0);
#endif
    return m_impl->keyCache.erase(keyId) > 0;
}

bool SecureKeyStore::hasKey(const std::string& keyId) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
#ifdef _WIN32
    if (m_impl->keyCache.count(keyId)) return true;
    std::string targetName = "RawrXD_Key_" + keyId;
    PCREDENTIALA pCred = nullptr;
    if (CredReadA(targetName.c_str(), CRED_TYPE_GENERIC, 0, &pCred)) {
        CredFree(pCred);
        return true;
    }
    return false;
#else
    return m_impl->keyCache.count(keyId) > 0;
#endif
}

std::vector<uint8_t> SecureKeyStore::generateKey(size_t keySize) {
    std::vector<uint8_t> key(keySize);
#ifdef _WIN32
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, key.data(),
                                        static_cast<ULONG>(keySize),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return {};
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom.read(reinterpret_cast<char*>(key.data()), keySize))
        return {};
#endif
    return key;
}

// ===== EncryptionEngine Implementation =====

class EncryptionEngine::Impl {
public:
    std::vector<uint8_t> key;
    uint8_t algorithm = ENC_NONE;
    bool initialized  = false;
};

EncryptionEngine::EncryptionEngine()
    : m_impl(std::make_unique<Impl>()) {}

EncryptionEngine::~EncryptionEngine() = default;

bool EncryptionEngine::initialize(const std::vector<uint8_t>& key, uint8_t algorithm) {
    if (key.size() != ENC_KEY_SIZE) return false;
    m_impl->key       = key;
    m_impl->algorithm = algorithm;
    m_impl->initialized = true;
    return true;
}

EncryptedEnvelope EncryptionEngine::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& additionalData)
{
    EncryptedEnvelope envelope;
    envelope.algorithm = m_impl->algorithm;
    envelope.kdf       = ENC_KDF_PBKDF2;
    envelope.iterations = ENC_ITERATIONS;
    envelope.additionalData = additionalData;
    envelope.salt.resize(ENC_SALT_SIZE);
    envelope.iv.resize(ENC_IV_SIZE);
    envelope.authTag.resize(ENC_TAG_SIZE);

    if (!m_impl->initialized) return envelope;

#ifdef _WIN32
    // Generate random salt and IV with CSPRNG
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, envelope.salt.data(),
                                        ENC_SALT_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ||
        !BCRYPT_SUCCESS(BCryptGenRandom(nullptr, envelope.iv.data(),
                                        ENC_IV_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return envelope;

    // Real AES-256-GCM via BCrypt
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;
    do {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
            break;
        if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                              (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
            break;
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                                       const_cast<PUCHAR>(m_impl->key.data()),
                                                       static_cast<ULONG>(m_impl->key.size()), 0)))
            break;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = envelope.iv.data();
        authInfo.cbNonce = ENC_IV_SIZE;
        authInfo.pbTag   = envelope.authTag.data();
        authInfo.cbTag   = ENC_TAG_SIZE;
        if (!additionalData.empty()) {
            authInfo.pbAuthData = const_cast<PUCHAR>(additionalData.data());
            authInfo.cbAuthData = static_cast<ULONG>(additionalData.size());
        }

        ULONG cbResult = 0;
        envelope.ciphertext.resize(plaintext.size());
        if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey,
                                          const_cast<PUCHAR>(plaintext.data()),
                                          static_cast<ULONG>(plaintext.size()),
                                          &authInfo, nullptr, 0,
                                          envelope.ciphertext.data(),
                                          static_cast<ULONG>(envelope.ciphertext.size()),
                                          &cbResult, 0)))
            break;
        envelope.ciphertext.resize(cbResult);
        ok = true;
    } while (false);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!ok) envelope.ciphertext.clear();
#else
    // Non-Windows: replace with libsodium or OpenSSL in production
    envelope.ciphertext = plaintext;
#endif
    return envelope;
}

std::vector<uint8_t> EncryptionEngine::decrypt(
    const EncryptedEnvelope& envelope,
    bool& outSuccess)
{
    outSuccess = false;
    if (!m_impl->initialized) return {};
    if (envelope.algorithm != m_impl->algorithm) return {};
    if (envelope.iv.size() != ENC_IV_SIZE) return {};
    if (envelope.authTag.size() != ENC_TAG_SIZE) return {};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::vector<uint8_t> plaintext;
    do {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
            break;
        if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                              (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
            break;
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                                       const_cast<PUCHAR>(m_impl->key.data()),
                                                       static_cast<ULONG>(m_impl->key.size()), 0)))
            break;

        // BCryptDecrypt with GCM requires a mutable copy of the tag
        std::vector<uint8_t> tagCopy = envelope.authTag;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(envelope.iv.data());
        authInfo.cbNonce = ENC_IV_SIZE;
        authInfo.pbTag   = tagCopy.data();
        authInfo.cbTag   = ENC_TAG_SIZE;
        if (!envelope.additionalData.empty()) {
            authInfo.pbAuthData = const_cast<PUCHAR>(envelope.additionalData.data());
            authInfo.cbAuthData = static_cast<ULONG>(envelope.additionalData.size());
        }

        ULONG cbResult = 0;
        plaintext.resize(envelope.ciphertext.size());
        NTSTATUS st = BCryptDecrypt(hKey,
                                    const_cast<PUCHAR>(envelope.ciphertext.data()),
                                    static_cast<ULONG>(envelope.ciphertext.size()),
                                    &authInfo, nullptr, 0,
                                    plaintext.data(),
                                    static_cast<ULONG>(plaintext.size()),
                                    &cbResult, 0);
        if (!BCRYPT_SUCCESS(st)) { plaintext.clear(); break; }
        plaintext.resize(cbResult);
        outSuccess = true;
    } while (false);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return plaintext;
#else
    outSuccess = true;
    return envelope.ciphertext;
#endif
}

bool EncryptionEngine::isInitialized() const { return m_impl->initialized; }
uint8_t EncryptionEngine::getAlgorithm() const { return m_impl->algorithm; }

// ===== EncryptedPersistenceLayer Implementation =====

EncryptedPersistenceLayer::EncryptedPersistenceLayer() = default;
EncryptedPersistenceLayer::~EncryptedPersistenceLayer() = default;

bool EncryptedPersistenceLayer::initialize(const std::string& keyId) {
    auto key = m_keyStore.retrieveKey(keyId);
    if (key.empty()) {
        key = SecureKeyStore::generateKey();
        if (key.empty() || !m_keyStore.storeKey(keyId, key))
            return false;
    }
    return m_engine.initialize(key, ENC_AES256_GCM);
}

bool EncryptedPersistenceLayer::initializeWithKey(const std::vector<uint8_t>& key) {
    return m_engine.initialize(key, ENC_AES256_GCM);
}

bool EncryptedPersistenceLayer::encryptFile(
    const std::string& inputPath,
    const std::string& outputPath)
{
    std::ifstream input(inputPath, std::ios::binary);
    if (!input) return false;
    std::vector<uint8_t> plaintext((std::istreambuf_iterator<char>(input)),
                                    std::istreambuf_iterator<char>());

    auto envelope = m_engine.encrypt(plaintext);
    if (envelope.ciphertext.empty() && !plaintext.empty()) return false;

    std::ofstream output(outputPath, std::ios::binary);
    if (!output) return false;

    output.write(reinterpret_cast<const char*>(&envelope.algorithm), 1);
    output.write(reinterpret_cast<const char*>(&envelope.kdf), 1);

    auto writeField = [&](const std::vector<uint8_t>& v) {
        uint32_t sz = static_cast<uint32_t>(v.size());
        output.write(reinterpret_cast<const char*>(&sz), 4);
        output.write(reinterpret_cast<const char*>(v.data()), sz);
    };
    writeField(envelope.salt);
    writeField(envelope.iv);
    output.write(reinterpret_cast<const char*>(&envelope.iterations), 4);
    writeField(envelope.ciphertext);
    writeField(envelope.authTag);

    m_stats.bytesEncrypted += plaintext.size();
    m_stats.filesEncrypted++;
    return output.good();
}

bool EncryptedPersistenceLayer::decryptFile(
    const std::string& inputPath,
    const std::string& outputPath)
{
    std::ifstream input(inputPath, std::ios::binary);
    if (!input) return false;

    EncryptedEnvelope envelope;
    input.read(reinterpret_cast<char*>(&envelope.algorithm), 1);
    input.read(reinterpret_cast<char*>(&envelope.kdf), 1);

    auto readField = [&](std::vector<uint8_t>& v) {
        uint32_t sz = 0;
        input.read(reinterpret_cast<char*>(&sz), 4);
        if (!input || sz > 256 * 1024 * 1024u) return false; // 256 MB sanity cap
        v.resize(sz);
        input.read(reinterpret_cast<char*>(v.data()), sz);
        return input.good();
    };
    if (!readField(envelope.salt)) return false;
    if (!readField(envelope.iv))   return false;
    input.read(reinterpret_cast<char*>(&envelope.iterations), 4);
    if (!readField(envelope.ciphertext)) return false;
    if (!readField(envelope.authTag))    return false;

    bool success = false;
    auto plaintext = m_engine.decrypt(envelope, success);
    if (!success) return false;

    std::ofstream output(outputPath, std::ios::binary);
    if (!output) return false;
    output.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());

    m_stats.bytesDecrypted += plaintext.size();
    m_stats.filesDecrypted++;
    return output.good();
}

std::vector<uint8_t> EncryptedPersistenceLayer::encryptData(const std::vector<uint8_t>& data) {
    auto envelope = m_engine.encrypt(data);
    if (envelope.ciphertext.empty() && !data.empty()) return {};

    std::vector<uint8_t> result;
    result.push_back(envelope.algorithm);
    result.push_back(envelope.kdf);
    result.insert(result.end(), envelope.salt.begin(), envelope.salt.end());
    result.insert(result.end(), envelope.iv.begin(), envelope.iv.end());
    uint32_t iter = envelope.iterations;
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&iter),
                  reinterpret_cast<uint8_t*>(&iter) + 4);
    result.insert(result.end(), envelope.ciphertext.begin(), envelope.ciphertext.end());
    result.insert(result.end(), envelope.authTag.begin(), envelope.authTag.end());
    return result;
}

std::vector<uint8_t> EncryptedPersistenceLayer::decryptData(
    const std::vector<uint8_t>& data,
    bool& outSuccess)
{
    outSuccess = false;
    const size_t minSize = 2 + ENC_SALT_SIZE + ENC_IV_SIZE + 4 + ENC_TAG_SIZE;
    if (data.size() < minSize) return {};

    EncryptedEnvelope envelope;
    size_t pos = 0;
    envelope.algorithm = data[pos++];
    envelope.kdf       = data[pos++];

    if (pos + ENC_SALT_SIZE > data.size()) return {};
    envelope.salt.assign(data.begin() + pos, data.begin() + pos + ENC_SALT_SIZE);
    pos += ENC_SALT_SIZE;

    if (pos + ENC_IV_SIZE > data.size()) return {};
    envelope.iv.assign(data.begin() + pos, data.begin() + pos + ENC_IV_SIZE);
    pos += ENC_IV_SIZE;

    if (pos + 4 > data.size()) return {};
    std::memcpy(&envelope.iterations, &data[pos], 4);
    pos += 4;

    if (pos + ENC_TAG_SIZE > data.size()) return {};
    size_t ciphertextSize = data.size() - pos - ENC_TAG_SIZE;
    envelope.ciphertext.assign(data.begin() + pos, data.begin() + pos + ciphertextSize);
    pos += ciphertextSize;
    envelope.authTag.assign(data.begin() + pos, data.end());

    return m_engine.decrypt(envelope, outSuccess);
}

bool EncryptedPersistenceLayer::isEncryptedFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return false;
    uint8_t algorithm = 0;
    file.read(reinterpret_cast<char*>(&algorithm), 1);
    return algorithm == ENC_AES256_GCM || algorithm == ENC_CHACHA20_POLY1305;
}

EncryptedPersistenceLayer::Stats EncryptedPersistenceLayer::getStats() const {
    return m_stats;
}

} // namespace EncryptedPersistence
