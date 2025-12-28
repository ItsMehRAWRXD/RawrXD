#pragma once

#include <QString>
#include <QByteArray>
#include <QJsonObject>

namespace mem {

/**
 * @struct CryptoVault::Blob
 * @brief Encrypted data container with tag and IV
 */
struct EncryptedBlob {
    QByteArray cipher;       ///< Encrypted data
    QByteArray tag;          ///< 128-bit authentication tag
    QByteArray iv;           ///< 96-bit initialization vector
};

/**
 * @class CryptoVault
 * @brief AES-256-GCM encryption using Windows Credential Store for key derivation
 * 
 * Security model:
 * - Master seed stored in Windows Credential Store (secure storage)
 * - Per-user keys derived via HKDF(userId, master_seed)
 * - AES-256-GCM for authenticated encryption at rest
 * - 128-bit auth tag prevents tampering
 * 
 * Zero-trust: No plaintext secrets on disk or in env vars
 */
class CryptoVault {
public:
    static constexpr size_t KEY_LEN = 32;   ///< 256 bits
    static constexpr size_t IV_LEN = 12;    ///< 96 bits (GCM)
    static constexpr size_t TAG_LEN = 16;   ///< 128 bits (GCM)

    /**
     * @brief Encrypt plaintext with user-scoped key
     * @param plain Plaintext data
     * @param userId User ID (used for key derivation)
     * @return EncryptedBlob with cipher, tag, and IV
     */
    static EncryptedBlob encrypt(const QByteArray& plain, const QString& userId);

    /**
     * @brief Decrypt ciphertext with user-scoped key
     * @param blob EncryptedBlob from encrypt()
     * @param userId User ID (must match encryption userId)
     * @return Plaintext data, or empty if authentication failed
     */
    static QByteArray decrypt(const EncryptedBlob& blob, const QString& userId);

    /**
     * @brief Encrypt JSON object
     */
    static EncryptedBlob encryptJson(const QJsonObject& obj, const QString& userId);

    /**
     * @brief Decrypt to JSON object
     */
    static QJsonObject decryptJson(const EncryptedBlob& blob, const QString& userId);

private:
    /**
     * @brief Derive per-user key from master seed
     * @param userId User identifier
     * @return 32-byte key
     */
    static QByteArray deriveKey(const QString& userId);

    /**
     * @brief Get or create master seed in Credential Store
     */
    static QByteArray getMasterSeed();

    /**
     * @brief Store master seed in Windows Credential Store
     */
    static bool storeMasterSeed(const QByteArray& seed);
};

} // namespace mem
