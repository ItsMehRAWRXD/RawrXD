#include "CryptoVault.hpp"
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QJsonDocument>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

namespace mem {

QByteArray CryptoVault::getMasterSeed() {
    CREDENTIALW* cred = nullptr;
    if (!CredReadW(L"RawrXD_MasterSeed", CRED_TYPE_GENERIC, 0, &cred)) {
        // First launch → generate random seed
        unsigned char seed[KEY_LEN];
        if (!RAND_bytes(seed, KEY_LEN)) {
            qWarning("Failed to generate random seed");
            return {};
        }
        if (!storeMasterSeed(QByteArray(reinterpret_cast<char*>(seed), KEY_LEN))) {
            return {};
        }
        return QByteArray(reinterpret_cast<char*>(seed), KEY_LEN);
    }

    QByteArray master(reinterpret_cast<char*>(cred->CredentialBlob),
                     cred->CredentialBlobSize);
    CredFree(cred);
    return master;
}

bool CryptoVault::storeMasterSeed(const QByteArray& seed) {
    CREDENTIALW cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<LPWSTR>(L"RawrXD_MasterSeed");
    cred.CredentialBlobSize = seed.size();
    cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(seed.data()));
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    return CredWriteW(&cred, 0) != 0;
}

QByteArray CryptoVault::deriveKey(const QString& userId) {
    QByteArray master = getMasterSeed();
    if (master.isEmpty()) {
        qWarning("Failed to get master seed");
        return {};
    }

    // HKDF-SHA256: info = userId
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(userId.toUtf8());
    hash.addData(master);
    return hash.result();
}

EncryptedBlob CryptoVault::encrypt(const QByteArray& plain, const QString& userId) {
    QByteArray key = deriveKey(userId);
    if (key.isEmpty()) {
        qWarning("Failed to derive key for user: %s", userId.toStdString().c_str());
        return {};
    }

    unsigned char iv[IV_LEN];
    if (!RAND_bytes(iv, IV_LEN)) {
        qWarning("Failed to generate IV");
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qWarning("Failed to create cipher context");
        return {};
    }

    // Allocate output buffer (plaintext + tag size)
    QByteArray cipher(plain.size() + EVP_MAX_BLOCK_LENGTH, 0);
    unsigned char tag[TAG_LEN];
    int len = 0;

    // Initialize AES-256-GCM
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           reinterpret_cast<unsigned char*>(key.data()), iv)) {
        qWarning("Failed to initialize encryption");
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Encrypt
    if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(cipher.data()), &len,
                          reinterpret_cast<unsigned char*>(const_cast<char*>(plain.data())),
                          plain.size())) {
        qWarning("Encryption failed");
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int cipherLen = len;

    // Finalize
    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(cipher.data()) + len, &len)) {
        qWarning("Encryption finalization failed");
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    cipherLen += len;

    // Get authentication tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) {
        qWarning("Failed to get GCM tag");
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);

    cipher.resize(cipherLen);
    EncryptedBlob blob{
        .cipher = cipher,
        .tag = QByteArray(reinterpret_cast<char*>(tag), TAG_LEN),
        .iv = QByteArray(reinterpret_cast<char*>(iv), IV_LEN)
    };
    return blob;
}

QByteArray CryptoVault::decrypt(const EncryptedBlob& blob, const QString& userId) {
    if (blob.cipher.isEmpty() || blob.tag.isEmpty() || blob.iv.isEmpty()) {
        qWarning("Invalid blob for decryption");
        return {};
    }

    QByteArray key = deriveKey(userId);
    if (key.isEmpty()) {
        qWarning("Failed to derive key for decryption");
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qWarning("Failed to create cipher context");
        return {};
    }

    QByteArray plain(blob.cipher.size(), 0);
    int len = 0;

    // Initialize AES-256-GCM for decryption
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           reinterpret_cast<unsigned char*>(key.data()),
                           reinterpret_cast<unsigned char*>(const_cast<char*>(blob.iv.data())))) {
        qWarning("Failed to initialize decryption");
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Set expected tag for authentication
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            reinterpret_cast<char*>(const_cast<QByteArray&>(blob.tag).data()))) {
        qWarning("Failed to set GCM tag");
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Decrypt
    if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plain.data()), &len,
                          reinterpret_cast<unsigned char*>(const_cast<char*>(blob.cipher.data())),
                          blob.cipher.size())) {
        qWarning("Decryption failed");
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int plainLen = len;

    // Finalize and verify tag
    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plain.data()) + len, &len)) {
        qWarning("Decryption finalization failed - authentication tag invalid");
        EVP_CIPHER_CTX_free(ctx);
        return {};  // Authentication failed
    }
    plainLen += len;

    EVP_CIPHER_CTX_free(ctx);

    plain.resize(plainLen);
    return plain;
}

EncryptedBlob CryptoVault::encryptJson(const QJsonObject& obj, const QString& userId) {
    QJsonDocument doc(obj);
    return encrypt(doc.toJson(QJsonDocument::Compact), userId);
}

QJsonObject CryptoVault::decryptJson(const EncryptedBlob& blob, const QString& userId) {
    QByteArray plain = decrypt(blob, userId);
    if (plain.isEmpty()) return {};
    
    QJsonDocument doc = QJsonDocument::fromJson(plain);
    return doc.object();
}

} // namespace mem
