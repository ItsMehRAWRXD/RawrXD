// D:\temp\RawrXD-agentic-ide-production\RawrXD-ModelLoader\include\pqc_crypto.h
// Post-quantum cryptography header

#pragma once

#include <QString>
#include <QByteArray>
#include <memory>
#include <map>
#include <QMutex>

namespace RawrXD {
namespace Crypto {

enum class Algorithm {
    KYBER512 = 0,
    KYBER768 = 1,
    KYBER1024 = 2,
    DILITHIUM2 = 3,
    DILITHIUM3 = 4,
    DILITHIUM5 = 5,
    FALCON512 = 6,
    SPHINCSSHA2256F = 7
};

struct KeyPairResult {
    bool success = false;
    QString keyId;
    QByteArray publicKey;
    QString errorMessage;
};

struct HybridKeyPairResult {
    bool success = false;
    QString keyId;
    QByteArray classicalPublicKey;
    QByteArray pqcPublicKey;
    QString errorMessage;
};

struct SignatureResult {
    bool success = false;
    QByteArray signature;
    QString algorithm;
    QString errorMessage;
};

struct EncryptionResult {
    bool success = false;
    QByteArray ciphertext;
    QByteArray sharedSecret;
    QString algorithm;
    QString errorMessage;
};

struct DecryptionResult {
    bool success = false;
    QByteArray sharedSecret;
    QString errorMessage;
};

class PQCCrypto {
public:
    class Impl;
    
    PQCCrypto();
    ~PQCCrypto();
    
    // Key generation
    KeyPairResult generateKeyPair(Algorithm algorithm = Algorithm::KYBER768);
    HybridKeyPairResult generateHybridKeyPair();  // Classical + PQC
    
    // Digital signatures (Dilithium)
    SignatureResult sign(const QByteArray& message, const QString& keyId);
    bool verify(const QByteArray& message, const QByteArray& signature, const QString& keyId);
    
    // Key encapsulation (Kyber)
    EncryptionResult encapsulate(const QString& keyId);
    DecryptionResult decapsulate(const QByteArray& ciphertext, const QString& keyId);
    
private:
    void initializePQC();
    QString algorithmToString(Algorithm algorithm);
    QString generateKeyId();
    QByteArray generateRandomBytes(size_t length);
    
    std::unique_ptr<Impl> impl;
};

} // namespace Crypto
} // namespace RawrXD
