#include "jwt_validator.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QDateTime>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

namespace RawrXD {
namespace Auth {

// ============================================================
// JWKS MANAGER IMPLEMENTATION
// ============================================================

JWKSManager::JWKSManager() {}

JWKSManager::~JWKSManager() {}

bool JWKSManager::loadFromJson(const QJsonObject& jwksJson) {
    if (!jwksJson.contains("keys")) {
        return false;
    }

    QJsonArray keysArray = jwksJson["keys"].toArray();
    keys.clear();

    for (const auto& keyValue : keysArray) {
        if (keyValue.isObject()) {
            auto jwk = std::make_shared<JWK>(JWK::fromJson(keyValue.toObject()));
            keys.push_back(jwk);
        }
    }

    return !keys.empty();
}

std::shared_ptr<JWK> JWKSManager::findKey(const QString& keyId) {
    for (const auto& key : keys) {
        if (key->keyId == keyId) {
            return key;
        }
    }
    return nullptr;
}

std::vector<std::shared_ptr<JWK>> JWKSManager::getAllKeys() const {
    return keys;
}

bool JWKSManager::verifyJWTSignature(const JWT& token, const std::shared_ptr<JWK>& key) {
    if (!key || !token.isValid) {
        return false;
    }

    auto base64UrlDecode = [](const QString& input) -> QByteArray {
        QByteArray data = input.toUtf8();
        data.replace('-', '+');
        data.replace('_', '/');
        while (data.size() % 4 != 0) {
            data.append('=');
        }
        return QByteArray::fromBase64(data);
    };

    // Rebuild RSA public key from modulus and exponent
    QByteArray modulus = base64UrlDecode(key->publicKeyModulus);
    QByteArray exponent = base64UrlDecode(key->publicKeyExponent);
    QByteArray signature = base64UrlDecode(token.signature);

    if (modulus.isEmpty() || exponent.isEmpty() || signature.isEmpty()) {
        return false;
    }

    const QStringList parts = token.rawToken.split('.');
    if (parts.size() != 3) {
        return false;
    }
    QByteArray signingInput = parts[0].toUtf8() + '.' + parts[1].toUtf8();

    BIGNUM* n = BN_bin2bn(reinterpret_cast<const unsigned char*>(modulus.constData()), modulus.size(), nullptr);
    BIGNUM* e = BN_bin2bn(reinterpret_cast<const unsigned char*>(exponent.constData()), exponent.size(), nullptr);
    if (!n || !e) {
        if (n) BN_free(n);
        if (e) BN_free(e);
        return false;
    }

    RSA* rsa = RSA_new();
    if (!rsa) {
        BN_free(n);
        BN_free(e);
        return false;
    }

    if (RSA_set0_key(rsa, n, e, nullptr) != 1) {
        RSA_free(rsa);
        BN_free(n);
        BN_free(e);
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa);
        return false;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    const EVP_MD* md = EVP_sha256();
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey) == 1;
    if (ok) {
        ok = EVP_DigestVerifyUpdate(ctx,
                                    reinterpret_cast<const unsigned char*>(signingInput.constData()),
                                    signingInput.size()) == 1;
    }
    if (ok) {
        ok = EVP_DigestVerifyFinal(ctx,
                                   reinterpret_cast<const unsigned char*>(signature.constData()),
                                   signature.size()) == 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey); // frees rsa too
    return ok;
}

bool JWKSManager::validateJWT(const JWT& token,
                             const QString& expectedIssuer,
                             const QString& expectedAudience,
                             long long nowSeconds) {
    if (!token.isValid) {
        return false;
    }

    // Validate issuer
    if (!expectedIssuer.isEmpty() && token.claims.issuer != expectedIssuer) {
        return false;
    }

    // Validate audience
    if (!expectedAudience.isEmpty() && token.claims.audience != expectedAudience) {
        return false;
    }

    // Validate expiration
    if (token.claims.isExpired(nowSeconds)) {
        return false;
    }

    // Validate nbf (not before)
    if (nowSeconds > 0 && token.claims.notBefore > 0 && nowSeconds < token.claims.notBefore) {
        return false;
    }

    return true;
}

// ============================================================
// TOKEN PROVIDER IMPLEMENTATION
// ============================================================

TokenProvider::TokenProvider() 
    : jwksManager(std::make_unique<JWKSManager>())
{
}

TokenProvider::~TokenProvider() = default;

QString TokenProvider::createToken(const TokenClaims& claims, const QString& secret) {
    // Create header
    QJsonObject header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";

    // Create payload
    QJsonObject payload = claims.toJson();

    // Encode header and payload
    QByteArray headerJson = QJsonDocument(header).toJson(QJsonDocument::Compact);
    QByteArray payloadJson = QJsonDocument(payload).toJson(QJsonDocument::Compact);

    QString headerBase64 = QString::fromUtf8(headerJson.toBase64(QByteArray::OmitTrailingEquals));
    QString payloadBase64 = QString::fromUtf8(payloadJson.toBase64(QByteArray::OmitTrailingEquals));

    // Create signature
    QString signingInput = headerBase64 + "." + payloadBase64;
    QByteArray signature = QMessageAuthenticationCode::hash(
        signingInput.toUtf8(),
        secret.toUtf8(),
        QCryptographicHash::Sha256
    );

    QString signatureBase64 = QString::fromUtf8(signature.toBase64(QByteArray::OmitTrailingEquals));

    return signingInput + "." + signatureBase64;
}

bool TokenProvider::validateToken(const QString& token, TokenClaims& outClaims, const QString& secret) {
    JWT jwt = JWT::decode(token);
    if (!jwt.isValid) {
        return false;
    }

    // Verify signature
    QStringList parts = token.split(".");
    if (parts.size() != 3) {
        return false;
    }

    QString signingInput = parts[0] + "." + parts[1];
    QByteArray signature = QMessageAuthenticationCode::hash(
        signingInput.toUtf8(),
        secret.toUtf8(),
        QCryptographicHash::Sha256
    );

    QString expectedSignature = QString::fromUtf8(signature.toBase64(QByteArray::OmitTrailingEquals));

    if (parts[2] != expectedSignature) {
        return false;
    }

    // Basic validation
    if (jwt.claims.isExpired()) {
        return false;
    }

    outClaims = jwt.claims;
    return true;
}

TokenClaims TokenProvider::extractClaims(const QString& token) {
    JWT jwt = JWT::decode(token);
    return jwt.claims;
}

} // namespace Auth
} // namespace RawrXD
