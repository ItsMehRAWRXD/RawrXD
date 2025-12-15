#pragma once

#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <memory>
#include <vector>

// ============================================================
// JWT TOKEN VALIDATION & JWKS MANAGEMENT
// ============================================================

namespace RawrXD {
namespace Auth {

/**
 * JWK (JSON Web Key) from JWKS endpoint
 */
struct JWK {
    QString keyId;
    QString keyType;          // RSA, EC, etc.
    QString algorithm;         // RS256, ES256, etc.
    QString publicKeyModulus;  // n (for RSA)
    QString publicKeyExponent; // e (for RSA)
    QString curve;            // crv (for EC)
    QString xCoordinate;      // x (for EC)
    QString yCoordinate;      // y (for EC)
    bool isPublic = true;

    static JWK fromJson(const QJsonObject& json) {
        JWK jwk;
        jwk.keyId = json["kid"].toString();
        jwk.keyType = json["kty"].toString();
        jwk.algorithm = json["alg"].toString();
        jwk.publicKeyModulus = json["n"].toString();
        jwk.publicKeyExponent = json["e"].toString();
        jwk.curve = json["crv"].toString();
        jwk.xCoordinate = json["x"].toString();
        jwk.yCoordinate = json["y"].toString();
        jwk.isPublic = json["use"].toString() == "sig";
        return jwk;
    }

    QJsonObject toJson() const {
        QJsonObject obj;
        obj["kid"] = keyId;
        obj["kty"] = keyType;
        obj["alg"] = algorithm;
        obj["n"] = publicKeyModulus;
        obj["e"] = publicKeyExponent;
        obj["crv"] = curve;
        obj["x"] = xCoordinate;
        obj["y"] = yCoordinate;
        obj["use"] = isPublic ? "sig" : "enc";
        return obj;
    }
};

/**
 * JWT Token claims structure
 */
struct TokenClaims {
    // Standard claims
    QString issuer;           // iss
    QString subject;          // sub (user ID)
    QString audience;         // aud
    long long issuedAt = 0;   // iat
    long long expiresAt = 0;  // exp
    long long notBefore = 0;  // nbf

    // Custom claims
    QString username;
    QJsonArray scope;
    QString email;
    QString emailVerified;
    QString name;
    QString givenName;
    QString familyName;
    QString picture;
    QString locale;
    QJsonObject customClaims;

    static TokenClaims fromJson(const QJsonObject& json) {
        TokenClaims claims;
        claims.issuer = json["iss"].toString();
        claims.subject = json["sub"].toString();
        claims.audience = json["aud"].toString();
        claims.issuedAt = static_cast<long long>(json["iat"].toDouble());
        claims.expiresAt = static_cast<long long>(json["exp"].toDouble());
        claims.notBefore = static_cast<long long>(json["nbf"].toDouble());
        
        claims.username = json["preferred_username"].toString();
        claims.scope = json["scope"].toArray();
        claims.email = json["email"].toString();
        claims.emailVerified = json["email_verified"].toString();
        claims.name = json["name"].toString();
        claims.givenName = json["given_name"].toString();
        claims.familyName = json["family_name"].toString();
        claims.picture = json["picture"].toString();
        claims.locale = json["locale"].toString();

        // Copy any remaining claims as custom
        for (auto it = json.constBegin(); it != json.constEnd(); ++it) {
            const char* standardClaims[] = {
                "iss", "sub", "aud", "iat", "exp", "nbf",
                "preferred_username", "scope", "email", "email_verified",
                "name", "given_name", "family_name", "picture", "locale"
            };
            
            bool isStandard = false;
            for (const char* sc : standardClaims) {
                if (it.key() == sc) {
                    isStandard = true;
                    break;
                }
            }
            
            if (!isStandard) {
                claims.customClaims[it.key()] = it.value();
            }
        }

        return claims;
    }

    QJsonObject toJson() const {
        QJsonObject obj;
        if (!issuer.isEmpty()) obj["iss"] = issuer;
        if (!subject.isEmpty()) obj["sub"] = subject;
        if (!audience.isEmpty()) obj["aud"] = audience;
        if (issuedAt > 0) obj["iat"] = static_cast<double>(issuedAt);
        if (expiresAt > 0) obj["exp"] = static_cast<double>(expiresAt);
        if (notBefore > 0) obj["nbf"] = static_cast<double>(notBefore);

        if (!username.isEmpty()) obj["preferred_username"] = username;
        if (!scope.isEmpty()) obj["scope"] = scope;
        if (!email.isEmpty()) obj["email"] = email;
        if (!emailVerified.isEmpty()) obj["email_verified"] = emailVerified;
        if (!name.isEmpty()) obj["name"] = name;
        if (!givenName.isEmpty()) obj["given_name"] = givenName;
        if (!familyName.isEmpty()) obj["family_name"] = familyName;
        if (!picture.isEmpty()) obj["picture"] = picture;
        if (!locale.isEmpty()) obj["locale"] = locale;

        // Add custom claims
        for (auto it = customClaims.constBegin(); it != customClaims.constEnd(); ++it) {
            obj[it.key()] = it.value();
        }

        return obj;
    }

    bool isExpired(long long nowSeconds = 0) const {
        if (nowSeconds == 0) {
            nowSeconds = std::time(nullptr);
        }
        return expiresAt > 0 && nowSeconds >= expiresAt;
    }

    bool isValidAt(long long atSeconds = 0) const {
        if (atSeconds == 0) {
            atSeconds = std::time(nullptr);
        }
        return (notBefore == 0 || atSeconds >= notBefore) && 
               (expiresAt == 0 || atSeconds < expiresAt);
    }
};

/**
 * JWT Token structure with header and claims
 */
struct JWT {
    QString algorithm;        // from header
    QString keyId;           // from header (kid)
    QString tokenType;       // from header (typ)
    TokenClaims claims;
    QString signature;
    QString rawToken;

    // Parsing result
    bool isValid = false;
    QString error;

    static JWT decode(const QString& token) {
        JWT jwt;
        jwt.rawToken = token;

        // Split by dots
        QStringList parts = token.split(".");
        if (parts.size() != 3) {
            jwt.error = "Invalid token format: expected 3 parts";
            return jwt;
        }

        // Decode header
        QJsonObject header = decodeBase64Json(parts[0]);
        if (header.isEmpty()) {
            jwt.error = "Invalid token header";
            return jwt;
        }

        jwt.algorithm = header["alg"].toString();
        jwt.keyId = header["kid"].toString();
        jwt.tokenType = header["typ"].toString();

        // Decode payload
        QJsonObject payload = decodeBase64Json(parts[1]);
        if (payload.isEmpty()) {
            jwt.error = "Invalid token payload";
            return jwt;
        }

        jwt.claims = TokenClaims::fromJson(payload);
        jwt.signature = parts[2];
        jwt.isValid = true;

        return jwt;
    }

private:
    static QJsonObject decodeBase64Json(const QString& base64) {
        // Add padding if necessary
        QString padded = base64;
        int padding = 4 - (padded.length() % 4);
        if (padding != 4) {
            padded += QString(padding, '=');
        }

        // Decode from base64
        QByteArray decoded = QByteArray::fromBase64(padded.toUtf8());
        QJsonDocument doc = QJsonDocument::fromJson(decoded);

        if (doc.isObject()) {
            return doc.object();
        }
        return QJsonObject();
    }
};

/**
 * JWKS Manager - handles fetching and caching of public keys
 */
class JWKSManager {
public:
    JWKSManager();
    ~JWKSManager();

    // Load JWKS from JSON
    bool loadFromJson(const QJsonObject& jwksJson);

    // Find a specific key by ID
    std::shared_ptr<JWK> findKey(const QString& keyId);

    // Get all keys
    std::vector<std::shared_ptr<JWK>> getAllKeys() const;

    // Verify JWT signature
    bool verifyJWTSignature(const JWT& token, const std::shared_ptr<JWK>& key);

    // Validate complete JWT with all claims
    bool validateJWT(const JWT& token, 
                    const QString& expectedIssuer,
                    const QString& expectedAudience,
                    long long nowSeconds = 0);

private:
    std::vector<std::shared_ptr<JWK>> keys;
};

/**
 * Token Provider - issues and validates tokens
 */
class TokenProvider {
public:
    TokenProvider();
    ~TokenProvider();

    // Create JWT token
    QString createToken(const TokenClaims& claims, const QString& secret);

    // Validate JWT token
    bool validateToken(const QString& token, TokenClaims& outClaims, const QString& secret);

    // Extract claims without validation
    TokenClaims extractClaims(const QString& token);

private:
    std::unique_ptr<JWKSManager> jwksManager;
};

} // namespace Auth
} // namespace RawrXD
