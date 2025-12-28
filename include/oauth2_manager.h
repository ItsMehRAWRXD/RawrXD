// D:\temp\RawrXD-agentic-ide-production\RawrXD-ModelLoader\include\oauth2_manager.h
// Production OAuth2/OIDC Manager header

#pragma once

#include <QString>
#include <QDateTime>
#include <memory>
#include <set>
#include <QMutex>
#include <optional>

namespace RawrXD {
namespace Auth {

struct TokenResult {
    bool success = false;
    QString accessToken;
    QString refreshToken;
    QString tokenType = "Bearer";
    int expiresIn = 3600;
    QString errorMessage;
    
    // MFA challenge
    bool mfaRequired = false;
    QString mfaChallengeId;
};

class OAuth2Manager {
public:
    class Impl;
    
    OAuth2Manager();
    ~OAuth2Manager();
    
    // User management
    bool registerUser(const QString& username, const QString& email, const QString& password);
    TokenResult authenticate(const QString& username, const QString& password);
    TokenResult refreshAccessToken(const QString& refreshToken);
    
    // Token validation
    bool validateToken(const QString& accessToken);
    
    // RBAC - Role-Based Access Control
    bool hasPermission(const QString& userId, const QString& permission);
    bool hasRole(const QString& userId, const QString& role);
    bool assignRole(const QString& userId, const QString& role);
    
    // MFA - Multi-Factor Authentication
    bool enableMFA(const QString& userId);
    
private:
    QString generateJWT(const QString& userId, int expiresIn);
    QString generateRefreshToken(const QString& userId);
    QString hashPassword(const QString& password, const QString& salt);
    QString generateSalt();
    bool verifyPassword(const QString& password, const QString& salt, const QString& expectedHash);
    bool verifyMFA(const QString& userId);
    QString generateMFASecret();
    QString generateChallenge(const QString& userId);
    void recordFailedAttempt(const QString& clientIp);
    std::optional<QJsonObject> decodeAndVerifyJwt(const QString& token) const;
    
    std::unique_ptr<Impl> impl;
};

} // namespace Auth
} // namespace RawrXD
