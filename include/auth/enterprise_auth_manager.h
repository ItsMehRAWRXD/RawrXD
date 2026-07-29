<<<<<<< HEAD
#ifndef ENTERPRISE_AUTH_MANAGER_H
#define ENTERPRISE_AUTH_MANAGER_H

// C++20, no Qt. JWT & enterprise auth; config from enterprise.json.

#include <string>
#include <functional>

class EnterpriseAuthManager
{
public:
    using AuthSucceededFn = std::function<void(const std::string& upn)>;
    using AuthFailedFn    = std::function<void(const std::string& reason)>;

    EnterpriseAuthManager() = default;
    ~EnterpriseAuthManager() = default;

    void setOnAuthenticationSucceeded(AuthSucceededFn f) { m_onSucceeded = std::move(f); }
    void setOnAuthenticationFailed(AuthFailedFn f)         { m_onFailed = std::move(f); }

    bool loadConfig(const std::string& configPath);
    bool authenticateWithToken(const std::string& bearerToken);
    std::string getUserUPN() const;
    std::string getSettingsFolderPath() const;
    bool isAuthenticated() const { return m_authenticated; }

private:
    bool fetchPublicKeys();
    bool validateToken(const std::string& token);
    std::string extractUPN(const std::string& token);

    std::string m_provider;
    std::string m_clientId;
    std::string m_jwksUrl;
    std::string m_userUPN;
    bool m_authenticated = false;

    AuthSucceededFn m_onSucceeded;
    AuthFailedFn    m_onFailed;
};

#endif // ENTERPRISE_AUTH_MANAGER_H
=======
#ifndef ENTERPRISE_AUTH_MANAGER_H
#define ENTERPRISE_AUTH_MANAGER_H

#include <QObject>
#include <QString>
#include <QMap>
#include <QVariant>
#include <QJsonObject>

// JWT & Enterprise Auth - Config file enterprise.json: 
// {"provider": "azure-ad", "client_id": "...", "jwks_url": "..."}
// On start-up: fetch public keys, validate bearer token, extract upn → use as folder suffix for settings (~/.rawrxd/<upn>/).
class EnterpriseAuthManager : public QObject
{
    Q_OBJECT

public:
    explicit EnterpriseAuthManager(QObject *parent = nullptr);
    ~EnterpriseAuthManager();

    // Load enterprise configuration
    bool loadConfig(const QString &configPath);

    // Authenticate user with bearer token
    bool authenticateWithToken(const QString &bearerToken);

    // Get authenticated user UPN (User Principal Name)
    QString getUserUPN() const;

    // Get settings folder path with UPN suffix
    QString getSettingsFolderPath() const;

    // Check if user is authenticated
    bool isAuthenticated() const;

signals:
    void authenticationSucceeded(const QString &upn);
    void authenticationFailed(const QString &reason);

private:
    QString m_provider;           // azure-ad, okta, etc.
    QString m_clientId;
    QString m_jwksUrl;
    QString m_userUPN;
    bool m_authenticated;

    // Fetch JWKS from remote endpoint
    bool fetchPublicKeys();

    // Validate JWT token
    bool validateToken(const QString &token);

    // Extract UPN from token claims
    QString extractUPN(const QString &token);
};

#endif // ENTERPRISE_AUTH_MANAGER_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
