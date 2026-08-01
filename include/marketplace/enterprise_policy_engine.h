=====================================================================
// EnterprisePolicyEngine — C++20, no Qt. Enterprise extension policies.
// ============================================================================

#include <functional>
#include <list>
#include <string>
#include <vector>

/**
 * Manages enterprise policies for extension installation:
 * JWT SSO, allow/deny lists, signature verification, compliance, audit logging.
 */
class EnterprisePolicyEngine {
public:
    EnterprisePolicyEngine() = default;
    ~EnterprisePolicyEngine();

    void setAllowList(const std::vector<std::string>& extensionIds);
    void setDenyList(const std::vector<std::string>& extensionIds);
    void setRequireSignature(bool require);
    void setJwtSecret(const std::string& secret);

    bool isExtensionAllowed(const std::string& extensionId);
    bool verifyExtensionSignature(const std::string& extensionId, const std::string& signature);
    bool validateUserAccess(const std::string& userId, const std::string& jwtToken);

    void logExtensionInstallation(const std::string& extensionId, const std::string& userId);
    void logExtensionUninstallation(const std::string& extensionId, const std::string& userId);
    /** Returns JSON-serialized audit entries (replaces QList<QJsonObject>) */
    std::vector<std::string> getAuditLog(int limit = 100);

    bool isJwtValid(const std::string& token);
    std::string generateJwtToken(const std::string& userId, const std::vector<std::string>& permissions);

    using PolicyViolationFn = std::function<void(const std::string& extensionId, const std::string& reason)>;
    using AuditLogEntryFn = std::function<void(const std::string& entry)>;
    using ComplianceChangedFn = std::function<void(bool compliant)>;
    void setOnPolicyViolation(PolicyViolationFn fn) { m_onPolicyViolation = std::move(fn); }
    void setOnAuditLogEntry(AuditLogEntryFn fn) { m_onAuditLogEntry = std::move(fn); }
    void setOnComplianceStatusChanged(ComplianceChangedFn fn) { m_onComplianceStatusChanged = std::move(fn); }

private:
    struct PolicySettings {
        std::vector<std::string> allowList;
        std::vector<std::string> denyList;
        bool requireSignature = false;
        std::string jwtSecret;
    };

    struct AuditEntry {
        std::string timestamp;
        std::string userId;
        std::string extensionId;
        std::string action;
        std::string details;
    };

    bool checkAllowList(const std::string& extensionId);
    bool checkDenyList(const std::string& extensionId);
    void addToAuditLog(const std::string& userId, const std::string& extensionId, const std::string& action, const std::string& details);
    std::string getCurrentTimestamp();
    bool verifyJwtSignature(const std::string& token);

    PolicySettings m_settings;
    std::list<AuditEntry> m_auditLog;
    bool m_compliant = true;

    PolicyViolationFn m_onPolicyViolation;
    AuditLogEntryFn m_onAuditLogEntry;
    ComplianceChangedFn m_onComplianceStatusChanged;
};
=======
#pragma once

#include <QObject>
#include <QString>
#include <QList>
#include <QJsonObject>

/**
 * @class EnterprisePolicyEngine
 * @brief Manages enterprise policies for extension installation
 * 
 * This class handles:
 * - JWT-based Single Sign-On (SSO)
 * - Extension allow-list/deny-list enforcement
 * - Digital signature verification
 * - Compliance checking
 * - Audit logging
 */
class EnterprisePolicyEngine : public QObject {
    Q_OBJECT

public:
    explicit EnterprisePolicyEngine(QObject* parent = nullptr);
    ~EnterprisePolicyEngine();

    // Policy configuration
    void setAllowList(const QStringList& extensionIds);
    void setDenyList(const QStringList& extensionIds);
    void setRequireSignature(bool require);
    void setJwtSecret(const QString& secret);
    
    // Policy enforcement
    bool isExtensionAllowed(const QString& extensionId);
    bool verifyExtensionSignature(const QString& extensionId, const QString& signature);
    bool validateUserAccess(const QString& userId, const QString& jwtToken);
    
    // Compliance and audit
    void logExtensionInstallation(const QString& extensionId, const QString& userId);
    void logExtensionUninstallation(const QString& extensionId, const QString& userId);
    QList<QJsonObject> getAuditLog(int limit = 100);
    
    // Utility methods
    bool isJwtValid(const QString& token);
    QString generateJwtToken(const QString& userId, const QStringList& permissions);

signals:
    void policyViolation(const QString& extensionId, const QString& reason);
    void auditLogEntry(const QJsonObject& entry);
    void complianceStatusChanged(bool compliant);

private:
    struct PolicySettings {
        QStringList allowList;
        QStringList denyList;
        bool requireSignature;
        QString jwtSecret;
    };
    
    struct AuditEntry {
        QString timestamp;
        QString userId;
        QString extensionId;
        QString action; // install, uninstall, block
        QString details;
    };

    PolicySettings m_settings;
    QList<AuditEntry> m_auditLog;
    bool m_compliant;

    bool checkAllowList(const QString& extensionId);
    bool checkDenyList(const QString& extensionId);
    void addToAuditLog(const QString& userId, const QString& extensionId, const QString& action, const QString& details);
    QString getCurrentTimestamp();
    bool verifyJwtSignature(const QString& token);
};

