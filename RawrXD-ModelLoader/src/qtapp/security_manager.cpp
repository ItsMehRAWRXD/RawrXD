#include "security_manager.h"
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QSettings>
#include <cstring>
#include <algorithm>

// OpenSSL headers for AES-256-GCM
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Static instance for singleton pattern
static SecurityManager* g_securityManagerInstance = nullptr;
static const int MAX_AUDIT_ENTRIES = 10000;
static const int PBKDF2_ITERATIONS = 100000;
static const int AES_KEY_SIZE = 32;  // 256 bits
static const int AES_IV_SIZE = 12;   // 96 bits for GCM
static const int GCM_TAG_SIZE = 16;  // 128 bits

/**
 * @brief SecurityManager::getInstance - Get singleton instance
 */
SecurityManager* SecurityManager::getInstance()
{
    if (!g_securityManagerInstance) {
        g_securityManagerInstance = new SecurityManager();
    }
    return g_securityManagerInstance;
}

/**
 * @brief SecurityManager::SecurityManager - Constructor
 */
SecurityManager::SecurityManager(QObject* parent)
    : QObject(parent), m_encryptionAlgorithm(EncryptionAlgorithm::AES256_GCM),
      m_isInitialized(false), m_masterKeyDerived(false)
{
    qDebug() << "[SecurityManager] Initializing security manager";
    
    // Initialize master key and cryptographic materials
    initializeMasterKey();
    loadCredentials();
    loadAuditLog();
    loadAccessControlList();
    
    m_isInitialized = true;
    qDebug() << "[SecurityManager] Security manager initialized";
}

/**
 * @brief SecurityManager::~SecurityManager - Destructor
 */
SecurityManager::~SecurityManager()
{
    // Clear sensitive data
    m_masterKey.fill(0);
    m_derivedKey.fill(0);
    
    // Persist audit log
    saveAuditLog();
    saveCredentials();
    
    qDebug() << "[SecurityManager] Security manager destroyed";
}

/**
 * @brief SecurityManager::initializeMasterKey - Derive master key from password
 */
bool SecurityManager::initializeMasterKey()
{
    qDebug() << "[SecurityManager] Initializing master key";
    
    try {
        // Get or create master password from secure storage
        QString masterPassword = getMasterPassword();
        if (masterPassword.isEmpty()) {
            qWarning() << "[SecurityManager] Master password not set!";
            return false;
        }
        
        // Derive master key using PBKDF2
        QByteArray salt = generateRandomBytes(32);
        m_masterKey = derivePBKDF2Key(masterPassword, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE);
        m_masterKeyDerived = true;
        
        qDebug() << "[SecurityManager] Master key derived successfully";
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[SecurityManager] Failed to initialize master key:" << e.what();
        return false;
    }
}

/**
 * @brief SecurityManager::encryptData - Encrypt data using AES-256-GCM
 */
QByteArray SecurityManager::encryptData(const QByteArray& plaintext)
{
    if (!m_masterKeyDerived) {
        qWarning() << "[SecurityManager] Master key not derived, cannot encrypt";
        return QByteArray();
    }
    
    try {
        // Generate random IV
        QByteArray iv = generateRandomBytes(AES_IV_SIZE);
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        
        // Initialize encryption
        int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
                                     reinterpret_cast<unsigned char*>(m_masterKey.data()),
                                     reinterpret_cast<unsigned char*>(iv.data()));
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }
        
        // Allocate output buffer
        QByteArray ciphertext(plaintext.length() + GCM_TAG_SIZE, 0);
        int len = 0;
        int ciphertext_len = 0;
        
        // Encrypt data
        ret = EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()),
                               &len, reinterpret_cast<const unsigned char*>(plaintext.data()),
                               plaintext.length());
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed");
        }
        ciphertext_len = len;
        
        // Finalize encryption
        ret = EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len,
                                 &len);
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }
        ciphertext_len += len;
        
        // Get authentication tag
        QByteArray tag(GCM_TAG_SIZE, 0);
        ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE,
                                  reinterpret_cast<unsigned char*>(tag.data()));
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to get authentication tag");
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Combine IV + ciphertext + tag
        return iv + ciphertext.left(ciphertext_len) + tag;
    }
    catch (const std::exception& e) {
        qCritical() << "[SecurityManager] Encryption failed:" << e.what();
        return QByteArray();
    }
}

/**
 * @brief SecurityManager::decryptData - Decrypt data using AES-256-GCM
 */
QByteArray SecurityManager::decryptData(const QByteArray& encrypted)
{
    if (!m_masterKeyDerived) {
        qWarning() << "[SecurityManager] Master key not derived, cannot decrypt";
        return QByteArray();
    }
    
    try {
        // Extract components
        if (encrypted.length() < AES_IV_SIZE + GCM_TAG_SIZE) {
            throw std::runtime_error("Invalid encrypted data length");
        }
        
        QByteArray iv = encrypted.left(AES_IV_SIZE);
        QByteArray tag = encrypted.right(GCM_TAG_SIZE);
        QByteArray ciphertext = encrypted.mid(AES_IV_SIZE, encrypted.length() - AES_IV_SIZE - GCM_TAG_SIZE);
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        
        // Initialize decryption
        int ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                     reinterpret_cast<unsigned char*>(m_masterKey.data()),
                                     reinterpret_cast<unsigned char*>(iv.data()));
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }
        
        // Set authentication tag
        ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                                  reinterpret_cast<unsigned char*>(tag.data()));
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set authentication tag");
        }
        
        // Allocate output buffer
        QByteArray plaintext(ciphertext.length(), 0);
        int len = 0;
        int plaintext_len = 0;
        
        // Decrypt data
        ret = EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()),
                               &len, reinterpret_cast<const unsigned char*>(ciphertext.data()),
                               ciphertext.length());
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed");
        }
        plaintext_len = len;
        
        // Finalize decryption (verify tag)
        ret = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len);
        if (ret != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to verify authentication tag");
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        plaintext.truncate(plaintext_len);
        return plaintext;
    }
    catch (const std::exception& e) {
        qCritical() << "[SecurityManager] Decryption failed:" << e.what();
        return QByteArray();
    }
}

/**
 * @brief SecurityManager::computeHMAC - Compute HMAC-SHA256
 */
QByteArray SecurityManager::computeHMAC(const QByteArray& data, const QByteArray& key)
{
    try {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        
        HMAC(EVP_sha256(), reinterpret_cast<const unsigned char*>(key.data()), key.length(),
             reinterpret_cast<const unsigned char*>(data.data()), data.length(),
             hash, &hash_len);
        
        return QByteArray(reinterpret_cast<const char*>(hash), hash_len);
    }
    catch (const std::exception& e) {
        qCritical() << "[SecurityManager] HMAC computation failed:" << e.what();
        return QByteArray();
    }
}

/**
 * @brief SecurityManager::derivePBKDF2Key - Derive key using PBKDF2
 */
QByteArray SecurityManager::derivePBKDF2Key(const QString& password, const QByteArray& salt,
                                            int iterations, int keyLength)
{
    try {
        QByteArray pwdBytes = password.toUtf8();
        QByteArray derivedKey(keyLength, 0);
        
        int ret = PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(pwdBytes.data()), pwdBytes.length(),
            reinterpret_cast<const unsigned char*>(salt.data()), salt.length(),
            iterations, EVP_sha256(), keyLength,
            reinterpret_cast<unsigned char*>(derivedKey.data())
        );
        
        if (ret != 1) {
            throw std::runtime_error("PBKDF2 key derivation failed");
        }
        
        return derivedKey;
    }
    catch (const std::exception& e) {
        qCritical() << "[SecurityManager] PBKDF2 derivation failed:" << e.what();
        return QByteArray();
    }
}

/**
 * @brief SecurityManager::generateRandomBytes - Generate random bytes
 */
QByteArray SecurityManager::generateRandomBytes(int length)
{
    QByteArray randomBytes(length, 0);
    
    int ret = RAND_bytes(reinterpret_cast<unsigned char*>(randomBytes.data()), length);
    if (ret != 1) {
        qCritical() << "[SecurityManager] Failed to generate random bytes";
        return QByteArray();
    }
    
    return randomBytes;
}

/**
 * @brief SecurityManager::setCredential - Store encrypted credential
 */
bool SecurityManager::setCredential(const QString& name, const CredentialInfo& credential)
{
    qDebug() << "[SecurityManager] Setting credential:" << name;
    
    try {
        // Encrypt token
        QByteArray encryptedToken = encryptData(credential.token.toUtf8());
        
        // Create credential object
        QJsonObject credObj;
        credObj["username"] = credential.username;
        credObj["email"] = credential.email;
        credObj["tokenType"] = credential.tokenType;
        credObj["token"] = QString::fromUtf8(encryptedToken.toBase64());
        credObj["expiresAt"] = credential.expiresAt.toString(Qt::ISODate);
        credObj["lastRotated"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        
        m_credentials[name] = credObj;
        saveCredentials();
        
        // Audit log
        auditLog("CREDENTIAL_SET", QString("Credential set: %1").arg(name), "SUCCESS");
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[SecurityManager] Failed to set credential:" << e.what();
        auditLog("CREDENTIAL_SET", QString("Credential set failed: %1").arg(name), "FAILURE");
        return false;
    }
}

/**
 * @brief SecurityManager::getCredential - Retrieve and decrypt credential
 */
bool SecurityManager::getCredential(const QString& name, CredentialInfo& credential)
{
    qDebug() << "[SecurityManager] Retrieving credential:" << name;
    
    try {
        if (m_credentials.find(name) == m_credentials.end()) {
            qWarning() << "[SecurityManager] Credential not found:" << name;
            return false;
        }
        
        QJsonObject credObj = m_credentials[name];
        
        // Decrypt token
        QByteArray encryptedToken = QByteArray::fromBase64(credObj["token"].toString().toUtf8());
        QByteArray decryptedToken = decryptData(encryptedToken);
        
        credential.username = credObj["username"].toString();
        credential.email = credObj["email"].toString();
        credential.tokenType = credObj["tokenType"].toString();
        credential.token = QString::fromUtf8(decryptedToken);
        credential.expiresAt = QDateTime::fromString(credObj["expiresAt"].toString(), Qt::ISODate);
        
        // Audit log
        auditLog("CREDENTIAL_GET", QString("Credential retrieved: %1").arg(name), "SUCCESS");
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[SecurityManager] Failed to get credential:" << e.what();
        auditLog("CREDENTIAL_GET", QString("Credential retrieval failed: %1").arg(name), "FAILURE");
        return false;
    }
}

/**
 * @brief SecurityManager::validateInput - Sanitize and validate input
 */
bool SecurityManager::validateInput(const QString& input, const QString& pattern)
{
    if (input.isEmpty()) {
        return false;
    }
    
    if (input.length() > 10000) {  // Prevent DOS
        return false;
    }
    
    // Basic SQL injection prevention
    if (input.contains("'") || input.contains("\"") || input.contains(";")) {
        return false;
    }
    
    return true;
}

/**
 * @brief SecurityManager::filterOutput - Filter sensitive data from output
 */
QString SecurityManager::filterOutput(const QString& output)
{
    QString filtered = output;
    
    // Remove API keys
    filtered.replace(QRegularExpression("api[_-]?key[=:]\\s*[\\w-]+"), "api_key=***");
    
    // Remove tokens
    filtered.replace(QRegularExpression("token[=:]\\s*[\\w-]+"), "token=***");
    
    // Remove passwords
    filtered.replace(QRegularExpression("password[=:]\\s*[\\w-]+"), "password=***");
    
    return filtered;
}

/**
 * @brief SecurityManager::checkRateLimit - Check if action exceeds rate limit
 */
bool SecurityManager::checkRateLimit(const QString& action, int maxRequests, int windowSeconds)
{
    qDebug() << "[SecurityManager] Checking rate limit for action:" << action;
    
    QDateTime now = QDateTime::currentDateTime();
    QDateTime windowStart = now.addSecs(-windowSeconds);
    
    // Count requests in window
    int requestCount = 0;
    for (const auto& entry : m_auditLog) {
        if (entry["action"].toString() == action) {
            QDateTime entryTime = QDateTime::fromString(entry["timestamp"].toString(), Qt::ISODate);
            if (entryTime > windowStart) {
                requestCount++;
            }
        }
    }
    
    if (requestCount >= maxRequests) {
        qWarning() << "[SecurityManager] Rate limit exceeded for action:" << action;
        auditLog("RATE_LIMIT_EXCEEDED", QString("Action: %1, Requests: %2").arg(action).arg(requestCount), "WARNING");
        return false;
    }
    
    return true;
}

/**
 * @brief SecurityManager::auditLog - Log security event
 */
void SecurityManager::auditLog(const QString& action, const QString& details, const QString& status)
{
    QJsonObject entry;
    entry["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    entry["action"] = action;
    entry["details"] = filterOutput(details);
    entry["status"] = status;
    entry["user"] = getCurrentUser();
    
    m_auditLog.append(entry);
    
    // Maintain max entries
    if (m_auditLog.size() > MAX_AUDIT_ENTRIES) {
        m_auditLog.removeAt(0);
    }
    
    // Emit signal
    emit auditLogChanged(entry);
}

/**
 * @brief SecurityManager::loadCredentials - Load credentials from disk
 */
void SecurityManager::loadCredentials()
{
    try {
        QString credPath = getCredentialsPath();
        QFile file(credPath);
        
        if (!file.open(QIODevice::ReadOnly)) {
            qDebug() << "[SecurityManager] Credentials file not found, starting fresh";
            return;
        }
        
        QByteArray data = file.readAll();
        file.close();
        
        QJsonDocument doc = QJsonDocument::fromJson(data);
        m_credentials = doc.object().toVariantMap();
        
        qDebug() << "[SecurityManager] Loaded" << m_credentials.size() << "credentials";
    }
    catch (const std::exception& e) {
        qWarning() << "[SecurityManager] Failed to load credentials:" << e.what();
    }
}

/**
 * @brief SecurityManager::saveCredentials - Persist credentials to disk
 */
void SecurityManager::saveCredentials()
{
    try {
        QString credPath = getCredentialsPath();
        QDir().mkpath(QFileInfo(credPath).absolutePath());
        
        QJsonObject obj;
        for (auto it = m_credentials.begin(); it != m_credentials.end(); ++it) {
            obj[it.key()] = QJsonValue::fromVariant(it.value());
        }
        
        QJsonDocument doc(obj);
        QFile file(credPath);
        
        if (!file.open(QIODevice::WriteOnly)) {
            qWarning() << "[SecurityManager] Failed to open credentials file for writing";
            return;
        }
        
        file.write(doc.toJson());
        file.close();
        
        qDebug() << "[SecurityManager] Saved credentials to" << credPath;
    }
    catch (const std::exception& e) {
        qWarning() << "[SecurityManager] Failed to save credentials:" << e.what();
    }
}

/**
 * @brief SecurityManager::loadAuditLog - Load audit log from disk
 */
void SecurityManager::loadAuditLog()
{
    try {
        QString auditPath = getAuditLogPath();
        QFile file(auditPath);
        
        if (!file.open(QIODevice::ReadOnly)) {
            qDebug() << "[SecurityManager] Audit log file not found, starting fresh";
            return;
        }
        
        QByteArray data = file.readAll();
        file.close();
        
        QJsonDocument doc = QJsonDocument::fromJson(data);
        m_auditLog = doc.array().toVariantList();
        
        qDebug() << "[SecurityManager] Loaded" << m_auditLog.size() << "audit entries";
    }
    catch (const std::exception& e) {
        qWarning() << "[SecurityManager] Failed to load audit log:" << e.what();
    }
}

/**
 * @brief SecurityManager::saveAuditLog - Persist audit log to disk
 */
void SecurityManager::saveAuditLog()
{
    try {
        QString auditPath = getAuditLogPath();
        QDir().mkpath(QFileInfo(auditPath).absolutePath());
        
        QJsonArray arr;
        for (const auto& entry : m_auditLog) {
            arr.append(QJsonValue::fromVariant(entry));
        }
        
        QJsonDocument doc(arr);
        QFile file(auditPath);
        
        if (!file.open(QIODevice::WriteOnly)) {
            qWarning() << "[SecurityManager] Failed to open audit log for writing";
            return;
        }
        
        file.write(doc.toJson());
        file.close();
        
        qDebug() << "[SecurityManager] Saved audit log to" << auditPath;
    }
    catch (const std::exception& e) {
        qWarning() << "[SecurityManager] Failed to save audit log:" << e.what();
    }
}

/**
 * @brief SecurityManager::loadAccessControlList - Load ACL from disk
 */
void SecurityManager::loadAccessControlList()
{
    try {
        QString aclPath = getACLPath();
        QFile file(aclPath);
        
        if (!file.open(QIODevice::ReadOnly)) {
            qDebug() << "[SecurityManager] ACL file not found, using default permissions";
            return;
        }
        
        QByteArray data = file.readAll();
        file.close();
        
        QJsonDocument doc = QJsonDocument::fromJson(data);
        m_accessControlList = doc.object().toVariantMap();
        
        qDebug() << "[SecurityManager] Loaded ACL with" << m_accessControlList.size() << "entries";
    }
    catch (const std::exception& e) {
        qWarning() << "[SecurityManager] Failed to load ACL:" << e.what();
    }
}

/**
 * @brief SecurityManager::getMasterPassword - Get master password
 */
QString SecurityManager::getMasterPassword()
{
    // In production, this should read from secure storage (Windows DPAPI, Keychain, etc.)
    QSettings settings;
    return settings.value("security/masterPassword", "").toString();
}

/**
 * @brief SecurityManager::getCredentialsPath - Get path to credentials file
 */
QString SecurityManager::getCredentialsPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/credentials.json";
}

/**
 * @brief SecurityManager::getAuditLogPath - Get path to audit log
 */
QString SecurityManager::getAuditLogPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/audit.log";
}

/**
 * @brief SecurityManager::getACLPath - Get path to ACL file
 */
QString SecurityManager::getACLPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/acl.json";
}

/**
 * @brief SecurityManager::getCurrentUser - Get current user name
 */
QString SecurityManager::getCurrentUser()
{
    return QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
}
