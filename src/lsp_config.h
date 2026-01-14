/**
 * \file lsp_config.h
 * \brief LSP Configuration Management
 * \author RawrXD Team
 * \date 2026-01-10
 * 
 * Handles externalized configuration for LSP servers via:
 * - Environment variables
 * - JSON configuration files
 * - Feature toggles
 * - Language-specific settings
 */

#pragma once

#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QMap>
#include <memory>

namespace RawrXD {

/**
 * \brief LSP Configuration Manager
 * 
 * Provides centralized configuration for LSP servers with support for:
 * - Multiple language servers
 * - Environment variable overrides
 * - JSON-based configuration files
 * - Feature toggles
 * - Runtime configuration updates
 */
class LSPConfigManager {
public:
    /**
     * Singleton instance
     */
    static LSPConfigManager& instance();
    
    /**
     * Load configuration from file
     * 
     * \param configPath Path to JSON configuration file
     * \return true if loaded successfully
     */
    bool loadFromFile(const QString& configPath);
    
    /**
     * Load configuration from environment variables
     * 
     * Supports:
     * - RAWRXD_LSP_ENABLED (bool)
     * - RAWRXD_LSP_<LANGUAGE>_COMMAND
     * - RAWRXD_LSP_<LANGUAGE>_ARGS
     * - RAWRXD_LSP_LOGGING_LEVEL
     * - RAWRXD_LSP_DEBUG
     */
    void loadFromEnvironment();
    
    /**
     * Get LSP server command for language
     * 
     * \param language Language name (cpp, python, typescript, etc.)
     * \return Command to start LSP server
     */
    QString getServerCommand(const QString& language) const;
    
    /**
     * Get LSP server arguments for language
     * 
     * \param language Language name
     * \return List of command-line arguments
     */
    QStringList getServerArguments(const QString& language) const;
    
    /**
     * Check if feature is enabled
     * 
     * \param feature Feature name (lsp, completion, diagnostics, etc.)
     * \return true if enabled
     */
    bool isFeatureEnabled(const QString& feature) const;
    
    /**
     * Get configuration value
     * 
     * \param path Dot-separated path (e.g., "completion.cachingEnabled")
     * \param defaultValue Default value if not found
     * \return Configuration value
     */
    QVariant getConfig(const QString& path, const QVariant& defaultValue = {}) const;
    
    /**
     * Set configuration value at runtime
     * 
     * \param path Dot-separated path
     * \param value New value
     */
    void setConfig(const QString& path, const QVariant& value);
    
    /**
     * Get all languages with LSP support
     * 
     * \return List of language names
     */
    QStringList getAvailableLanguages() const;
    
    /**
     * Check if language has LSP server configured
     * 
     * \param language Language name
     * \return true if configured
     */
    bool isLanguageSupported(const QString& language) const;
    
    /**
     * Get environment variables for language server
     * 
     * \param language Language name
     * \return Map of environment variables
     */
    QMap<QString, QString> getEnvironmentVariables(const QString& language) const;
    
    /**
     * Enable or disable LSP entirely
     * 
     * \param enabled true to enable
     */
    void setLSPEnabled(bool enabled);
    
    /**
     * Check if LSP is enabled globally
     * 
     * \return true if LSP is enabled
     */
    bool isLSPEnabled() const;
    
    /**
     * Get logging level
     * 
     * \return Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
     */
    QString getLoggingLevel() const;
    
    /**
     * Get log file path
     * 
     * \return Path to log file (empty if disabled)
     */
    QString getLogFilePath() const;
    
    /**
     * Reload configuration from file
     */
    void reload();

private:
    LSPConfigManager();
    ~LSPConfigManager() = default;
    
    LSPConfigManager(const LSPConfigManager&) = delete;
    LSPConfigManager& operator=(const LSPConfigManager&) = delete;
    
    QJsonObject m_config;
    QString m_configPath;
    bool m_lspEnabled = true;
    
    QVariant getNestedValue(const QString& path) const;
    void setNestedValue(const QString& path, const QVariant& value);
};

} // namespace RawrXD
