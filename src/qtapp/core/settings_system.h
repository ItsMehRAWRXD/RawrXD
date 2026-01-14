#pragma once

#include <QString>
#include <QObject>
#include <QVariant>
#include <QMap>
#include <QJsonObject>
#include <memory>

/**
 * @file settings_system.h
 * @brief Centralized configuration management with persistence
 * 
 * Provides:
 * - Settings persistence via QSettings
 * - Schema-based validation
 * - UI widget auto-binding
 * - Settings migration
 * - Change notifications
 */

class SettingsSystem : public QObject {
    Q_OBJECT

public:
    /**
     * Settings category/schema
     */
    enum class Category {
        Editor,
        Build,
        Debug,
        Git,
        Appearance,
        Performance,
        Network,
        Advanced
    };

    /**
     * Setting definition
     */
    struct Setting {
        QString key;
        QString displayName;
        QString description;
        QVariant defaultValue;
        QVariant currentValue;
        Category category;
        QString valueType;  // "string", "int", "bool", "double", "color", "font"
        QVariant minValue;
        QVariant maxValue;
        QStringList enumValues;
    };

    static SettingsSystem& instance();

    /**
     * Register a setting
     */
    void registerSetting(const Setting& setting);

    /**
     * Get setting value
     */
    QVariant getSetting(const QString& key, const QVariant& defaultValue = QVariant()) const;

    /**
     * Set setting value
     */
    bool setSetting(const QString& key, const QVariant& value);

    /**
     * Get all settings in category
     */
    QMap<QString, QVariant> getSettingsInCategory(Category category) const;

    /**
     * Get all settings
     */
    QMap<QString, QVariant> getAllSettings() const;

    /**
     * Check if setting exists
     */
    bool hasSetting(const QString& key) const;

    /**
     * Get setting definition
     */
    Setting getSettingDefinition(const QString& key) const;

    /**
     * Get all registered settings
     */
    QStringList getRegisteredSettings() const;

    /**
     * Save all settings to persistent storage
     */
    void saveSettings();

    /**
     * Load all settings from persistent storage
     */
    void loadSettings();

    /**
     * Reset all settings to defaults
     */
    void resetToDefaults();

    /**
     * Reset category to defaults
     */
    void resetCategoryToDefaults(Category category);

    /**
     * Reset single setting to default
     */
    bool resetSetting(const QString& key);

    /**
     * Import settings from JSON
     */
    bool importSettings(const QJsonObject& json);

    /**
     * Export settings to JSON
     */
    QJsonObject exportSettings() const;

    /**
     * Export category to JSON
     */
    QJsonObject exportCategory(Category category) const;

    /**
     * Validate setting value
     */
    bool validateValue(const QString& key, const QVariant& value) const;

    /**
     * Get setting value type
     */
    QString getValueType(const QString& key) const;

    /**
     * Get enum options for setting
     */
    QStringList getEnumValues(const QString& key) const;

    /**
     * Watch setting changes
     */
    void watchSetting(const QString& key, QObject* receiver, const char* member);

    /**
     * Unwatch setting
     */
    void unwatchSetting(const QString& key, QObject* receiver);

    /**
     * Get settings group (for organizing UI)
     */
    QStringList getSettingsGroup(const QString& groupName) const;

    /**
     * Create settings group
     */
    void registerSettingsGroup(const QString& groupName, const QStringList& settingKeys);

    /**
     * Migrate old settings version
     */
    bool migrateSettings(int fromVersion);

    /**
     * Get current settings version
     */
    int getSettingsVersion() const;

    /**
     * Get editor-specific settings as convenience
     */
    QMap<QString, QVariant> getEditorSettings() const;

    /**
     * Get build-specific settings as convenience
     */
    QMap<QString, QVariant> getBuildSettings() const;

    /**
     * Get appearance-specific settings as convenience
     */
    QMap<QString, QVariant> getAppearanceSettings() const;

signals:
    /**
     * Setting changed
     */
    void settingChanged(const QString& key, const QVariant& newValue, const QVariant& oldValue);

    /**
     * Multiple settings changed
     */
    void settingsChanged(const QStringList& keys);

    /**
     * Settings saved
     */
    void settingsSaved();

    /**
     * Settings loaded
     */
    void settingsLoaded();

    /**
     * Settings reset
     */
    void settingsReset();

    /**
     * Settings migrated
     */
    void settingsMigrated(int fromVersion, int toVersion);

private:
    SettingsSystem();
    ~SettingsSystem() override;

    struct SettingWatcher {
        QObject* receiver;
        const char* member;
    };

    QMap<QString, Setting> m_settings;
    QMap<QString, QList<SettingWatcher>> m_watchers;
    QMap<QString, QStringList> m_settingsGroups;

    int m_currentVersion = 1;
    static constexpr const char* SETTINGS_ORG = "RawrXD";
    static constexpr const char* SETTINGS_APP = "IDE";
    static constexpr const char* VERSION_KEY = "Settings/Version";

    void initializeDefaults();
    bool migrateFromV0();
    QVariant validateAndCoerce(const QString& key, const QVariant& value) const;
};
