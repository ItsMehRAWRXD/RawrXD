#pragma once

#include <QObject>
#include <QString>
#include <QMap>
#include <functional>

/**
 * @brief ModelRouter - Model selection with mode flags and fallback policy
 * 
 * Ported from model_router.asm MASM implementation.
 * Implements mode-based model selection and single-fallback on error.
 */
class ModelRouter : public QObject {
    Q_OBJECT

public:
    // Mode flags (from MASM MODE_FLAG_*)
    enum ModeFlag {
        MODE_NONE           = 0,
        MODE_MAX            = 1,      // Use high-quality model
        MODE_SEARCH_WEB     = 2,      // Enable web-search augmentation
        MODE_TURBO          = 4,      // Use turbo/deep-research mode
        MODE_AUTO_INSTANT   = 8,      // Enable auto-instant thinking
        MODE_LEGACY         = 16,     // Use legacy compatibility mode
        MODE_THINKING_STD   = 32      // Standard thinking mode
    };
    Q_DECLARE_FLAGS(ModeFlags, ModeFlag)

    explicit ModelRouter(QObject* parent = nullptr);
    ~ModelRouter();

    // Mode management (from MASM ModelRouter_GetMode/SetMode)
    void setMode(ModeFlags flags);
    ModeFlags getMode() const { return m_modeFlags; }
    void toggleMode(ModeFlag flag);

    // Fallback policy (from MASM ModelRouter_SetFallbackPolicy)
    void setFallbackPolicy(bool allowFallback);
    bool getFallbackPolicy() const { return m_allowFallback; }

    // Model selection (from MASM ModelRouter_CallModel)
    QString selectPrimaryModel() const;
    QString selectFallbackModel() const;

    // Set custom models
    void setPrimaryModel(const QString& modelName);
    void setFallbackModel(const QString& modelName);

    // Call guard (from MASM g_modelCallInProgress)
    bool isCallInProgress() const { return m_callInProgress; }
    void setCallInProgress(bool inProgress);

    // Mode descriptions for UI
    QString getModeDescription(ModeFlag flag) const;
    QMap<ModeFlag, QString> getAllModeDescriptions() const;

signals:
    void modeChanged(ModeFlags newFlags);
    void fallbackPolicyChanged(bool allowFallback);
    void callStatusChanged(bool inProgress);

private:
    // Current configuration
    ModeFlags m_modeFlags{MODE_NONE};
    QString m_primaryModelName{"gpt-4"};
    QString m_fallbackModelName{"gpt-3.5-turbo"};
    bool m_allowFallback{true};
    bool m_callInProgress{false};

    // Mode descriptions
    QMap<ModeFlag, QString> m_modeDescriptions;
    void initializeModeDescriptions();
};

Q_DECLARE_OPERATORS_FOR_FLAGS(ModelRouter::ModeFlags)
