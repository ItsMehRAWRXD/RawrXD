// RawrXD Agentic IDE - Transparency Control Panel
// Advanced transparency controls with fade animations
#pragma once

#include <QWidget>
#include <QTimer>
#include <QPushButton>
#include <QSlider>
#include <QLabel>
#include <QCheckBox>
#include <QGroupBox>

namespace RawrXD {

/**
 * @brief TransparencyControlPanel - Advanced transparency controls
 * 
 * Features:
 * - Quick opacity presets (Opaque, Semi-Transparent, Glass, Ghost)
 * - Smooth fade animations (fade in/out)
 * - Always-on-top and click-through controls
 * - Real-time preview of transparency settings
 */
class TransparencyControlPanel : public QWidget {
    Q_OBJECT
    
public:
    explicit TransparencyControlPanel(QWidget* parent = nullptr);
    
signals:
    void opacityChanged(const QString& element, double opacity);
    void transparencyToggled(bool enabled);
    void alwaysOnTopToggled(bool enabled);
    void clickThroughToggled(bool enabled);
    
private slots:
    void onWindowOpacityChanged(int value);
    void onDockOpacityChanged(int value);
    void onChatOpacityChanged(int value);
    void onEditorOpacityChanged(int value);
    
    void onTransparencyToggled(bool checked);
    void onAlwaysOnTopToggled(bool checked);
    void onClickThroughToggled(bool checked);
    
    void onQuickPresetClicked();
    void onAdvancedSettingsClicked();
    
    void fadeWindowIn();
    void fadeWindowOut();
    void updateFadeAnimation();
    
private:
    void setupUI();
    void createOpacityControls();
    void createQuickPresets();
    void createAdvancedControls();
    void connectSignals();
    void updateOpacityLabels();
    
    // Opacity Controls
    QSlider* m_windowOpacitySlider;
    QSlider* m_dockOpacitySlider;
    QSlider* m_chatOpacitySlider;
    QSlider* m_editorOpacitySlider;
    
    QLabel* m_windowOpacityLabel;
    QLabel* m_dockOpacityLabel;
    QLabel* m_chatOpacityLabel;
    QLabel* m_editorOpacityLabel;
    
    // Quick Presets
    QPushButton* m_opaquePreset;
    QPushButton* m_semiTransparentPreset;
    QPushButton* m_glassPreset;
    QPushButton* m_ghostPreset;
    
    // Advanced Controls
    QCheckBox* m_transparencyEnabled;
    QCheckBox* m_alwaysOnTop;
    QCheckBox* m_clickThroughEnabled;
    QPushButton* m_fadeInButton;
    QPushButton* m_fadeOutButton;
    QPushButton* m_advancedSettingsButton;
    
    // Fade Animation
    QTimer* m_fadeTimer;
    double m_currentOpacity;
    double m_targetOpacity;
    double m_fadeStep;
    
    // State
    bool m_fadingIn;
    bool m_fadingOut;
};

} // namespace RawrXD
