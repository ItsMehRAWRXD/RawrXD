// RawrXD Agentic IDE - Transparency Control Panel Implementation
// Advanced transparency controls with smooth animations
#include "TransparencyControlPanel.h"
#include "ThemeManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QSlider>
#include <QPushButton>
#include <QCheckBox>
#include <QMessageBox>
#include <QDebug>
#include <chrono>

namespace RawrXD {

TransparencyControlPanel::TransparencyControlPanel(QWidget* parent)
    : QWidget(parent)
    , m_fadeTimer(new QTimer(this))
    , m_currentOpacity(1.0)
    , m_targetOpacity(1.0)
    , m_fadeStep(0.02)
    , m_fadingIn(false)
    , m_fadingOut(false) {
    
    qDebug() << "[TransparencyControlPanel] Initializing...";
    auto startTime = std::chrono::steady_clock::now();
    
    setupUI();
    connectSignals();
    
    // Setup fade timer for smooth animations
    m_fadeTimer->setInterval(16); // ~60 FPS
    connect(m_fadeTimer, &QTimer::timeout, this, &TransparencyControlPanel::updateFadeAnimation);
    
    // Load current settings
    updateOpacityLabels();
    
    auto endTime = std::chrono::steady_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    qDebug() << "[TransparencyControlPanel] Initialized in" << durationMs << "ms";
}

void TransparencyControlPanel::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(8);
    mainLayout->setContentsMargins(8, 8, 8, 8);
    
    // Opacity Controls Section
    QGroupBox* opacityGroup = new QGroupBox("Element Opacity");
    QGridLayout* opacityLayout = new QGridLayout(opacityGroup);
    opacityLayout->setSpacing(6);
    
    // Window Opacity
    opacityLayout->addWidget(new QLabel("Window:"), 0, 0);
    m_windowOpacitySlider = new QSlider(Qt::Horizontal);
    m_windowOpacitySlider->setRange(10, 100);
    m_windowOpacitySlider->setValue(100);
    m_windowOpacitySlider->setTickPosition(QSlider::TicksBelow);
    m_windowOpacitySlider->setTickInterval(10);
    opacityLayout->addWidget(m_windowOpacitySlider, 0, 1);
    m_windowOpacityLabel = new QLabel("100%");
    m_windowOpacityLabel->setMinimumWidth(40);
    opacityLayout->addWidget(m_windowOpacityLabel, 0, 2);
    
    // Dock Opacity
    opacityLayout->addWidget(new QLabel("Docks:"), 1, 0);
    m_dockOpacitySlider = new QSlider(Qt::Horizontal);
    m_dockOpacitySlider->setRange(10, 100);
    m_dockOpacitySlider->setValue(100);
    m_dockOpacitySlider->setTickPosition(QSlider::TicksBelow);
    m_dockOpacitySlider->setTickInterval(10);
    opacityLayout->addWidget(m_dockOpacitySlider, 1, 1);
    m_dockOpacityLabel = new QLabel("100%");
    m_dockOpacityLabel->setMinimumWidth(40);
    opacityLayout->addWidget(m_dockOpacityLabel, 1, 2);
    
    // Chat Opacity
    opacityLayout->addWidget(new QLabel("Chat:"), 2, 0);
    m_chatOpacitySlider = new QSlider(Qt::Horizontal);
    m_chatOpacitySlider->setRange(10, 100);
    m_chatOpacitySlider->setValue(100);
    m_chatOpacitySlider->setTickPosition(QSlider::TicksBelow);
    m_chatOpacitySlider->setTickInterval(10);
    opacityLayout->addWidget(m_chatOpacitySlider, 2, 1);
    m_chatOpacityLabel = new QLabel("100%");
    m_chatOpacityLabel->setMinimumWidth(40);
    opacityLayout->addWidget(m_chatOpacityLabel, 2, 2);
    
    // Editor Opacity
    opacityLayout->addWidget(new QLabel("Editor:"), 3, 0);
    m_editorOpacitySlider = new QSlider(Qt::Horizontal);
    m_editorOpacitySlider->setRange(10, 100);
    m_editorOpacitySlider->setValue(100);
    m_editorOpacitySlider->setTickPosition(QSlider::TicksBelow);
    m_editorOpacitySlider->setTickInterval(10);
    opacityLayout->addWidget(m_editorOpacitySlider, 3, 1);
    m_editorOpacityLabel = new QLabel("100%");
    m_editorOpacityLabel->setMinimumWidth(40);
    opacityLayout->addWidget(m_editorOpacityLabel, 3, 2);
    
    mainLayout->addWidget(opacityGroup);
    
    // Quick Presets Section
    QGroupBox* presetsGroup = new QGroupBox("Quick Presets");
    QHBoxLayout* presetsLayout = new QHBoxLayout(presetsGroup);
    presetsLayout->setSpacing(4);
    
    m_opaquePreset = new QPushButton("Opaque");
    m_opaquePreset->setToolTip("Set all elements to 100% opacity");
    presetsLayout->addWidget(m_opaquePreset);
    
    m_semiTransparentPreset = new QPushButton("Semi-Transparent");
    m_semiTransparentPreset->setToolTip("Set moderate transparency for all elements");
    presetsLayout->addWidget(m_semiTransparentPreset);
    
    m_glassPreset = new QPushButton("Glass");
    m_glassPreset->setToolTip("Set glass-like transparency (recommended)");
    presetsLayout->addWidget(m_glassPreset);
    
    m_ghostPreset = new QPushButton("Ghost");
    m_ghostPreset->setToolTip("Set high transparency for minimal distraction");
    presetsLayout->addWidget(m_ghostPreset);
    
    mainLayout->addWidget(presetsGroup);
    
    // Advanced Controls Section
    QGroupBox* advancedGroup = new QGroupBox("Advanced Controls");
    QVBoxLayout* advancedLayout = new QVBoxLayout(advancedGroup);
    
    // Transparency Toggle
    m_transparencyEnabled = new QCheckBox("Enable Window Transparency");
    m_transparencyEnabled->setToolTip("Apply opacity settings to the actual window");
    m_transparencyEnabled->setChecked(false);
    advancedLayout->addWidget(m_transparencyEnabled);
    
    // Always on Top
    m_alwaysOnTop = new QCheckBox("Always on Top");
    m_alwaysOnTop->setToolTip("Keep the IDE window above all other windows");
    m_alwaysOnTop->setChecked(false);
    advancedLayout->addWidget(m_alwaysOnTop);
    
    // Click-through (experimental)
    m_clickThroughEnabled = new QCheckBox("Enable Click-Through (Experimental)");
    m_clickThroughEnabled->setToolTip("Allow mouse clicks to pass through transparent areas");
    m_clickThroughEnabled->setChecked(false);
    m_clickThroughEnabled->setEnabled(false); // Platform-specific
    advancedLayout->addWidget(m_clickThroughEnabled);
    
    // Fade Controls
    QHBoxLayout* fadeLayout = new QHBoxLayout();
    m_fadeInButton = new QPushButton("Fade In");
    m_fadeInButton->setToolTip("Smoothly fade the window to full opacity");
    fadeLayout->addWidget(m_fadeInButton);
    
    m_fadeOutButton = new QPushButton("Fade Out");
    m_fadeOutButton->setToolTip("Smoothly fade the window to partial transparency");
    fadeLayout->addWidget(m_fadeOutButton);
    
    advancedLayout->addLayout(fadeLayout);
    
    // Advanced Settings Button
    m_advancedSettingsButton = new QPushButton("Advanced Settings...");
    m_advancedSettingsButton->setToolTip("Open full theme configuration panel");
    advancedLayout->addWidget(m_advancedSettingsButton);
    
    // Warning Label
    QLabel* warningLabel = new QLabel(
        "⚠️ Transparency effects may impact performance on some systems.\n"
        "Use lower opacity values for better performance.");
    warningLabel->setStyleSheet("color: #ff9800; font-size: 11px;");
    warningLabel->setWordWrap(true);
    advancedLayout->addWidget(warningLabel);
    
    mainLayout->addWidget(advancedGroup);
    mainLayout->addStretch();
}

void TransparencyControlPanel::connectSignals() {
    // Opacity sliders
    connect(m_windowOpacitySlider, &QSlider::valueChanged,
            this, &TransparencyControlPanel::onWindowOpacityChanged);
    connect(m_dockOpacitySlider, &QSlider::valueChanged,
            this, &TransparencyControlPanel::onDockOpacityChanged);
    connect(m_chatOpacitySlider, &QSlider::valueChanged,
            this, &TransparencyControlPanel::onChatOpacityChanged);
    connect(m_editorOpacitySlider, &QSlider::valueChanged,
            this, &TransparencyControlPanel::onEditorOpacityChanged);
    
    // Quick presets
    connect(m_opaquePreset, &QPushButton::clicked, [this]() {
        qDebug() << "[TransparencyControlPanel] Applying Opaque preset";
        m_windowOpacitySlider->setValue(100);
        m_dockOpacitySlider->setValue(100);
        m_chatOpacitySlider->setValue(100);
        m_editorOpacitySlider->setValue(100);
    });
    
    connect(m_semiTransparentPreset, &QPushButton::clicked, [this]() {
        qDebug() << "[TransparencyControlPanel] Applying Semi-Transparent preset";
        m_windowOpacitySlider->setValue(90);
        m_dockOpacitySlider->setValue(85);
        m_chatOpacitySlider->setValue(92);
        m_editorOpacitySlider->setValue(88);
    });
    
    connect(m_glassPreset, &QPushButton::clicked, [this]() {
        qDebug() << "[TransparencyControlPanel] Applying Glass preset";
        m_windowOpacitySlider->setValue(95);
        m_dockOpacitySlider->setValue(90);
        m_chatOpacitySlider->setValue(92);
        m_editorOpacitySlider->setValue(88);
    });
    
    connect(m_ghostPreset, &QPushButton::clicked, [this]() {
        qDebug() << "[TransparencyControlPanel] Applying Ghost preset";
        m_windowOpacitySlider->setValue(70);
        m_dockOpacitySlider->setValue(60);
        m_chatOpacitySlider->setValue(75);
        m_editorOpacitySlider->setValue(65);
    });
    
    // Transparency toggles
    connect(m_transparencyEnabled, &QCheckBox::toggled,
            this, &TransparencyControlPanel::onTransparencyToggled);
    connect(m_alwaysOnTop, &QCheckBox::toggled,
            this, &TransparencyControlPanel::onAlwaysOnTopToggled);
    connect(m_clickThroughEnabled, &QCheckBox::toggled,
            this, &TransparencyControlPanel::onClickThroughToggled);
    
    // Fade controls
    connect(m_fadeInButton, &QPushButton::clicked,
            this, &TransparencyControlPanel::fadeWindowIn);
    connect(m_fadeOutButton, &QPushButton::clicked,
            this, &TransparencyControlPanel::fadeWindowOut);
    
    // Advanced settings
    connect(m_advancedSettingsButton, &QPushButton::clicked,
            this, &TransparencyControlPanel::onAdvancedSettingsClicked);
}

void TransparencyControlPanel::updateOpacityLabels() {
    const auto& colors = ThemeManager::instance().currentColors();
    
    m_windowOpacitySlider->blockSignals(true);
    m_dockOpacitySlider->blockSignals(true);
    m_chatOpacitySlider->blockSignals(true);
    m_editorOpacitySlider->blockSignals(true);
    
    m_windowOpacitySlider->setValue(static_cast<int>(colors.windowOpacity * 100));
    m_dockOpacitySlider->setValue(static_cast<int>(colors.dockOpacity * 100));
    m_chatOpacitySlider->setValue(static_cast<int>(colors.chatOpacity * 100));
    m_editorOpacitySlider->setValue(static_cast<int>(colors.editorOpacity * 100));
    
    m_windowOpacitySlider->blockSignals(false);
    m_dockOpacitySlider->blockSignals(false);
    m_chatOpacitySlider->blockSignals(false);
    m_editorOpacitySlider->blockSignals(false);
    
    m_windowOpacityLabel->setText(QString("%1%").arg(m_windowOpacitySlider->value()));
    m_dockOpacityLabel->setText(QString("%1%").arg(m_dockOpacitySlider->value()));
    m_chatOpacityLabel->setText(QString("%1%").arg(m_chatOpacitySlider->value()));
    m_editorOpacityLabel->setText(QString("%1%").arg(m_editorOpacitySlider->value()));
    
    // Update transparency toggle
    m_transparencyEnabled->blockSignals(true);
    m_transparencyEnabled->setChecked(ThemeManager::instance().isWindowTransparencyEnabled());
    m_transparencyEnabled->blockSignals(false);
    
    m_alwaysOnTop->blockSignals(true);
    m_alwaysOnTop->setChecked(ThemeManager::instance().isAlwaysOnTop());
    m_alwaysOnTop->blockSignals(false);
    
    m_clickThroughEnabled->blockSignals(true);
    m_clickThroughEnabled->setChecked(ThemeManager::instance().isClickThroughEnabled());
    m_clickThroughEnabled->blockSignals(false);
}

void TransparencyControlPanel::onWindowOpacityChanged(int value) {
    m_windowOpacityLabel->setText(QString("%1%").arg(value));
    double opacity = value / 100.0;
    qDebug() << "[TransparencyControlPanel] Window opacity changed to" << opacity;
    emit opacityChanged("window", opacity);
}

void TransparencyControlPanel::onDockOpacityChanged(int value) {
    m_dockOpacityLabel->setText(QString("%1%").arg(value));
    double opacity = value / 100.0;
    qDebug() << "[TransparencyControlPanel] Dock opacity changed to" << opacity;
    emit opacityChanged("dock", opacity);
}

void TransparencyControlPanel::onChatOpacityChanged(int value) {
    m_chatOpacityLabel->setText(QString("%1%").arg(value));
    double opacity = value / 100.0;
    qDebug() << "[TransparencyControlPanel] Chat opacity changed to" << opacity;
    emit opacityChanged("chat", opacity);
}

void TransparencyControlPanel::onEditorOpacityChanged(int value) {
    m_editorOpacityLabel->setText(QString("%1%").arg(value));
    double opacity = value / 100.0;
    qDebug() << "[TransparencyControlPanel] Editor opacity changed to" << opacity;
    emit opacityChanged("editor", opacity);
}

void TransparencyControlPanel::onTransparencyToggled(bool checked) {
    qDebug() << "[TransparencyControlPanel] Transparency toggled:" << checked;
    emit transparencyToggled(checked);
}

void TransparencyControlPanel::onAlwaysOnTopToggled(bool checked) {
    qDebug() << "[TransparencyControlPanel] Always on top toggled:" << checked;
    emit alwaysOnTopToggled(checked);
}

void TransparencyControlPanel::onClickThroughToggled(bool checked) {
    qDebug() << "[TransparencyControlPanel] Click-through toggled:" << checked;
    emit clickThroughToggled(checked);
}

void TransparencyControlPanel::onQuickPresetClicked() {
    // Handled in lambda connections above
}

void TransparencyControlPanel::onAdvancedSettingsClicked() {
    QMessageBox::information(this, "Advanced Settings",
        "Advanced transparency settings are available in the full Theme Configuration panel.\n\n"
        "Features include:\n"
        "• Complete color customization\n"
        "• Per-element opacity controls\n"
        "• Theme import/export\n"
        "• Real-time preview\n\n"
        "Open the Theme Configuration panel from the View menu for full control.");
}

void TransparencyControlPanel::fadeWindowIn() {
    qDebug() << "[TransparencyControlPanel] Starting fade in animation";
    
    if (m_fadingOut) {
        m_fadingOut = false;
        m_fadeTimer->stop();
    }
    
    m_fadingIn = true;
    m_targetOpacity = 1.0;
    m_fadeStep = 0.02;
    m_fadeTimer->start();
}

void TransparencyControlPanel::fadeWindowOut() {
    qDebug() << "[TransparencyControlPanel] Starting fade out animation";
    
    if (m_fadingIn) {
        m_fadingIn = false;
        m_fadeTimer->stop();
    }
    
    m_fadingOut = true;
    m_targetOpacity = 0.3;
    m_fadeStep = -0.02;
    m_fadeTimer->start();
}

void TransparencyControlPanel::updateFadeAnimation() {
    if (!m_fadingIn && !m_fadingOut) return;
    
    m_currentOpacity += m_fadeStep;
    
    // Clamp opacity to valid range
    if (m_fadingIn && m_currentOpacity >= m_targetOpacity) {
        m_currentOpacity = m_targetOpacity;
        m_fadingIn = false;
        m_fadeTimer->stop();
        qDebug() << "[TransparencyControlPanel] Fade in complete";
    } else if (m_fadingOut && m_currentOpacity <= m_targetOpacity) {
        m_currentOpacity = m_targetOpacity;
        m_fadingOut = false;
        m_fadeTimer->stop();
        qDebug() << "[TransparencyControlPanel] Fade out complete";
    }
    
    // Apply opacity to window
    m_windowOpacitySlider->blockSignals(true);
    m_windowOpacitySlider->setValue(static_cast<int>(m_currentOpacity * 100));
    m_windowOpacitySlider->blockSignals(false);
    
    m_windowOpacityLabel->setText(QString("%1%").arg(m_windowOpacitySlider->value()));
    
    // Emit signal to update actual window opacity
    emit opacityChanged("window", m_currentOpacity);
}

} // namespace RawrXD
