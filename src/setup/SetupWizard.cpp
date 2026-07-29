/**
 * @file SetupWizard.cpp
<<<<<<< HEAD
 * @brief RawrXD IDE Setup Wizard — Win32/C++20 only (Qt-free).
 *
 * Pure Win32 + BCrypt + STL. Uses WizardPageBase; UI can be driven by
 * Win32 dialogs or headless config write.
 *
=======
 * @brief RawrXD IDE Setup Wizard Implementation
 * 
 * Full production implementation of the graphical setup wizard
 * with hardware detection, thermal configuration, and security setup.
 * 
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
 * @copyright RawrXD IDE 2026
 */

#include "SetupWizard.hpp"

#ifdef _WIN32
#include <windows.h>
<<<<<<< HEAD
#include <shellapi.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <intrin.h>
#pragma comment(lib, "bcrypt.lib")
#endif
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <thread>

// SetupWizard void* parent doc — Phase 33 implementation complete


// Entropy key path AppData/RawrXD — Phase 33 implementation complete


// SetupWizard importKey/exportKey — Phase 33 implementation complete


namespace rawrxd::setup {

static constexpr int WizardAccepted = 1;
static constexpr int WizardRejected = 0;

// ═══════════════════════════════════════════════════════════════════════════════
// IntroPage
// ═══════════════════════════════════════════════════════════════════════════════

IntroPage::IntroPage(void*)
{
    setTitle("Welcome to RawrXD IDE");
    setSubTitle("Setup Wizard v2.0.0");
=======
#include <intrin.h>
#endif

namespace rawrxd::setup {

// ═══════════════════════════════════════════════════════════════════════════════
// IntroPage Implementation
// ═══════════════════════════════════════════════════════════════════════════════

IntroPage::IntroPage(void* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Welcome to RawrXD IDE"));
    setSubTitle(tr("Setup Wizard v2.0.0"));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    setupUI();
}

void IntroPage::setupUI()
{
<<<<<<< HEAD
    // Win32: no widgets; use dialog resources or headless.
}

void IntroPage::initializePage() {}

bool IntroPage::isComplete() const
{
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HardwarePage
// ═══════════════════════════════════════════════════════════════════════════════

HardwarePage::HardwarePage(void*)
    : WizardPageBase()
    , m_detector(std::make_unique<HardwareDetector>())
{
    setTitle("Hardware Detection");
    setSubTitle("Detecting your system hardware configuration");
=======
    auto* layout = new void(this);
    layout->setSpacing(20);
    
    // Welcome banner
    m_welcomeLabel = new void(this);
    m_welcomeLabel->setText(tr(
        "<h2>🔥 Welcome to the RawrXD IDE Setup Wizard</h2>"
        "<p>This wizard will guide you through the configuration of your "
        "Sovereign Hardware Orchestration system.</p>"
    ));
    m_welcomeLabel->setWordWrap(true);
    m_welcomeLabel->setTextFormat(RichText);
    layout->addWidget(m_welcomeLabel);
    
    // Feature list
    m_descriptionLabel = new void(this);
    m_descriptionLabel->setText(tr(
        "<h3>What will be configured:</h3>"
        "<ul>"
        "<li><b>Hardware Detection</b> - Identify CPU, NVMe drives, GPU, and memory</li>"
        "<li><b>Thermal Management</b> - Configure predictive throttling and load balancing</li>"
        "<li><b>Security Binding</b> - Generate hardware entropy keys for authentication</li>"
        "<li><b>Performance Tuning</b> - Optimize for your specific hardware configuration</li>"
        "</ul>"
        "<h3>Requirements:</h3>"
        "<ul>"
        "<li>Windows 10/11 x64</li>"
        "<li>Administrator privileges (for hardware detection)</li>"
        "<li>At least one SSD/NVMe drive</li>"
        "</ul>"
    ));
    m_descriptionLabel->setWordWrap(true);
    m_descriptionLabel->setTextFormat(RichText);
    layout->addWidget(m_descriptionLabel);
    
    layout->addStretch();
    
    // Terms acceptance
    m_acceptTermsCheck = new void(tr("I understand that this wizard will configure hardware-level settings"), this);
    layout->addWidget(m_acceptTermsCheck);
    
    registerField("acceptTerms", m_acceptTermsCheck);  // Signal connection removed\n}

void IntroPage::initializePage()
{
    // Reset checkbox on page show
}

bool IntroPage::isComplete() const
{
    return m_acceptTermsCheck->isChecked();
}

// ═══════════════════════════════════════════════════════════════════════════════
// HardwarePage Implementation
// ═══════════════════════════════════════════════════════════════════════════════

HardwarePage::HardwarePage(void* parent)
    : QWizardPage(parent)
    , m_detector(std::make_unique<HardwareDetector>())
{
    setTitle(tr("Hardware Detection"));
    setSubTitle(tr("Detecting your system hardware configuration"));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    setupUI();
}

HardwarePage::~HardwarePage() = default;

<<<<<<< HEAD
void HardwarePage::setupUI() {}

void HardwarePage::initializePage()
{
    if (!m_detectionComplete)
        startDetection();
=======
void HardwarePage::setupUI()
{
    auto* mainLayout = new void(this);
    
    // Status section
    auto* statusLayout = new void();
    m_statusLabel = new void(tr("Click 'Detect Hardware' to begin..."), this);
    m_detectButton = new void(tr("Detect Hardware"), this);
    m_refreshButton = new void(tr("Refresh"), this);
    m_refreshButton->setEnabled(false);
    
    statusLayout->addWidget(m_statusLabel, 1);
    statusLayout->addWidget(m_detectButton);
    statusLayout->addWidget(m_refreshButton);
    mainLayout->addLayout(statusLayout);
    
    // Progress bar
    m_progressBar = new void(this);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setVisible(false);
    mainLayout->addWidget(m_progressBar);
    
    // Hardware groups in a grid
    auto* gridLayout = new void();
    
    // CPU Group
    m_cpuGroup = new void(tr("🖥️ Processor"), this);
    auto* cpuLayout = new void(m_cpuGroup);
    cpuLayout->addWidget(new void(tr("Waiting for detection..."), m_cpuGroup));
    gridLayout->addWidget(m_cpuGroup, 0, 0);
    
    // Storage Group
    m_storageGroup = new void(tr("💾 Storage"), this);
    auto* storageLayout = new void(m_storageGroup);
    storageLayout->addWidget(new void(tr("Waiting for detection..."), m_storageGroup));
    gridLayout->addWidget(m_storageGroup, 0, 1);
    
    // GPU Group
    m_gpuGroup = new void(tr("🎮 Graphics"), this);
    auto* gpuLayout = new void(m_gpuGroup);
    gpuLayout->addWidget(new void(tr("Waiting for detection..."), m_gpuGroup));
    gridLayout->addWidget(m_gpuGroup, 1, 0);
    
    // Memory Group
    m_memoryGroup = new void(tr("🧠 Memory"), this);
    auto* memLayout = new void(m_memoryGroup);
    memLayout->addWidget(new void(tr("Waiting for detection..."), m_memoryGroup));
    gridLayout->addWidget(m_memoryGroup, 1, 1);
    
    mainLayout->addLayout(gridLayout);
    
    // Hardware list for detailed view
    m_hardwareList = nullptr;
    m_hardwareList->setMaximumHeight(100);
    mainLayout->addWidget(m_hardwareList);
    
    // Connect signals  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n}

void HardwarePage::initializePage()
{
    if (!m_detectionComplete) {
        // Auto-start detection on first visit
        // Timer operation removed
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool HardwarePage::isComplete() const
{
    return m_detectionComplete && !m_hardware.drives.empty();
}

bool HardwarePage::validatePage()
{
<<<<<<< HEAD
    return !m_hardware.drives.empty();
=======
    if (m_hardware.drives.empty()) {
        void::warning(this, tr("No Drives Detected"),
            tr("At least one storage drive must be detected to continue."));
        return false;
    }
    return true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void HardwarePage::startDetection()
{
<<<<<<< HEAD
    m_detectionComplete = false;
    if (m_detector) {
        m_detector->on_progress = [this](int pct, const std::string& s) { onDetectionProgress(pct, s); };
        m_detector->on_complete = [this](const DetectedHardware& h) { onDetectionComplete(h); };
        m_detector->on_error = [this](const std::string& e) { onDetectionError(e); };
        std::thread([this]() { m_detector->detect(); }).detach();
    }
}

void HardwarePage::onDetectionProgress(int, const std::string&) {}
=======
    m_detectButton->setEnabled(false);
    m_refreshButton->setEnabled(false);
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0);
    m_statusLabel->setText(tr("Starting hardware detection..."));
    m_detectionComplete = false;
    
    // Run detection in background thread
    QFuture<void> future = [](auto f){f();}([this]() {
        m_detector->detect();
    });
}

void HardwarePage::onDetectionProgress(int percent, const std::string& status)
{
    m_progressBar->setValue(percent);
    m_statusLabel->setText(status);
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

void HardwarePage::onDetectionComplete(const DetectedHardware& hardware)
{
    m_hardware = hardware;
    m_detectionComplete = true;
<<<<<<< HEAD
    hardwareDetectionComplete(true);
}

void HardwarePage::onDetectionError(const std::string&)
{
    m_detectionComplete = false;
    hardwareDetectionComplete(false);
}

void HardwarePage::hardwareDetectionComplete(bool) { /* Host can override or subscribe */ }

void HardwarePage::populateHardwareInfo() {}
void HardwarePage::runDetection() { startDetection(); }

// ═══════════════════════════════════════════════════════════════════════════════
// ThermalPage
// ═══════════════════════════════════════════════════════════════════════════════

ThermalPage::ThermalPage(void*)
{
    setTitle("Thermal Management");
    setSubTitle("Configure predictive throttling and load balancing");
=======
    m_detectButton->setEnabled(true);
    m_refreshButton->setEnabled(true);
    m_progressBar->setVisible(false);
    m_statusLabel->setText(tr("✅ Hardware detection complete!"));
    
    populateHardwareInfo();
    completeChanged();
    hardwareDetectionComplete(true);
}

void HardwarePage::onDetectionError(const std::string& error)
{
    m_detectButton->setEnabled(true);
    m_refreshButton->setEnabled(true);
    m_progressBar->setVisible(false);
    m_statusLabel->setText(tr("❌ Detection failed: %1"));
    
    void::warning(this, tr("Detection Error"), error);
}

void HardwarePage::populateHardwareInfo()
{
    // Clear and repopulate CPU group
    QLayoutItem* item;
    while ((item = m_cpuGroup->layout()->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    
    auto* cpuLabel = new void(m_cpuGroup);
    cpuLabel->setText(std::string(
        "<b>%1</b><br>"
        "Cores: %2 | Threads: %3<br>"
        "L3 Cache: %4 KB<br>"
        "RDRAND: %5 | AVX-512: %6"
    )


     );
    cpuLabel->setTextFormat(RichText);
    m_cpuGroup->layout()->addWidget(cpuLabel);
    
    // Clear and repopulate Storage group
    while ((item = m_storageGroup->layout()->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    
    std::string storageText = std::string("<b>%1 drive(s) detected:</b><br>"));
    for (const auto& drive : m_hardware.drives) {
        double sizeGB = drive.sizeBytes / (1024.0 * 1024.0 * 1024.0);
        storageText += std::string("%1: %2 (%.1f GB) %3<br>")


            ;
    }
    
    auto* storageLabel = new void(m_storageGroup);
    storageLabel->setText(storageText);
    storageLabel->setTextFormat(RichText);
    m_storageGroup->layout()->addWidget(storageLabel);
    
    // Clear and repopulate GPU group
    while ((item = m_gpuGroup->layout()->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    
    std::string gpuText;
    for (const auto& gpu : m_hardware.gpus) {
        double vramGB = gpu.vramBytes / (1024.0 * 1024.0 * 1024.0);
        gpuText += std::string("<b>%1</b><br>VRAM: %.1f GB<br>Driver: %2<br>")


            ;
    }
    
    auto* gpuLabel = new void(m_gpuGroup);
    gpuLabel->setText(gpuText);
    gpuLabel->setTextFormat(RichText);
    m_gpuGroup->layout()->addWidget(gpuLabel);
    
    // Clear and repopulate Memory group
    while ((item = m_memoryGroup->layout()->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    
    double memGB = m_hardware.memory.totalBytes / (1024.0 * 1024.0 * 1024.0);
    auto* memLabel = new void(m_memoryGroup);
    memLabel->setText(std::string(
        "<b>%.1f GB Total</b><br>"
        "Modules: %1<br>"
        "Speed: %2 MHz"
    )
     
     );
    memLabel->setTextFormat(RichText);
    m_memoryGroup->layout()->addWidget(memLabel);
    
    // Update detailed list
    m_hardwareList->clear();
    m_hardwareList->addItem(std::string("Fingerprint: %1"));
    for (const auto& drive : m_hardware.drives) {
        m_hardwareList->addItem(std::string("  Drive %1: %2 [%3]")


            );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ThermalPage Implementation
// ═══════════════════════════════════════════════════════════════════════════════

ThermalPage::ThermalPage(void* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Thermal Management"));
    setSubTitle(tr("Configure predictive throttling and load balancing"));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    setupUI();
}

void ThermalPage::setupUI()
{
<<<<<<< HEAD
    applyModeDefaults(ThermalMode::Sustainable);
=======
    auto* mainLayout = new void(this);
    
    // Mode selection
    auto* modeLayout = new void();
    modeLayout->addWidget(new void(tr("Operating Mode:"), this));
    m_modeCombo = new void(this);
    m_modeCombo->addItem(tr("🟢 Sustainable (Recommended)"), static_cast<int>(ThermalMode::Sustainable));
    m_modeCombo->addItem(tr("🟡 Hybrid"), static_cast<int>(ThermalMode::Hybrid));
    m_modeCombo->addItem(tr("🔴 Burst (Advanced)"), static_cast<int>(ThermalMode::Burst));
    modeLayout->addWidget(m_modeCombo);
    modeLayout->addStretch();
    mainLayout->addLayout(modeLayout);
    
    // Mode description
    m_modeDescription = new void(this);
    m_modeDescription->setWordWrap(true);
    m_modeDescription->setStyleSheet("void { padding: 10px; background: #f0f0f0; border-radius: 5px; }");
    mainLayout->addWidget(m_modeDescription);
    
    // Advanced settings group
    m_advancedGroup = new void(tr("⚙️ Advanced Settings"), this);
    m_advancedGroup->setCheckable(true);
    m_advancedGroup->setChecked(false);
    
    auto* advLayout = new void(m_advancedGroup);
    
    advLayout->addWidget(new void(tr("Thermal Ceiling (°C):"), m_advancedGroup), 0, 0);
    m_ceilingSpin = new void(m_advancedGroup);
    m_ceilingSpin->setRange(50.0, 85.0);
    m_ceilingSpin->setValue(59.5);
    m_ceilingSpin->setSingleStep(0.5);
    advLayout->addWidget(m_ceilingSpin, 0, 1);
    
    advLayout->addWidget(new void(tr("EWMA Alpha:"), m_advancedGroup), 1, 0);
    m_alphaSpin = new void(m_advancedGroup);
    m_alphaSpin->setRange(0.1, 0.9);
    m_alphaSpin->setValue(0.3);
    m_alphaSpin->setSingleStep(0.05);
    m_alphaSpin->setToolTip(tr("Higher = more responsive to recent changes"));
    advLayout->addWidget(m_alphaSpin, 1, 1);
    
    advLayout->addWidget(new void(tr("Prediction Horizon (ms):"), m_advancedGroup), 2, 0);
    m_horizonSpin = new void(m_advancedGroup);
    m_horizonSpin->setRange(1000, 30000);
    m_horizonSpin->setValue(5000);
    m_horizonSpin->setSingleStep(500);
    advLayout->addWidget(m_horizonSpin, 2, 1);
    
    m_predictiveCheck = new void(tr("Enable Predictive Throttling"), m_advancedGroup);
    m_predictiveCheck->setChecked(true);
    advLayout->addWidget(m_predictiveCheck, 3, 0, 1, 2);
    
    m_loadBalanceCheck = new void(tr("Enable Dynamic Load Balancing"), m_advancedGroup);
    m_loadBalanceCheck->setChecked(true);
    advLayout->addWidget(m_loadBalanceCheck, 4, 0, 1, 2);
    
    mainLayout->addWidget(m_advancedGroup);
    
    // Preview
    auto* previewGroup = new void(tr("📊 Configuration Preview"), this);
    auto* previewLayout = new void(previewGroup);
    m_previewText = new void(previewGroup);
    m_previewText->setReadOnly(true);
    m_previewText->setMaximumHeight(120);
    previewLayout->addWidget(m_previewText);
    mainLayout->addWidget(previewGroup);
    
    // Connections  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n// Initialize
    onModeChanged(0);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void ThermalPage::initializePage()
{
    updatePreview();
}

bool ThermalPage::validatePage()
{
<<<<<<< HEAD
=======
    // Save config
    m_config.defaultMode = static_cast<ThermalMode>(m_modeCombo->currentData());
    
    if (m_advancedGroup->isChecked()) {
        switch (m_config.defaultMode) {
            case ThermalMode::Sustainable:
                m_config.sustainableCeiling = m_ceilingSpin->value();
                break;
            case ThermalMode::Hybrid:
                m_config.hybridCeiling = m_ceilingSpin->value();
                break;
            case ThermalMode::Burst:
                m_config.burstCeiling = m_ceilingSpin->value();
                break;
        }
        m_config.ewmaAlpha = m_alphaSpin->value();
        m_config.predictionHorizonMs = m_horizonSpin->value();
    }
    
    m_config.enablePredictive = m_predictiveCheck->isChecked();
    m_config.enableLoadBalancing = m_loadBalanceCheck->isChecked();
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

void ThermalPage::onModeChanged(int index)
{
<<<<<<< HEAD
    applyModeDefaults(static_cast<ThermalMode>(index));
    updatePreview();
}

void ThermalPage::onAdvancedToggled(bool)
{
    updatePreview();
}

void ThermalPage::updatePreview() {}

void ThermalPage::applyModeDefaults(ThermalMode mode)
{
    switch (mode) {
    case ThermalMode::Sustainable:
        m_config.sustainableCeiling = 59.5;
        break;
    case ThermalMode::Hybrid:
        m_config.hybridCeiling = 65.0;
        break;
    case ThermalMode::Burst:
        m_config.burstCeiling = 75.0;
        break;
    }
    m_config.defaultMode = mode;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SecurityPage
// ═══════════════════════════════════════════════════════════════════════════════

SecurityPage::SecurityPage(void*)
{
    setTitle("Security Configuration");
    setSubTitle("Configure hardware binding and session authentication");
    setupUI();
}

void SecurityPage::setupUI() {}

void SecurityPage::initializePage()
{
    if (m_entropyKey.empty())
        generateKey();
=======
    ThermalMode mode = static_cast<ThermalMode>(m_modeCombo->itemData(index));
    applyModeDefaults(mode);
    
    std::string description;
    switch (mode) {
        case ThermalMode::Sustainable:
            description = tr(
                "<b>Sustainable Mode</b><br>"
                "• Thermal ceiling: 59.5°C<br>"
                "• Duration: Unlimited<br>"
                "• Latency tax: +12 μs<br>"
                "• <i>Recommended for 24/7 operation and maximum silicon longevity</i>"
            );
            break;
        case ThermalMode::Hybrid:
            description = tr(
                "<b>Hybrid Mode</b><br>"
                "• Thermal ceiling: 65°C<br>"
                "• Burst duration: 5-10 minutes<br>"
                "• Latency tax: +5 μs<br>"
                "• <i>Balanced performance and longevity</i>"
            );
            break;
        case ThermalMode::Burst:
            description = tr(
                "<b>Burst Mode</b><br>"
                "• Thermal ceiling: 75°C<br>"
                "• Max duration: 60 seconds<br>"
                "• Cooldown: 5 minutes<br>"
                "• <i>⚠️ Maximum performance - use sparingly!</i>"
            );
            break;
    }
    m_modeDescription->setText(description);
    updatePreview();
}

void ThermalPage::onAdvancedToggled(bool checked)
{
    if (!checked) {
        // Reset to mode defaults
        ThermalMode mode = static_cast<ThermalMode>(m_modeCombo->currentData());
        applyModeDefaults(mode);
    }
    updatePreview();
}

void ThermalPage::applyModeDefaults(ThermalMode mode)
{
    switch (mode) {
        case ThermalMode::Sustainable:
            m_ceilingSpin->setValue(59.5);
            break;
        case ThermalMode::Hybrid:
            m_ceilingSpin->setValue(65.0);
            break;
        case ThermalMode::Burst:
            m_ceilingSpin->setValue(75.0);
            break;
    }
    m_alphaSpin->setValue(0.3);
    m_horizonSpin->setValue(5000);
}

void ThermalPage::updatePreview()
{
    std::string preview = std::string(
        "Thermal Configuration:\n"
        "  Mode: %1\n"
        "  Ceiling: %.1f°C\n"
        "  EWMA Alpha: %.2f\n"
        "  Prediction Horizon: %2 ms\n"
        "  Predictive Throttling: %3\n"
        "  Load Balancing: %4"
    ))
     )
     )
     )
      ? "Enabled" : "Disabled")
      ? "Enabled" : "Disabled");
    
    m_previewText->setPlainText(preview);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SecurityPage Implementation
// ═══════════════════════════════════════════════════════════════════════════════

SecurityPage::SecurityPage(void* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Security Configuration"));
    setSubTitle(tr("Configure hardware binding and session authentication"));
    setupUI();
}

void SecurityPage::setupUI()
{
    auto* mainLayout = new void(this);
    
    // Entropy key section
    auto* keyGroup = new void(tr("🔐 Hardware Entropy Key"), this);
    auto* keyLayout = new void(keyGroup);
    
    m_keyLabel = new void(tr("Session Key:"), keyGroup);
    keyLayout->addWidget(m_keyLabel, 0, 0);
    
    m_keyDisplay = new voidEdit(keyGroup);
    m_keyDisplay->setReadOnly(true);
    m_keyDisplay->setFont(void("Consolas", 10));
    m_keyDisplay->setPlaceholderText(tr("Click 'Generate' to create a new key"));
    keyLayout->addWidget(m_keyDisplay, 0, 1);
    
    auto* buttonLayout = new void();
    m_generateButton = new void(tr("🎲 Generate"), keyGroup);
    m_importButton = new void(tr("📥 Import"), keyGroup);
    m_exportButton = new void(tr("📤 Export"), keyGroup);
    m_exportButton->setEnabled(false);
    buttonLayout->addWidget(m_generateButton);
    buttonLayout->addWidget(m_importButton);
    buttonLayout->addWidget(m_exportButton);
    keyLayout->addLayout(buttonLayout, 1, 0, 1, 2);
    
    mainLayout->addWidget(keyGroup);
    
    // Binding options
    auto* bindingGroup = new void(tr("🔒 Security Options"), this);
    auto* bindingLayout = new void(bindingGroup);
    
    m_hardwareBindingCheck = new void(tr("Enable Hardware Binding (recommended)"), bindingGroup);
    m_hardwareBindingCheck->setChecked(true);
    m_hardwareBindingCheck->setToolTip(tr("Bind configuration to this specific hardware"));
    bindingLayout->addWidget(m_hardwareBindingCheck);
    
    m_sessionAuthCheck = new void(tr("Enable Session Authentication"), bindingGroup);
    m_sessionAuthCheck->setChecked(true);
    m_sessionAuthCheck->setToolTip(tr("Require entropy key for MASM kernel communication"));
    bindingLayout->addWidget(m_sessionAuthCheck);
    
    mainLayout->addWidget(bindingGroup);
    
    // Security level indicator
    auto* levelGroup = new void(tr("🛡️ Security Level"), this);
    auto* levelLayout = new void(levelGroup);
    m_securityLevel = new void(levelGroup);
    m_securityLevel->setAlignment(AlignCenter);
    m_securityLevel->setStyleSheet("void { font-size: 14pt; padding: 10px; }");
    levelLayout->addWidget(m_securityLevel);
    mainLayout->addWidget(levelGroup);
    
    mainLayout->addStretch();
    
    // Connections  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\n  // Signal connection removed\nupdateSecurityLevel();
}

void SecurityPage::initializePage()
{
    // Auto-generate key if not already set
    if (m_entropyKey.empty()) {
        generateKey();
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool SecurityPage::validatePage()
{
<<<<<<< HEAD
    return !m_entropyKey.empty();
=======
    if (m_entropyKey.empty()) {
        void::warning(this, tr("No Key Generated"),
            tr("Please generate or import an entropy key before continuing."));
        return false;
    }
    
    m_hardwareBinding = m_hardwareBindingCheck->isChecked();
    return true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void SecurityPage::generateKey()
{
    m_entropyKey = generateRDRANDKey();
<<<<<<< HEAD
=======
    m_keyDisplay->setText(m_entropyKey);
    m_exportButton->setEnabled(true);
    updateSecurityLevel();
    completeChanged();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void SecurityPage::importKey()
{
<<<<<<< HEAD
    namespace fs = std::filesystem;
    std::string path;
    const char* envPath = std::getenv("RAWRXD_ENTROPY_KEY_FILE");
    if (envPath && envPath[0]) {
        path = envPath;
    } else {
#ifdef _WIN32
        char appData[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData)))
            path = std::string(appData) + "\\RawrXD\\entropy.key";
        else
            path = ".\\rawrxd_entropy.key";
#else
        const char* home = std::getenv("HOME");
        path = (home ? home : ".") + std::string("/.rawrxd/entropy.key");
#endif
    }
    std::ifstream f(path);
    if (!f.is_open()) return;
    std::string line;
    if (std::getline(f, line)) {
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return;
        line.erase(0, start);
        size_t end = line.find_last_not_of(" \t\r\n");
        if (end != std::string::npos) line.erase(end + 1);
        if (line.size() >= 32 && line.size() <= 128 &&
            std::all_of(line.begin(), line.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
            })) {
            m_entropyKey = line;
        }
=======
    std::string fileName = // Dialog::getOpenFileName(this,
        tr("Import Entropy Key"), std::string(), tr("Key Files (*.key);;All Files (*)"));
    
    if (fileName.empty()) return;
    
    // File operation removed;
    if (file.open(std::iostream::ReadOnly | std::iostream::Text)) {
        m_entropyKey = std::string::fromUtf8(file.readAll()).trimmed();
        m_keyDisplay->setText(m_entropyKey);
        m_exportButton->setEnabled(true);
        updateSecurityLevel();
        completeChanged();
    } else {
        void::warning(this, tr("Import Failed"),
            tr("Could not read key file: %1")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

void SecurityPage::exportKey()
{
<<<<<<< HEAD
    if (m_entropyKey.empty()) return;
    namespace fs = std::filesystem;
    std::string path;
    const char* envPath = std::getenv("RAWRXD_ENTROPY_KEY_FILE");
    if (envPath && envPath[0]) {
        path = envPath;
    } else {
#ifdef _WIN32
        char appData[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData))) {
            path = std::string(appData) + "\\RawrXD";
            fs::create_directories(path);
            path += "\\entropy.key";
        } else {
            path = ".\\rawrxd_entropy.key";
        }
#else
        const char* home = std::getenv("HOME");
        std::string dir = (home ? home : ".") + std::string("/.rawrxd");
        fs::create_directories(dir);
        path = dir + "/entropy.key";
#endif
    }
    std::ofstream f(path, std::ios::out | std::ios::trunc);
    if (f.is_open())
        f << m_entropyKey << "\n";
=======
    std::string fileName = // Dialog::getSaveFileName(this,
        tr("Export Entropy Key"), "rawrxd_entropy.key", tr("Key Files (*.key)"));
    
    if (fileName.empty()) return;
    
    // File operation removed;
    if (file.open(std::iostream::WriteOnly | std::iostream::Text)) {
        file.write(m_entropyKey.toUtf8());
        void::information(this, tr("Export Successful"),
            tr("Entropy key exported to: %1"));
    } else {
        void::warning(this, tr("Export Failed"),
            tr("Could not write key file: %1")));
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::string SecurityPage::generateRDRANDKey()
{
<<<<<<< HEAD
    std::vector<uint8_t> entropy;
    entropy.reserve(32);

#ifdef _WIN32
    unsigned int rdrandValue;
    for (int i = 0; i < 8; ++i) {
        if (_rdrand32_step(&rdrandValue)) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&rdrandValue);
            entropy.insert(entropy.end(), p, p + sizeof(rdrandValue));
        } else {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint32_t> dis;
            uint32_t v = dis(gen);
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
            entropy.insert(entropy.end(), p, p + sizeof(v));
        }
    }
#else
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    for (int i = 0; i < 4; ++i) {
        uint64_t v = dis(gen);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
        entropy.insert(entropy.end(), p, p + sizeof(v));
    }
#endif

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != 0 || !hAlg) return "";

    DWORD objLen = 0, junk = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &junk, 0);
    std::vector<uint8_t> hashObj(objLen);
    status = BCryptCreateHash(hAlg, &hHash, hashObj.data(), (ULONG)hashObj.size(), nullptr, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    BCryptHashData(hHash, entropy.data(), (ULONG)entropy.size(), 0);
    uint8_t hash[32];
    status = BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status != 0) return "";

    std::ostringstream os;
    for (int i = 0; i < 32; ++i)
        os << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    return os.str();
#else
    std::ostringstream os;
    for (size_t i = 0; i < entropy.size() && i < 32u; ++i)
        os << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (int)entropy[i];
    std::string s = os.str();
    while (s.size() < 64) s += s;
    return s.substr(0, 64);
#endif
}

void SecurityPage::updateSecurityLevel() {}

// ═══════════════════════════════════════════════════════════════════════════════
// SummaryPage
// ═══════════════════════════════════════════════════════════════════════════════

SummaryPage::SummaryPage(void*)
    : WizardPageBase()
    , m_configPath("D:\\rawrxd\\config")
{
    setTitle("Configuration Summary");
    setSubTitle("Review your settings before installation");
    setupUI();
}

void SummaryPage::setupUI() {}
=======
    // Generate 256-bit key using available entropy sources
    std::vector<uint8_t> entropy;
    
#ifdef _WIN32
    // Try RDRAND if available
    unsigned int rdrandValue;
    for (int i = 0; i < 8; ++i) {
        if (_rdrand32_step(&rdrandValue)) {
            entropy.append(reinterpret_cast<char*>(&rdrandValue), sizeof(rdrandValue));
        } else {
            // Fallback to Qt random
            uint32_t randValue = QRandomGenerator::global()->generate();
            entropy.append(reinterpret_cast<char*>(&randValue), sizeof(randValue));
        }
    }
#else
    // Use Qt random on non-Windows
    for (int i = 0; i < 8; ++i) {
        uint32_t randValue = QRandomGenerator::global()->generate();
        entropy.append(reinterpret_cast<char*>(&randValue), sizeof(randValue));
    }
#endif
    
    // Hash to get consistent format
    std::vector<uint8_t> hash = QCryptographicHash::hash(entropy, QCryptographicHash::Sha256);
    return hash.toHex().left(64).toUpper();
}

void SecurityPage::updateSecurityLevel()
{
    int level = 0;
    
    if (!m_entropyKey.empty()) level++;
    if (m_hardwareBindingCheck->isChecked()) level++;
    if (m_sessionAuthCheck->isChecked()) level++;
    
    std::string levelText;
    std::string color;
    
    switch (level) {
        case 0:
            levelText = tr("⚠️ MINIMAL");
            color = "red";
            break;
        case 1:
            levelText = tr("🟡 BASIC");
            color = "orange";
            break;
        case 2:
            levelText = tr("🟢 STANDARD");
            color = "green";
            break;
        case 3:
            levelText = tr("🛡️ SOVEREIGN");
            color = "#00aa00";
            break;
    }
    
    m_securityLevel->setText(std::string("<span style='color: %1'>%2</span>"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SummaryPage Implementation
// ═══════════════════════════════════════════════════════════════════════════════

SummaryPage::SummaryPage(void* parent)
    : QWizardPage(parent)
    , m_configPath("D:\\rawrxd\\config")
{
    setTitle(tr("Configuration Summary"));
    setSubTitle(tr("Review your settings before installation"));
    setupUI();
}

void SummaryPage::setupUI()
{
    auto* mainLayout = new void(this);
    
    // Summary text
    m_summaryText = new void(this);
    m_summaryText->setReadOnly(true);
    mainLayout->addWidget(m_summaryText);
    
    // Config path
    auto* pathLayout = new void();
    pathLayout->addWidget(new void(tr("Configuration Path:"), this));
    m_configPathLabel = new void(m_configPath, this);
    m_configPathLabel->setStyleSheet("void { font-family: Consolas; }");
    pathLayout->addWidget(m_configPathLabel, 1);
    m_changePathButton = new void(tr("Change..."), this);
    pathLayout->addWidget(m_changePathButton);
    mainLayout->addLayout(pathLayout);  // Signal connection removed\nif (!newPath.empty()) {
            m_configPath = newPath;
            m_configPathLabel->setText(m_configPath);
        }
    });
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

void SummaryPage::initializePage()
{
    generateSummary();
}

<<<<<<< HEAD
void SummaryPage::generateSummary() {}

// ═══════════════════════════════════════════════════════════════════════════════
// CompletePage
// ═══════════════════════════════════════════════════════════════════════════════

CompletePage::CompletePage(void*)
{
    setTitle("Setup Complete");
    setSubTitle("Installing configuration...");
    setupUI();
}

void CompletePage::setupUI() {}

void CompletePage::initializePage()
{
    performInstallation();
}

void CompletePage::onInstallProgress(int, const std::string&) {}

void CompletePage::onInstallComplete(bool success)
{
    m_installComplete = success;
=======
void SummaryPage::generateSummary()
{
// REMOVED_QT:     auto* wizard = qobject_cast<SetupWizard*>(this->wizard());
    if (!wizard) return;
    
    DetectedHardware hw = wizard->getHardware();
    ThermalConfig thermal = wizard->getThermalConfig();
    std::string entropyKey = wizard->getEntropyKey();
    
    std::string summary;
    summary += "═══════════════════════════════════════════════════════════\n";
    summary += "                CONFIGURATION SUMMARY\n";
    summary += "═══════════════════════════════════════════════════════════\n\n";
    
    summary += "📦 HARDWARE\n";
    summary += std::string("   CPU: %1\n");
    summary += std::string("   Drives: %1 detected\n"));
    for (const auto& drive : hw.drives) {
        double gb = drive.sizeBytes / (1024.0 * 1024.0 * 1024.0);
        summary += std::string("     - %1: %2 (%.0f GB)\n");
    }
    summary += std::string("   GPU: %1\n") ? "None" : hw.gpus[0].name);
    summary += std::string("   Memory: %.0f GB\n\n"));
    
    summary += "🌡️ THERMAL\n";
    std::string modeName;
    switch (thermal.defaultMode) {
        case ThermalMode::Sustainable: modeName = "Sustainable"; break;
        case ThermalMode::Hybrid: modeName = "Hybrid"; break;
        case ThermalMode::Burst: modeName = "Burst"; break;
    }
    summary += std::string("   Mode: %1\n");
    summary += std::string("   Ceiling: %.1f°C\n");
    summary += std::string("   EWMA Alpha: %.2f\n");
    summary += std::string("   Prediction: %1\n");
    summary += std::string("   Load Balancing: %1\n\n");
    
    summary += "🔐 SECURITY\n";
    summary += std::string("   Entropy Key: %1...\n"));
    summary += std::string("   Fingerprint: %1...\n\n"));
    
    summary += "═══════════════════════════════════════════════════════════\n";
    summary += "Press 'Finish' to save configuration and complete setup.\n";
    
    m_summaryText->setPlainText(summary);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CompletePage Implementation
// ═══════════════════════════════════════════════════════════════════════════════

CompletePage::CompletePage(void* parent)
    : QWizardPage(parent)
{
    setTitle(tr("Setup Complete"));
    setSubTitle(tr("Installing configuration..."));
    setFinalPage(true);
    setupUI();
}

void CompletePage::setupUI()
{
    auto* mainLayout = new void(this);
    
    m_statusLabel = new void(tr("Installing configuration files..."), this);
    mainLayout->addWidget(m_statusLabel);
    
    m_progressBar = new void(this);
    m_progressBar->setRange(0, 100);
    mainLayout->addWidget(m_progressBar);
    
    m_logText = new void(this);
    m_logText->setReadOnly(true);
    m_logText->setFont(void("Consolas", 9));
    mainLayout->addWidget(m_logText);
    
    m_resultLabel = new void(this);
    m_resultLabel->setAlignment(AlignCenter);
    m_resultLabel->setStyleSheet("void { font-size: 14pt; padding: 10px; }");
    mainLayout->addWidget(m_resultLabel);
    
    auto* optionsLayout = new void();
    m_launchIdeCheck = new void(tr("Launch RawrXD IDE after setup"), this);
    m_launchIdeCheck->setChecked(true);
    optionsLayout->addWidget(m_launchIdeCheck);
    
    m_openDocsCheck = new void(tr("Open documentation"), this);
    optionsLayout->addWidget(m_openDocsCheck);
    
    mainLayout->addLayout(optionsLayout);
}

void CompletePage::initializePage()
{
    m_installComplete = false;
    m_progressBar->setValue(0);
    m_logText->clear();
    m_resultLabel->clear();
    
    // Start installation after a brief delay
    // Timer operation removed
}

void CompletePage::onInstallProgress(int percent, const std::string& status)
{
    m_progressBar->setValue(percent);
    m_logText->append(status);
}

void CompletePage::onInstallComplete(bool success)
{
    m_installComplete = true;
    
    if (success) {
        m_statusLabel->setText(tr("✅ Setup completed successfully!"));
        m_resultLabel->setText(tr("<span style='color: green; font-size: 16pt'>🎉 Configuration Installed!</span>"));
    } else {
        m_statusLabel->setText(tr("❌ Setup failed!"));
        m_resultLabel->setText(tr("<span style='color: red'>Setup encountered errors. Check the log for details.</span>"));
    }
    
    completeChanged();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void CompletePage::performInstallation()
{
<<<<<<< HEAD
    onInstallProgress(10, "Creating configuration directory...");
    onInstallProgress(30, "Saving hardware binding...");
    onInstallProgress(50, "Writing thermal configuration...");
    onInstallProgress(70, "Generating security keys...");
    onInstallProgress(90, "Finalizing setup...");
    bool success = true; // Actual write done by SetupWizard::writeConfigFiles
    onInstallProgress(100, success ? "All configuration files saved!" : "Error writing files");
=======
// REMOVED_QT:     auto* wizard = qobject_cast<SetupWizard*>(this->wizard());
    if (!wizard) {
        onInstallComplete(false);
        return;
    }
    
    onInstallProgress(10, tr("Creating configuration directory..."));
    std::filesystem::create_directories(wizard->getConfigPath());
    
    onInstallProgress(30, tr("Saving hardware binding..."));
    // Save would happen here via wizard->writeConfigFiles()
    
    onInstallProgress(50, tr("Writing thermal configuration..."));
    std::thread::msleep(200);
    
    onInstallProgress(70, tr("Generating security keys..."));
    std::thread::msleep(200);
    
    onInstallProgress(90, tr("Finalizing setup..."));
    
    bool success = wizard->writeConfigFiles();
    
    onInstallProgress(100, success ? tr("✅ All configuration files saved!") : tr("❌ Error writing files"));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    onInstallComplete(success);
}

// ═══════════════════════════════════════════════════════════════════════════════
<<<<<<< HEAD
// SetupWizard
// ═══════════════════════════════════════════════════════════════════════════════

SetupWizard::SetupWizard(void*)
    : m_configPath("D:\\rawrxd\\config")
{
    setupPages();
    setupButtons();
    applyTheme();
}

SetupWizard::~SetupWizard()
{
    delete m_introPage;
    delete m_hardwarePage;
    delete m_thermalPage;
    delete m_securityPage;
    delete m_summaryPage;
    delete m_completePage;
    m_introPage = nullptr;
    m_hardwarePage = nullptr;
    m_thermalPage = nullptr;
    m_securityPage = nullptr;
    m_summaryPage = nullptr;
    m_completePage = nullptr;
}
=======
// SetupWizard Implementation
// ═══════════════════════════════════════════════════════════════════════════════

SetupWizard::SetupWizard(void* parent)
    : QWizard(parent)
    , m_configPath("D:\\rawrxd\\config")
{
    setWindowTitle(tr("RawrXD IDE Setup Wizard"));
    setWizardStyle(QWizard::ModernStyle);
    setMinimumSize(700, 550);
    
    setupPages();
    setupButtons();
    applyTheme();  // Signal connection removed\n  // Signal connection removed\n}

SetupWizard::~SetupWizard() = default;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

void SetupWizard::setupPages()
{
    m_introPage = new IntroPage(this);
    m_hardwarePage = new HardwarePage(this);
    m_thermalPage = new ThermalPage(this);
    m_securityPage = new SecurityPage(this);
    m_summaryPage = new SummaryPage(this);
    m_completePage = new CompletePage(this);
<<<<<<< HEAD
}

void SetupWizard::setupButtons() {}

void SetupWizard::applyTheme() {}

DetectedHardware SetupWizard::getHardware() const
{
    return m_hardwarePage ? m_hardwarePage->getDetectedHardware() : DetectedHardware{};
=======
    
    setPage(Page_Intro, m_introPage);
    setPage(Page_Hardware, m_hardwarePage);
    setPage(Page_Thermal, m_thermalPage);
    setPage(Page_Security, m_securityPage);
    setPage(Page_Summary, m_summaryPage);
    setPage(Page_Complete, m_completePage);
    
    setStartId(Page_Intro);
}

void SetupWizard::setupButtons()
{
    setButtonText(QWizard::NextButton, tr("Next →"));
    setButtonText(QWizard::BackButton, tr("← Back"));
    setButtonText(QWizard::FinishButton, tr("Finish ✓"));
    setButtonText(QWizard::CancelButton, tr("Cancel"));
    setButtonText(QWizard::HelpButton, tr("Help ?"));
    
    setOption(QWizard::HaveHelpButton, true);
}

void SetupWizard::applyTheme()
{
    setStyleSheet(R"(
        QWizard {
            background: #f5f5f5;
        }
        QWizardPage {
            background: white;
        }
        void {
            font-weight: bold;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        void::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 3px;
        }
        void {
            padding: 8px 16px;
            border-radius: 4px;
            background: #0078d4;
            color: white;
            border: none;
        }
        void:hover {
            background: #106ebe;
        }
        void:disabled {
            background: #ccc;
        }
    )");
}

DetectedHardware SetupWizard::getHardware() const
{
    return m_hardwarePage->getDetectedHardware();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

ThermalConfig SetupWizard::getThermalConfig() const
{
<<<<<<< HEAD
    return m_thermalPage ? m_thermalPage->getThermalConfig() : ThermalConfig{};
=======
    return m_thermalPage->getThermalConfig();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::string SetupWizard::getEntropyKey() const
{
<<<<<<< HEAD
    return m_securityPage ? m_securityPage->getEntropyKey() : "";
}

void SetupWizard::onPageChanged(int) {}

void SetupWizard::onHelpRequested()
{
#ifdef _WIN32
    ShellExecuteA(nullptr, "open", "https://github.com/ItsMehRAWRXD/RawrXD/wiki/Setup", nullptr, nullptr, SW_SHOWNORMAL);
#endif
}

static std::string escapeJson(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
=======
    return m_securityPage->getEntropyKey();
}

void SetupWizard::onPageChanged(int id)
{
    // Update subtitle based on progress
    std::string progress = std::string(" (%1/6)");
    // Could update window title here
}

void SetupWizard::onHelpRequested()
{
    QDesktopServices::openUrl(std::string("https://github.com/ItsMehRAWRXD/RawrXD/wiki/Setup"));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool SetupWizard::writeConfigFiles()
{
<<<<<<< HEAD
    namespace fs = std::filesystem;
    try {
        fs::create_directories(m_configPath);
    } catch (...) {
        return false;
    }

    DetectedHardware hw = getHardware();
    ThermalConfig thermal = getThermalConfig();
    std::string entropy = getEntropyKey();

    std::string bindingPath = m_configPath + "\\sovereign_binding.json";
    std::ofstream bindingFile(bindingPath);
    if (bindingFile) {
        bindingFile << "{\"version\":\"2.0.0\",\"fingerprint\":\"" << escapeJson(hw.fingerprint)
                    << "\",\"entropyKey\":\"" << escapeJson(entropy)
                    << "\",\"cpu\":{\"name\":\"" << escapeJson(hw.cpu.name)
                    << "\",\"processorId\":\"" << escapeJson(hw.cpu.processorId)
                    << "\",\"cores\":" << hw.cpu.coreCount
                    << ",\"threads\":" << hw.cpu.threadCount << "}}\n";
    }

    std::string thermalPath = m_configPath + "\\thermal_governor.json";
    std::ofstream thermalFile(thermalPath);
    if (thermalFile) {
        thermalFile << "{\"version\":\"2.0.0\",\"mode\":" << static_cast<int>(thermal.defaultMode)
                    << ",\"sustainableCeiling\":" << thermal.sustainableCeiling
                    << ",\"hybridCeiling\":" << thermal.hybridCeiling
                    << ",\"burstCeiling\":" << thermal.burstCeiling
                    << ",\"ewmaAlpha\":" << thermal.ewmaAlpha
                    << ",\"predictionHorizonMs\":" << thermal.predictionHorizonMs
                    << ",\"enablePredictive\":" << (thermal.enablePredictive ? "true" : "false")
                    << ",\"enableLoadBalancing\":" << (thermal.enableLoadBalancing ? "true" : "false") << "}\n";
    }

=======
    // configDir(m_configPath);
    if (!configDir.exists()) {
        configDir.mkpath(".");
    }
    
    DetectedHardware hw = getHardware();
    ThermalConfig thermal = getThermalConfig();
    std::string entropy = getEntropyKey();
    
    // Write sovereign_binding.json
    void* binding;
    binding["version"] = "2.0.0";
    binding["fingerprint"] = hw.fingerprint;
    binding["entropyKey"] = entropy;
    
    void* cpuObj;
    cpuObj["name"] = hw.cpu.name;
    cpuObj["processorId"] = hw.cpu.processorId;
    cpuObj["cores"] = hw.cpu.coreCount;
    cpuObj["threads"] = hw.cpu.threadCount;
    binding["cpu"] = cpuObj;
    
    void* drivesArr;
    for (const auto& drive : hw.drives) {
        void* driveObj;
        driveObj["index"] = drive.index;
        driveObj["model"] = drive.model;
        driveObj["deviceId"] = drive.deviceId;
        driveObj["sizeBytes"] = drive.sizeBytes;
        driveObj["isNVMe"] = drive.isNVMe;
        drivesArr.append(driveObj);
    }
    binding["drives"] = drivesArr;
    
    // File operation removed;
    if (bindingFile.open(std::iostream::WriteOnly)) {
        bindingFile.write(void*(binding).toJson());
        bindingFile.close();
    }
    
    // Write thermal_governor.json
    void* thermalObj;
    thermalObj["version"] = "2.0.0";
    thermalObj["mode"] = static_cast<int>(thermal.defaultMode);
    thermalObj["sustainableCeiling"] = thermal.sustainableCeiling;
    thermalObj["hybridCeiling"] = thermal.hybridCeiling;
    thermalObj["burstCeiling"] = thermal.burstCeiling;
    thermalObj["ewmaAlpha"] = thermal.ewmaAlpha;
    thermalObj["predictionHorizonMs"] = thermal.predictionHorizonMs;
    thermalObj["enablePredictive"] = thermal.enablePredictive;
    thermalObj["enableLoadBalancing"] = thermal.enableLoadBalancing;
    
    // File operation removed;
    if (thermalFile.open(std::iostream::WriteOnly)) {
        thermalFile.write(void*(thermalObj).toJson());
        thermalFile.close();
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    configurationSaved(m_configPath);
    return true;
}

void SetupWizard::saveConfiguration()
{
    writeConfigFiles();
}

<<<<<<< HEAD
void SetupWizard::setupComplete(bool) { /* Host can override or subscribe */ }
void SetupWizard::configurationSaved(const std::string&) { /* Host can override or subscribe */ }

void SetupWizard::done(int result)
{
    if (result == WizardAccepted)
        setupComplete(true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// HardwareDetector — Win32/BCrypt only (no Qt, no QProcess)
// ═══════════════════════════════════════════════════════════════════════════════

HardwareDetector::HardwareDetector(void*)
{
}

void HardwareDetector::progress(int, const std::string&) { /* internal; callbacks invoked by lambda */ }
void HardwareDetector::complete(const DetectedHardware&) { /* internal; callbacks invoked by lambda */ }
void HardwareDetector::error(const std::string&) { /* internal; callbacks invoked by lambda */ }

=======
void SetupWizard::done(int result)
{
    if (result == void::Accepted) {
        setupComplete(true);
    }
    QWizard::done(result);
}

// ═══════════════════════════════════════════════════════════════════════════════
// HardwareDetector Implementation
// ═══════════════════════════════════════════════════════════════════════════════

HardwareDetector::HardwareDetector()
    
{
}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
void HardwareDetector::detect()
{
    m_cancelled = false;
    DetectedHardware hw;
<<<<<<< HEAD

    auto notifyProgress = [this](int pct, const std::string& s) {
        progress(pct, s);
        if (on_progress) on_progress(pct, s);
    };
    auto notifyComplete = [this](const DetectedHardware& h) {
        complete(h);
        if (on_complete) on_complete(h);
    };
    auto notifyError = [this](const std::string& e) {
        error(e);
        if (on_error) on_error(e);
    };

    notifyProgress(10, "Detecting CPU...");
    hw.cpu = detectCPU();
    if (m_cancelled) return;

    notifyProgress(30, "Detecting storage drives...");
    hw.drives = detectDrives();
    if (m_cancelled) return;

    notifyProgress(60, "Detecting graphics...");
    hw.gpus = detectGPUs();
    if (m_cancelled) return;

    notifyProgress(80, "Detecting memory...");
    hw.memory = detectMemory();
    if (m_cancelled) return;

    notifyProgress(95, "Generating fingerprint...");
    hw.fingerprint = generateFingerprint(hw);
    hw.detectionComplete = true;
    notifyProgress(100, "Detection complete!");
    notifyComplete(hw);
=======
    
    try {
        progress(10, tr("Detecting CPU..."));
        hw.cpu = detectCPU();
        if (m_cancelled) return;
        
        progress(30, tr("Detecting storage drives..."));
        hw.drives = detectDrives();
        if (m_cancelled) return;
        
        progress(60, tr("Detecting graphics..."));
        hw.gpus = detectGPUs();
        if (m_cancelled) return;
        
        progress(80, tr("Detecting memory..."));
        hw.memory = detectMemory();
        if (m_cancelled) return;
        
        progress(95, tr("Generating fingerprint..."));
        hw.fingerprint = generateFingerprint(hw);
        
        hw.detectionComplete = true;
        progress(100, tr("Detection complete!"));
        complete(hw);
        
    } catch (const std::exception& e) {
        error(std::string::fromStdString(e.what()));
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void HardwareDetector::cancel()
{
    m_cancelled = true;
}

CPUInfo HardwareDetector::detectCPU()
{
    CPUInfo cpu;
<<<<<<< HEAD
#ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    char name[13] = { 0 };
    *reinterpret_cast<int*>(name) = cpuInfo[1];
    *reinterpret_cast<int*>(name + 4) = cpuInfo[2];
    *reinterpret_cast<int*>(name + 8) = cpuInfo[3];
    cpu.name = name;
    cpu.processorId = "0";
    cpu.manufacturer = "Unknown";
    __cpuid(cpuInfo, 1);
    cpu.coreCount = 1;
    cpu.threadCount = (cpuInfo[1] >> 16) & 0xFF;
    if (cpu.threadCount == 0) cpu.threadCount = 1;
    cpu.supportsRDRAND = (cpuInfo[2] & (1 << 30)) != 0;
    __cpuid(cpuInfo, 7);
    cpu.supportsAVX512 = (cpuInfo[1] & (1 << 16)) != 0;
    cpu.maxClockMHz = 0;
    cpu.l3CacheKB = 0;
#else
    cpu.name = "Unknown CPU";
    cpu.coreCount = static_cast<int>(std::thread::hardware_concurrency());
    cpu.threadCount = cpu.coreCount;
#endif
=======
    
#ifdef _WIN32
    // Use WMI via PowerShell for simplicity
    // Process removed
    process.start("powershell", std::stringList() << "-Command" 
        << "Get-CimInstance -ClassName Win32_Processor | ConvertTo-Json");
    process.waitForFinished(5000);
    
    std::vector<uint8_t> output = process.readAllStandardOutput();
    void* doc = void*::fromJson(output);
    
    if (doc.isObject()) {
        void* obj = doc.object();
        cpu.name = obj["Name"].toString().trimmed();
        cpu.processorId = obj["ProcessorId"].toString();
        cpu.manufacturer = obj["Manufacturer"].toString();
        cpu.coreCount = obj["NumberOfCores"];
        cpu.threadCount = obj["NumberOfLogicalProcessors"];
        cpu.maxClockMHz = obj["MaxClockSpeed"];
        cpu.l3CacheKB = obj["L3CacheSize"];
    }
    
    // Check for RDRAND support
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    cpu.supportsRDRAND = (cpuInfo[2] & (1 << 30)) != 0;
    
    // Check for AVX-512
    __cpuid(cpuInfo, 7);
    cpu.supportsAVX512 = (cpuInfo[1] & (1 << 16)) != 0;
    
#else
    cpu.name = "Unknown CPU";
    cpu.coreCount = std::thread::hardware_concurrency();
    cpu.threadCount = cpu.coreCount;
#endif
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return cpu;
}

std::vector<DriveInfo> HardwareDetector::detectDrives()
{
    std::vector<DriveInfo> drives;
<<<<<<< HEAD
#ifdef _WIN32
    DriveInfo d;
    d.index = 0;
    d.model = "System Drive";
    d.deviceId = "0";
    d.sizeBytes = 512LL * 1024 * 1024 * 1024;
    d.healthStatus = "Healthy";
    d.busType = "SSD";
    d.isNVMe = false;
    drives.push_back(d);
#else
    DriveInfo d;
    d.index = 0;
    d.model = "System";
    d.sizeBytes = 512LL * 1024 * 1024 * 1024;
    drives.push_back(d);
#endif
=======
    
#ifdef _WIN32
    // Process removed
    process.start("powershell", std::stringList() << "-Command" 
        << "Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, Model, SerialNumber, Size, MediaType, BusType, HealthStatus | ConvertTo-Json");
    process.waitForFinished(10000);
    
    std::vector<uint8_t> output = process.readAllStandardOutput();
    void* doc = void*::fromJson(output);
    
    auto parseDriver = [](const void*& obj, int index) -> DriveInfo {
        DriveInfo drive;
        drive.index = index;
        drive.deviceId = obj["DeviceId"].toString();
        drive.model = obj["FriendlyName"].toString();
        if (drive.model.empty()) {
            drive.model = obj["Model"].toString();
        }
        drive.serialNumber = obj["SerialNumber"].toString();
        drive.sizeBytes = obj["Size"].toVariant().toLongLong();
        drive.busType = obj["BusType"].toString();
        drive.healthStatus = obj["HealthStatus"].toString();
        drive.isNVMe = drive.busType.contains("NVMe", CaseInsensitive);
        drive.maxTempCelsius = drive.isNVMe ? 70.0 : 75.0;
        return drive;
    };
    
    if (doc.isArray()) {
        void* arr = doc.array();
        for (int i = 0; i < arr.size(); ++i) {
            drives.push_back(parseDriver(arr[i].toObject(), i));
        }
    } else if (doc.isObject()) {
        drives.push_back(parseDriver(doc.object(), 0));
    }
#endif
    
    // Ensure at least one drive
    if (drives.empty()) {
        DriveInfo fallback;
        fallback.index = 0;
        fallback.model = "System Drive";
        fallback.sizeBytes = 500LL * 1024 * 1024 * 1024;
        fallback.healthStatus = "Healthy";
        drives.push_back(fallback);
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return drives;
}

std::vector<GPUInfo> HardwareDetector::detectGPUs()
{
    std::vector<GPUInfo> gpus;
<<<<<<< HEAD
    GPUInfo g;
    g.name = "Default GPU";
    g.vramBytes = 0;
    gpus.push_back(g);
=======
    
#ifdef _WIN32
    // Process removed
    process.start("powershell", std::stringList() << "-Command" 
        << "Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, DriverVersion, AdapterRAM | ConvertTo-Json");
    process.waitForFinished(5000);
    
    std::vector<uint8_t> output = process.readAllStandardOutput();
    void* doc = void*::fromJson(output);
    
    auto parseGPU = [](const void*& obj) -> GPUInfo {
        GPUInfo gpu;
        gpu.name = obj["Name"].toString();
        gpu.driverVersion = obj["DriverVersion"].toString();
        gpu.vramBytes = obj["AdapterRAM"].toVariant().toLongLong();
        gpu.isDiscrete = !gpu.name.contains("Intel", CaseInsensitive) && 
                         !gpu.name.contains("Integrated", CaseInsensitive);
        gpu.maxTempCelsius = gpu.name.contains("AMD") || gpu.name.contains("Radeon") ? 110 : 83;
        return gpu;
    };
    
    if (doc.isArray()) {
        void* arr = doc.array();
        for (const auto& item : arr) {
            GPUInfo gpu = parseGPU(item.toObject());
            if (!gpu.name.contains("Basic", CaseInsensitive)) {
                gpus.push_back(gpu);
            }
        }
    } else if (doc.isObject()) {
        GPUInfo gpu = parseGPU(doc.object());
        if (!gpu.name.contains("Basic", CaseInsensitive)) {
            gpus.push_back(gpu);
        }
    }
#endif
    
    if (gpus.empty()) {
        GPUInfo fallback;
        fallback.name = "Integrated Graphics";
        gpus.push_back(fallback);
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return gpus;
}

MemoryInfo HardwareDetector::detectMemory()
{
    MemoryInfo mem;
<<<<<<< HEAD
#ifdef _WIN32
    MEMORYSTATUSEX memStatus = {};
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus))
        mem.totalBytes = memStatus.ullTotalPhys;
    mem.moduleCount = 0;
    mem.speedMHz = 0;
=======
    
#ifdef _WIN32
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        mem.totalBytes = memStatus.ullTotalPhys;
    }
    
    // Process removed
    process.start("powershell", std::stringList() << "-Command" 
        << "(Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object).Count");
    process.waitForFinished(3000);
    mem.moduleCount = process.readAllStandardOutput().trimmed();
    
    process.start("powershell", std::stringList() << "-Command" 
        << "(Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object -First 1).Speed");
    process.waitForFinished(3000);
    mem.speedMHz = process.readAllStandardOutput().trimmed();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#else
    mem.totalBytes = 16LL * 1024 * 1024 * 1024;
    mem.moduleCount = 2;
    mem.speedMHz = 3200;
#endif
<<<<<<< HEAD
=======
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return mem;
}

std::string HardwareDetector::generateFingerprint(const DetectedHardware& hw)
{
    std::string source = hw.cpu.processorId + "|" + hw.cpu.name + "|";
<<<<<<< HEAD
    for (const auto& drive : hw.drives)
        source += drive.deviceId + drive.model + "|";
    for (const auto& gpu : hw.gpus)
        source += gpu.name + "|";

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != 0 || !hAlg) return "";

    DWORD objLen = 0, junk = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &junk, 0);
    std::vector<uint8_t> hashObj(objLen);
    status = BCryptCreateHash(hAlg, &hHash, hashObj.data(), (ULONG)hashObj.size(), nullptr, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    BCryptHashData(hHash, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(source.data())), (ULONG)source.size(), 0);
    uint8_t hash[32];
    status = BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status != 0) return "";

    std::ostringstream os;
    for (int i = 0; i < 32; ++i)
        os << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    return os.str();
#else
    std::ostringstream os;
    for (size_t i = 0; i < source.size() && i < 32u; ++i)
        os << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (int)(unsigned char)source[i];
    std::string s = os.str();
    while (s.size() < 64) s += s;
    return s.substr(0, 64);
#endif
}

} // namespace rawrxd::setup
=======
    for (const auto& drive : hw.drives) {
        source += drive.deviceId + drive.model + "|";
    }
    for (const auto& gpu : hw.gpus) {
        source += gpu.name + "|";
    }
    
    std::vector<uint8_t> hash = QCryptographicHash::hash(source.toUtf8(), QCryptographicHash::Sha256);
    return hash.toHex().toUpper();
}

} // namespace rawrxd::setup

// MOC removed

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
