/**
 * @file RAWRXD_ThermalDashboard.cpp
<<<<<<< HEAD
 * @brief Win32 Thermal Dashboard UI — pure C++20, zero Qt.
 */
#include "RAWRXD_ThermalDashboard.hpp"
#include <cstdio>

#pragma comment(lib, "comctl32.lib")
=======
 * @brief Qt6 Thermal Dashboard UI Implementation
 */

#include "RAWRXD_ThermalDashboard.hpp"
#include "thermal_dashboard_plugin.hpp"
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

namespace rawrxd::thermal {

// ═══════════════════════════════════════════════════════════════════════════════
<<<<<<< HEAD
// ThermalDashboard
// ═══════════════════════════════════════════════════════════════════════════════

static const wchar_t* kThermalClass = L"RawrXD_ThermalDashboard";
static bool s_classRegistered = false;

ThermalDashboard::ThermalDashboard(HWND hwndParent)
    : m_hwndParent(hwndParent)
{
}

ThermalDashboard::~ThermalDashboard()
{
    if (m_hWnd && IsWindow(m_hWnd)) DestroyWindow(m_hWnd);
}

void ThermalDashboard::show()
{
    if (m_hWnd && IsWindow(m_hWnd)) { SetForegroundWindow(m_hWnd); return; }

    HINSTANCE hInst = GetModuleHandle(nullptr);
    if (!s_classRegistered) {
        WNDCLASSEXW wc{};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = WndProc;
        wc.hInstance      = hInst;
        wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(RGB(26, 26, 26));
        wc.lpszClassName = kThermalClass;
        RegisterClassExW(&wc);
        s_classRegistered = true;
    }

    RECT rc;
    if (m_hwndParent) GetWindowRect(m_hwndParent, &rc);
    else { rc.left = 200; rc.top = 100; }

    m_hWnd = CreateWindowExW(WS_EX_TOOLWINDOW,
        kThermalClass, L"\xD83C\xDF21 RawrXD Thermal Dashboard",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        rc.left + 60, rc.top + 40, 620, 540,
        m_hwndParent, nullptr, hInst, nullptr);

    SetWindowLongPtrW(m_hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    createControls(m_hWnd);
    ShowWindow(m_hWnd, SW_SHOW);
}

void ThermalDashboard::hide()
{
    if (m_hWnd) ShowWindow(m_hWnd, SW_HIDE);
}

// ═══════════════════════════════════════════════════════════════════════════════
// WndProc
// ═══════════════════════════════════════════════════════════════════════════════

LRESULT CALLBACK ThermalDashboard::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    auto* self = reinterpret_cast<ThermalDashboard*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    if (self) return self->handleMessage(hWnd, msg, wParam, lParam);
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

LRESULT ThermalDashboard::handleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_TD_APPLY_BTN) {
            int sel = static_cast<int>(SendMessageW(m_hwndModeCombo, CB_GETCURSEL, 0, 0));
            if (m_burstCb) m_burstCb(sel);
            return 0;
        }
        break;
    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Create child controls
// ═══════════════════════════════════════════════════════════════════════════════

void ThermalDashboard::createControls(HWND hWnd)
{
    HINSTANCE hInst = GetModuleHandle(nullptr);
    int y = 10;
    const int LBL_W = 180, BAR_W = 320, TEMP_W = 60;

    // ---- NVMe drives ----
    CreateWindowExW(0, L"STATIC", L"NVMe Drives",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y, 200, 18, hWnd, nullptr, hInst, nullptr);
    y += 22;

    const wchar_t* nvmeNames[] = {
        L"NVMe0 (SK hynix P41)", L"NVMe1 (Samsung 990 PRO)",
        L"NVMe2 (WD Black SN850X)", L"NVMe3 (Samsung 990 PRO 4TB)",
        L"NVMe4 (Crucial T705 4TB)"
    };
    for (int i = 0; i < 5; ++i) {
        m_nvme[i].hLabel = CreateWindowExW(0, L"STATIC", nvmeNames[i],
            WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y + 2, LBL_W, 18, hWnd, nullptr, hInst, nullptr);
        m_nvme[i].hBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH, LBL_W + 16, y, BAR_W, 18, hWnd, nullptr, hInst, nullptr);
        SendMessageW(m_nvme[i].hBar, PBM_SETRANGE32, 0, 100);
        m_nvme[i].hTemp = CreateWindowExW(0, L"STATIC", L"--\xB0C",
            WS_CHILD | WS_VISIBLE | SS_RIGHT, LBL_W + BAR_W + 22, y + 2, TEMP_W, 18, hWnd, nullptr, hInst, nullptr);
        y += 24;
    }
    y += 8;

    // ---- GPU / CPU ----
    CreateWindowExW(0, L"STATIC", L"System Thermals",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y, 200, 18, hWnd, nullptr, hInst, nullptr);
    y += 22;

    CreateWindowExW(0, L"STATIC", L"7800 XT Junction",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y + 2, LBL_W, 18, hWnd, nullptr, hInst, nullptr);
    m_hwndGpuBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH, LBL_W + 16, y, BAR_W, 18, hWnd, nullptr, hInst, nullptr);
    SendMessageW(m_hwndGpuBar, PBM_SETRANGE32, 0, 110);
    m_hwndGpuLabel = CreateWindowExW(0, L"STATIC", L"--\xB0C",
        WS_CHILD | WS_VISIBLE | SS_RIGHT, LBL_W + BAR_W + 22, y + 2, TEMP_W, 18, hWnd, nullptr, hInst, nullptr);
    y += 24;

    CreateWindowExW(0, L"STATIC", L"7800X3D Package",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y + 2, LBL_W, 18, hWnd, nullptr, hInst, nullptr);
    m_hwndCpuBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH, LBL_W + 16, y, BAR_W, 18, hWnd, nullptr, hInst, nullptr);
    SendMessageW(m_hwndCpuBar, PBM_SETRANGE32, 0, 95);
    m_hwndCpuLabel = CreateWindowExW(0, L"STATIC", L"--\xB0C",
        WS_CHILD | WS_VISIBLE | SS_RIGHT, LBL_W + BAR_W + 22, y + 2, TEMP_W, 18, hWnd, nullptr, hInst, nullptr);
    y += 32;

    // ---- Throttle ----
    CreateWindowExW(0, L"STATIC", L"Burst Governor",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y, 200, 18, hWnd, nullptr, hInst, nullptr);
    y += 22;

    CreateWindowExW(0, L"STATIC", L"Current Throttle",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y + 2, LBL_W, 18, hWnd, nullptr, hInst, nullptr);
    m_hwndThrottleBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH, LBL_W + 16, y, BAR_W, 18, hWnd, nullptr, hInst, nullptr);
    SendMessageW(m_hwndThrottleBar, PBM_SETRANGE32, 0, 100);
    m_hwndThrottleLbl = CreateWindowExW(0, L"STATIC", L"0%",
        WS_CHILD | WS_VISIBLE | SS_RIGHT, LBL_W + BAR_W + 22, y + 2, TEMP_W, 18, hWnd, nullptr, hInst, nullptr);
    y += 30;

    // ---- Mode selector ----
    CreateWindowExW(0, L"STATIC", L"Burst Mode:",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y + 4, 80, 18, hWnd, nullptr, hInst, nullptr);
    m_hwndModeCombo = CreateWindowExW(0, L"COMBOBOX", nullptr,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        96, y, 350, 120, hWnd, reinterpret_cast<HMENU>(IDC_TD_MODE_COMBO), hInst, nullptr);
    SendMessageW(m_hwndModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"\xD83D\xDE80 SOVEREIGN-MAX (142\x03BCs)"));
    SendMessageW(m_hwndModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"\xD83C\xDF21 THERMAL-GOVERNED (237\x03BCs)"));
    SendMessageW(m_hwndModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"\x26A1 ADAPTIVE-HYBRID (dynamic)"));
    SendMessageW(m_hwndModeCombo, CB_SETCURSEL, 2, 0);

    m_hwndApplyBtn = CreateWindowExW(0, L"BUTTON", L"Apply",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        454, y, 90, 26, hWnd, reinterpret_cast<HMENU>(IDC_TD_APPLY_BTN), hInst, nullptr);
    y += 38;

    // ---- Status ----
    m_hwndStatusLabel = CreateWindowExW(0, L"STATIC",
        L"\x231B Initializing thermal monitoring...",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 12, y, 560, 18, hWnd, nullptr, hInst, nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Runtime updates
// ═══════════════════════════════════════════════════════════════════════════════

COLORREF ThermalDashboard::tempToColor(float temp)
{
    if (temp < 55.0f) return RGB(0, 255, 0);
    if (temp < 65.0f) return RGB(136, 255, 0);
    if (temp < 72.0f) return RGB(255, 204, 0);
    if (temp < 80.0f) return RGB(255, 136, 0);
    return RGB(255, 51, 51);
=======
// ThermalDashboard Implementation
// ═══════════════════════════════════════════════════════════════════════════════

ThermalDashboard::ThermalDashboard(void* parent)
    : void(parent)
{
    setupUI();
}

void ThermalDashboard::setupUI()
{
    auto* mainLayout = new void(this);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(15, 15, 15, 15);
    
    // Title
    auto* titleLabel = new void("🌡️ RawrXD Thermal Dashboard", this);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff88;");
    mainLayout->addWidget(titleLabel);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // NVMe Section
    // ═══════════════════════════════════════════════════════════════════════════
    auto* nvmeGroup = new void("NVMe Drives", this);
    nvmeGroup->setStyleSheet(R"(
        void {
            border: 2px solid #444;
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
            font-weight: bold;
            color: #aaa;
        }
        void::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
    )");
    
    auto* nvmeLayout = new void(nvmeGroup);
    
    const char* nvmeNames[] = {
        "NVMe0 (SK hynix P41)",
        "NVMe1 (Samsung 990 PRO)",
        "NVMe2 (WD Black SN850X)",
        "NVMe3 (Samsung 990 PRO 4TB)",
        "NVMe4 (Crucial T705 4TB)"
    };
    
    for (int i = 0; i < 5; ++i) {
        auto* row = new void();
        
        m_nvmeWidgets[i].nameLabel = new void(nvmeNames[i], this);
        m_nvmeWidgets[i].nameLabel->setMinimumWidth(180);
        m_nvmeWidgets[i].nameLabel->setStyleSheet("color: #ccc;");
        
        m_nvmeWidgets[i].tempBar = new void(this);
        m_nvmeWidgets[i].tempBar->setRange(0, 100);
        m_nvmeWidgets[i].tempBar->setValue(50);
        m_nvmeWidgets[i].tempBar->setTextVisible(false);
        m_nvmeWidgets[i].tempBar->setFixedHeight(20);
        m_nvmeWidgets[i].tempBar->setStyleSheet(R"(
            void {
                border: 1px solid #555;
                border-radius: 4px;
                background: #222;
            }
            void::chunk {
                border-radius: 3px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00cc66, stop:0.6 #ffcc00, stop:1 #ff3333);
            }
        )");
        
        m_nvmeWidgets[i].tempLabel = new void("--°C", this);
        m_nvmeWidgets[i].tempLabel->setMinimumWidth(60);
        m_nvmeWidgets[i].tempLabel->setAlignment(//AlignRight | //AlignVCenter);
        m_nvmeWidgets[i].tempLabel->setStyleSheet("color: #0f0; font-weight: bold;");
        
        row->addWidget(m_nvmeWidgets[i].nameLabel);
        row->addWidget(m_nvmeWidgets[i].tempBar, 1);
        row->addWidget(m_nvmeWidgets[i].tempLabel);
        
        nvmeLayout->addLayout(row);
    }
    
    mainLayout->addWidget(nvmeGroup);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // GPU/CPU Section
    // ═══════════════════════════════════════════════════════════════════════════
    auto* systemGroup = new void("System Thermals", this);
    systemGroup->setStyleSheet(nvmeGroup->styleSheet());
    
    auto* systemLayout = new void(systemGroup);
    
    // GPU
    auto* gpuRow = new void();
    auto* gpuLabel = new void("7800 XT Junction", this);
    gpuLabel->setMinimumWidth(180);
    gpuLabel->setStyleSheet("color: #ff6666;");
    
    m_gpuTempBar = new void(this);
    m_gpuTempBar->setRange(0, 110);
    m_gpuTempBar->setValue(65);
    m_gpuTempBar->setTextVisible(false);
    m_gpuTempBar->setFixedHeight(20);
    m_gpuTempBar->setStyleSheet(m_nvmeWidgets[0].tempBar->styleSheet());
    
    m_gpuTempLabel = new void("--°C", this);
    m_gpuTempLabel->setMinimumWidth(60);
    m_gpuTempLabel->setAlignment(//AlignRight | //AlignVCenter);
    m_gpuTempLabel->setStyleSheet("color: #ff6666; font-weight: bold;");
    
    gpuRow->addWidget(gpuLabel);
    gpuRow->addWidget(m_gpuTempBar, 1);
    gpuRow->addWidget(m_gpuTempLabel);
    systemLayout->addLayout(gpuRow);
    
    // CPU
    auto* cpuRow = new void();
    auto* cpuLabel = new void("7800X3D Package", this);
    cpuLabel->setMinimumWidth(180);
    cpuLabel->setStyleSheet("color: #6699ff;");
    
    m_cpuTempBar = new void(this);
    m_cpuTempBar->setRange(0, 95);
    m_cpuTempBar->setValue(55);
    m_cpuTempBar->setTextVisible(false);
    m_cpuTempBar->setFixedHeight(20);
    m_cpuTempBar->setStyleSheet(m_nvmeWidgets[0].tempBar->styleSheet());
    
    m_cpuTempLabel = new void("--°C", this);
    m_cpuTempLabel->setMinimumWidth(60);
    m_cpuTempLabel->setAlignment(//AlignRight | //AlignVCenter);
    m_cpuTempLabel->setStyleSheet("color: #6699ff; font-weight: bold;");
    
    cpuRow->addWidget(cpuLabel);
    cpuRow->addWidget(m_cpuTempBar, 1);
    cpuRow->addWidget(m_cpuTempLabel);
    systemLayout->addLayout(cpuRow);
    
    mainLayout->addWidget(systemGroup);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Throttle Status
    // ═══════════════════════════════════════════════════════════════════════════
    auto* throttleGroup = new void("Burst Governor", this);
    throttleGroup->setStyleSheet(nvmeGroup->styleSheet());
    
    auto* throttleLayout = new void(throttleGroup);
    
    // Throttle bar
    auto* throttleRow = new void();
    auto* throttleLbl = new void("Current Throttle", this);
    throttleLbl->setStyleSheet("color: #ffcc00;");
    throttleLbl->setMinimumWidth(180);
    
    m_throttleBar = new void(this);
    m_throttleBar->setRange(0, 100);
    m_throttleBar->setValue(0);
    m_throttleBar->setTextVisible(false);
    m_throttleBar->setFixedHeight(20);
    m_throttleBar->setStyleSheet(R"(
        void {
            border: 1px solid #555;
            border-radius: 4px;
            background: #222;
        }
        void::chunk {
            border-radius: 3px;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #00ff00, stop:0.5 #ffff00, stop:1 #ff0000);
        }
    )");
    
    m_throttleLabel = new void("0%", this);
    m_throttleLabel->setMinimumWidth(60);
    m_throttleLabel->setAlignment(//AlignRight | //AlignVCenter);
    m_throttleLabel->setStyleSheet("color: #0f0; font-weight: bold;");
    
    throttleRow->addWidget(throttleLbl);
    throttleRow->addWidget(m_throttleBar, 1);
    throttleRow->addWidget(m_throttleLabel);
    throttleLayout->addLayout(throttleRow);
    
    // Mode selector
    auto* modeRow = new void();
    auto* modeLbl = new void("Burst Mode:", this);
    modeLbl->setStyleSheet("color: #aaa;");
    
    m_burstModeCombo = new void(this);
    m_burstModeCombo->addItem("🚀 SOVEREIGN-MAX (142μs)", 0);
    m_burstModeCombo->addItem("🌡️ THERMAL-GOVERNED (237μs)", 1);
    m_burstModeCombo->addItem("⚡ ADAPTIVE-HYBRID (dynamic)", 2);
    m_burstModeCombo->setCurrentIndex(2);
    m_burstModeCombo->setStyleSheet(R"(
        void {
            background: #333;
            color: #fff;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 5px 10px;
            min-width: 250px;
        }
        void:hover {
            border-color: #00ff88;
        }
        void::drop-down {
            border: none;
            width: 20px;
        }
    )");
    
    m_applyButton = new void("Apply", this);
    m_applyButton->setStyleSheet(R"(
        void {
            background: #00aa55;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 20px;
            font-weight: bold;
        }
        void:hover {
            background: #00cc66;
        }
        void:pressed {
            background: #008844;
        }
    )");
// Qt connect removed
        burstModeChanged(mode);
    });
    
    modeRow->addWidget(modeLbl);
    modeRow->addWidget(m_burstModeCombo, 1);
    modeRow->addWidget(m_applyButton);
    throttleLayout->addLayout(modeRow);
    
    mainLayout->addWidget(throttleGroup);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Status Bar
    // ═══════════════════════════════════════════════════════════════════════════
    m_statusLabel = new void("⏳ Initializing thermal monitoring...", this);
    m_statusLabel->setStyleSheet("color: #888; font-style: italic;");
    mainLayout->addWidget(m_statusLabel);
    
    mainLayout->addStretch();
    
    // Dark theme
    setStyleSheet("background-color: #1a1a1a;");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void ThermalDashboard::onThermalUpdate(const ThermalSnapshot& snapshot)
{
<<<<<<< HEAD
    for (int i = 0; i < snapshot.activeDriveCount && i < 5; ++i)
        updateNVMeDisplay(i, snapshot.nvmeTemps[i]);
    for (int i = snapshot.activeDriveCount; i < 5; ++i) {
        ShowWindow(m_nvme[i].hLabel, SW_HIDE);
        ShowWindow(m_nvme[i].hBar,   SW_HIDE);
        ShowWindow(m_nvme[i].hTemp,  SW_HIDE);
    }
    updateGPUDisplay(snapshot.gpuTemp);
    updateCPUDisplay(snapshot.cpuTemp);
    updateThrottleDisplay(snapshot.currentThrottle);

    wchar_t buf[128];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
        L"\x2713 %d drives active", snapshot.activeDriveCount);
    SetWindowTextW(m_hwndStatusLabel, buf);
}

void ThermalDashboard::updateNVMeDisplay(int idx, float temp)
{
    if (idx < 0 || idx >= 5) return;
    SendMessageW(m_nvme[idx].hBar, PBM_SETPOS, static_cast<int>(temp), 0);
    wchar_t buf[16];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%.0f\xB0C", temp);
    SetWindowTextW(m_nvme[idx].hTemp, buf);
=======
    // Update NVMe displays
    for (int i = 0; i < snapshot.activeDriveCount && i < 5; ++i) {
        updateNVMeDisplay(i, snapshot.nvmeTemps[i]);
    }
    
    // Hide unused drives
    for (int i = snapshot.activeDriveCount; i < 5; ++i) {
        m_nvmeWidgets[i].nameLabel->setVisible(false);
        m_nvmeWidgets[i].tempBar->setVisible(false);
        m_nvmeWidgets[i].tempLabel->setVisible(false);
    }
    
    // Update GPU/CPU
    updateGPUDisplay(snapshot.gpuTemp);
    updateCPUDisplay(snapshot.cpuTemp);
    
    // Update throttle
    updateThrottleDisplay(snapshot.currentThrottle);
    
    // Status
    m_statusLabel->setText(std::string("✓ Last update: %1 | %2 drives active")
        .toString("hh:mm:ss"))
        );
}

void ThermalDashboard::updateNVMeDisplay(int index, float temp)
{
    if (index < 0 || index >= 5) return;
    
    m_nvmeWidgets[index].tempBar->setValue(static_cast<int>(temp));
    m_nvmeWidgets[index].tempLabel->setText(std::string("%1°C"));
    m_nvmeWidgets[index].tempLabel->setStyleSheet(
        std::string("color: %1; font-weight: bold;")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void ThermalDashboard::updateGPUDisplay(float temp)
{
<<<<<<< HEAD
    SendMessageW(m_hwndGpuBar, PBM_SETPOS, static_cast<int>(temp), 0);
    wchar_t buf[16];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%.0f\xB0C", temp);
    SetWindowTextW(m_hwndGpuLabel, buf);
=======
    m_gpuTempBar->setValue(static_cast<int>(temp));
    m_gpuTempLabel->setText(std::string("%1°C"));
    m_gpuTempLabel->setStyleSheet(
        std::string("color: %1; font-weight: bold;")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void ThermalDashboard::updateCPUDisplay(float temp)
{
<<<<<<< HEAD
    SendMessageW(m_hwndCpuBar, PBM_SETPOS, static_cast<int>(temp), 0);
    wchar_t buf[16];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%.0f\xB0C", temp);
    SetWindowTextW(m_hwndCpuLabel, buf);
=======
    m_cpuTempBar->setValue(static_cast<int>(temp));
    m_cpuTempLabel->setText(std::string("%1°C"));
    m_cpuTempLabel->setStyleSheet(
        std::string("color: %1; font-weight: bold;")));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void ThermalDashboard::updateThrottleDisplay(int throttle)
{
<<<<<<< HEAD
    SendMessageW(m_hwndThrottleBar, PBM_SETPOS, throttle, 0);
    wchar_t buf[16];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%d%%", throttle);
    SetWindowTextW(m_hwndThrottleLbl, buf);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ThermalCompactWidget
// ═══════════════════════════════════════════════════════════════════════════════

ThermalCompactWidget::ThermalCompactWidget(HWND hwndParent)
    : m_hwndParent(hwndParent)
{
}

ThermalCompactWidget::~ThermalCompactWidget()
{
    if (m_hWnd && IsWindow(m_hWnd)) DestroyWindow(m_hWnd);
}

void ThermalCompactWidget::show()
{
    if (m_hWnd && IsWindow(m_hWnd)) return;
    HINSTANCE hInst = GetModuleHandle(nullptr);

    m_hWnd = CreateWindowExW(0, L"STATIC", nullptr,
        WS_CHILD | WS_VISIBLE | SS_SUNKEN,
        0, 0, 260, 28, m_hwndParent, nullptr, hInst, nullptr);

    m_hwndTempLbl  = CreateWindowExW(0, L"STATIC", L"\xD83C\xDF21 --\xB0C",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 4, 4, 80, 18, m_hWnd, nullptr, hInst, nullptr);
    m_hwndThrottle = CreateWindowExW(0, L"STATIC", L"\x26A1",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 88, 4, 30, 18, m_hWnd, nullptr, hInst, nullptr);
    m_hwndMode     = CreateWindowExW(0, L"STATIC", L"\xD83D\xDD04",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 122, 4, 30, 18, m_hWnd, nullptr, hInst, nullptr);
=======
    m_throttleBar->setValue(throttle);
    m_throttleLabel->setText(std::string("%1%"));
    
    std::string color;
    if (throttle == 0) {
        color = "#00ff00";  // Green: full speed
    } else if (throttle < 20) {
        color = "#88ff00";  // Light green
    } else if (throttle < 40) {
        color = "#ffcc00";  // Yellow
    } else {
        color = "#ff3333";  // Red: heavy throttle
    }
    m_throttleLabel->setStyleSheet(std::string("color: %1; font-weight: bold;"));
}

std::string ThermalDashboard::getTempColor(float temp)
{
    if (temp < 55) return "#00ff00";       // Green
    if (temp < 65) return "#88ff00";       // Light green
    if (temp < 72) return "#ffcc00";       // Yellow
    if (temp < 80) return "#ff8800";       // Orange
    return "#ff3333";                       // Red
}

// ═══════════════════════════════════════════════════════════════════════════════
// ThermalCompactWidget Implementation
// ═══════════════════════════════════════════════════════════════════════════════

ThermalCompactWidget::ThermalCompactWidget(void* parent)
    : void(parent)
{
    setupUI();
}

void ThermalCompactWidget::setupUI()
{
    setFrameStyle(void::StyledPanel | void::Raised);
    setStyleSheet(R"(
        void {
            background: #2a2a2a;
            border: 1px solid #444;
            border-radius: 4px;
            padding: 4px;
        }
    )");
    
    auto* layout = new void(this);
    layout->setSpacing(8);
    layout->setContentsMargins(8, 4, 8, 4);
    
    // Temp icon + value
    m_maxTempLabel = new void("🌡️ --°C", this);
    m_maxTempLabel->setStyleSheet("color: #0f0; font-weight: bold;");
    layout->addWidget(m_maxTempLabel);
    
    // Throttle status icon
    m_throttleIcon = new void("⚡", this);
    m_throttleIcon->setToolTip("Throttle status");
    layout->addWidget(m_throttleIcon);
    
    // Mode icon
    m_modeIcon = new void("🔄", this);
    m_modeIcon->setToolTip("Adaptive Hybrid mode");
    layout->addWidget(m_modeIcon);
    
    setFixedHeight(32);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void ThermalCompactWidget::onThermalUpdate(const ThermalSnapshot& snapshot)
{
<<<<<<< HEAD
    float maxTemp = snapshot.gpuTemp;
    for (int i = 0; i < snapshot.activeDriveCount; ++i)
        maxTemp = (std::max)(maxTemp, snapshot.nvmeTemps[i]);
    maxTemp = (std::max)(maxTemp, snapshot.cpuTemp);

    wchar_t buf[32];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"\xD83C\xDF21 %.0f\xB0C", maxTemp);
    SetWindowTextW(m_hwndTempLbl, buf);

    if (snapshot.currentThrottle == 0)
        SetWindowTextW(m_hwndThrottle, L"\x26A1");
    else if (snapshot.currentThrottle < 30)
        SetWindowTextW(m_hwndThrottle, L"\xD83D\xDD0B");
    else
        SetWindowTextW(m_hwndThrottle, L"\xD83D\xDC22");
}

} // namespace rawrxd::thermal
=======
    // Find max temp
    float maxTemp = snapshot.gpuTemp;
    for (int i = 0; i < snapshot.activeDriveCount; ++i) {
        maxTemp = qMax(maxTemp, snapshot.nvmeTemps[i]);
    }
    maxTemp = qMax(maxTemp, snapshot.cpuTemp);
    
    // Update display
    std::string color = (maxTemp < 65) ? "#00ff00" : (maxTemp < 75) ? "#ffcc00" : "#ff3333";
    m_maxTempLabel->setText(std::string("🌡️ %1°C"));
    m_maxTempLabel->setStyleSheet(std::string("color: %1; font-weight: bold;"));
    
    // Throttle icon
    if (snapshot.currentThrottle == 0) {
        m_throttleIcon->setText("⚡");
        m_throttleIcon->setToolTip("Full speed");
    } else if (snapshot.currentThrottle < 30) {
        m_throttleIcon->setText("🔋");
        m_throttleIcon->setToolTip(std::string("Light throttle: %1%"));
    } else {
        m_throttleIcon->setText("🐢");
        m_throttleIcon->setToolTip(std::string("Heavy throttle: %1%"));
    }
}

} // namespace rawrxd::thermal

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
