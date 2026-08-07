// StatusBarTelemetry.cpp
// RawrXD Win32IDE Status Bar Telemetry Display
// Real-time TPS, VRAM, temperature metrics

#include "StatusBarTelemetry.h"
#include <cstdio>
#include <cstring>

// ─── Construction / Destruction ───

StatusBarTelemetry::StatusBarTelemetry() noexcept
    : m_hwndStatus(nullptr)
    , m_hwndParent(nullptr)
    , m_partCount(0)
    , m_updateIntervalMs(250)
    , m_lastUpdateTick(0)
{
    ZeroMemory(m_parts, sizeof(m_parts));
}

StatusBarTelemetry::~StatusBarTelemetry() {
    Shutdown();
}

// ─── Initialization ───

bool StatusBarTelemetry::Initialize(HWND hwndParent, int numParts) {
    if (!hwndParent || numParts < 1 || numParts > MAX_PARTS) {
        return false;
    }

    m_hwndParent = hwndParent;
    m_partCount = numParts;

    // Create status bar
    m_hwndStatus = CreateWindowExW(
        0,
        STATUSCLASSNAMEW,
        nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hwndParent,
        (HMENU)IDC_STATUS_BAR,
        GetModuleHandleW(nullptr),
        nullptr
    );

    if (!m_hwndStatus) {
        return false;
    }

    // Calculate part widths based on parent width
    UpdatePartWidths();

    return true;
}

void StatusBarTelemetry::Shutdown() noexcept {
    if (m_hwndStatus) {
        DestroyWindow(m_hwndStatus);
        m_hwndStatus = nullptr;
    }
    m_hwndParent = nullptr;
}

// ─── Part Management ───

void StatusBarTelemetry::UpdatePartWidths() {
    if (!m_hwndStatus || !m_hwndParent) return;

    RECT rc;
    GetClientRect(m_hwndParent, &rc);
    int width = rc.right - rc.left;

    // Define part widths (right-aligned, growing left)
    // Part 0: Engine status (left, flexible)
    // Part 1: GPU temps
    // Part 2: VRAM usage
    // Part 3: TPS metrics (right, fixed)

    int rightEdge = width - 16; // Leave room for gripper

    switch (m_partCount) {
        case 1:
            m_parts[0] = -1; // Single part fills all
            break;
        case 2:
            m_parts[0] = rightEdge - 200;
            m_parts[1] = -1;
            break;
            case 3:
            m_parts[0] = rightEdge - 350;
            m_parts[1] = rightEdge - 200;
            m_parts[2] = -1;
            break;
        case 4:
        default:
            m_parts[0] = rightEdge - 500; // Engine/model info
            m_parts[1] = rightEdge - 350; // GPU temps
            m_parts[2] = rightEdge - 200; // VRAM
            m_parts[3] = -1;              // TPS (rightmost)
            break;
    }

    SendMessageW(m_hwndStatus, SB_SETPARTS, m_partCount, (LPARAM)m_parts);
}

void StatusBarTelemetry::SetPartText(int part, const wchar_t* text) {
    if (!m_hwndStatus || part < 0 || part >= m_partCount) return;
    SendMessageW(m_hwndStatus, SB_SETTEXTW, part, (LPARAM)text);
}

// ─── Telemetry Updates ───

void StatusBarTelemetry::UpdateFromTelemetry(const O1StatusTelemetry& telemetry,
                                              const std::string& modelName) {
    DWORD now = GetTickCount();
    if ((now - m_lastUpdateTick) < (DWORD)m_updateIntervalMs) {
        return; // Throttle updates
    }
    m_lastUpdateTick = now;

    wchar_t buffer[256];

    // Part 0: Engine and model info
    if (m_partCount >= 1) {
        std::wstring modelWide(modelName.begin(), modelName.end());
        if (modelWide.length() > 20) {
            modelWide = modelWide.substr(0, 17) + L"...";
        }
        swprintf_s(buffer, L"OMEGA-1 | %s", modelWide.empty() ? L"No Model" : modelWide.c_str());
        SetPartText(0, buffer);
    }

    // Part 1: GPU temperatures
    if (m_partCount >= 2) {
        if (telemetry.gpu1TempC > 0) {
            swprintf_s(buffer, L"GPU: %.0f°C / %.0f°C",
                      telemetry.gpu0TempC, telemetry.gpu1TempC);
        } else {
            swprintf_s(buffer, L"GPU: %.0f°C", telemetry.gpu0TempC);
        }
        SetPartText(1, buffer);
    }

    // Part 2: VRAM usage
    if (m_partCount >= 3) {
        float totalVram = telemetry.gpu0VramTotalGb;
        float usedVram = telemetry.gpu0VramUsedGb;
        if (telemetry.gpu1VramTotalGb > 0) {
            totalVram += telemetry.gpu1VramTotalGb;
            usedVram += telemetry.gpu1VramUsedGb;
        }
        swprintf_s(buffer, L"VRAM: %.1f/%.0f GB",
                  usedVram, totalVram);
        SetPartText(2, buffer);
    }

    // Part 3: TPS metrics
    if (m_partCount >= 4) {
        const wchar_t* status = telemetry.isGenerating ? L"⚡" : L"○";
        swprintf_s(buffer, L"%s Prompt: %.0f t/s | Gen: %.0f t/s",
                  status, telemetry.tpsPrompt, telemetry.tpsGeneration);
        SetPartText(3, buffer);
    }
}

void StatusBarTelemetry::SetDisconnected() {
    if (m_partCount >= 1) SetPartText(0, L"OMEGA-1 | Disconnected");
    if (m_partCount >= 2) SetPartText(1, L"");
    if (m_partCount >= 3) SetPartText(2, L"");
    if (m_partCount >= 4) SetPartText(3, L"");
}

void StatusBarTelemetry::SetConnecting() {
    if (m_partCount >= 1) SetPartText(0, L"OMEGA-1 | Connecting...");
}

// ─── Window Message Handling ───

void StatusBarTelemetry::OnParentResize() {
    if (!m_hwndStatus) return;

    // Update part widths for new parent size
    UpdatePartWidths();

    // Resize status bar
    SendMessageW(m_hwndStatus, WM_SIZE, 0, 0);
}

bool StatusBarTelemetry::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!m_hwndStatus) return false;

    switch (msg) {
        case WM_SIZE:
            OnParentResize();
            return true;

        case WM_DRAWITEM:
            // Custom drawing if needed
            return false;
    }

    return false;
}

// ─── Accessors ───

void StatusBarTelemetry::SetUpdateInterval(int ms) {
    m_updateIntervalMs = std::max(100, std::min(5000, ms));
}

HWND StatusBarTelemetry::GetHandle() const noexcept {
    return m_hwndStatus;
}
