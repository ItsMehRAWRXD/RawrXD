#include "ide/SelfOptimizationPanel.hpp"
#include "sovereign/Beaconism.hpp"
#include <algorithm>

namespace IDE {

static const wchar_t* CLASS_NAME = L"SelfOptimizationPanel";

SelfOptimizationPanel::SelfOptimizationPanel()
    : m_hwnd(nullptr), m_parent(nullptr), m_visible(false) {
}

SelfOptimizationPanel::~SelfOptimizationPanel() {
    Shutdown();
}

bool SelfOptimizationPanel::Initialize(HWND parent) {
    m_parent = parent;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    m_hwnd = CreateWindowExW(
        0, CLASS_NAME, L"Self Optimization",
        WS_CHILD | WS_CLIPSIBLINGS,
        0, 0, 400, 300,
        parent, nullptr, GetModuleHandle(nullptr), this
    );

    SelfOptimization::RegisterDecisionCallback(
        [this](const SelfOptimization::OptimizationDecision& dec) { OnDecision(dec); }
    );

    return m_hwnd != nullptr;
}

void SelfOptimizationPanel::Shutdown() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void SelfOptimizationPanel::Show() {
    m_visible = true;
    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
}

void SelfOptimizationPanel::Hide() {
    m_visible = false;
    ShowWindow(m_hwnd, SW_HIDE);
}

bool SelfOptimizationPanel::IsVisible() const {
    return m_visible;
}

void SelfOptimizationPanel::SetBounds(int x, int y, int width, int height) {
    SetWindowPos(m_hwnd, nullptr, x, y, width, height, SWP_NOZORDER);
}

void SelfOptimizationPanel::Update() {
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void SelfOptimizationPanel::OnDecision(const SelfOptimization::OptimizationDecision& dec) {
    m_decisions.push_back(dec);
    if (m_decisions.size() > 10) {
        m_decisions.erase(m_decisions.begin());
    }
    Update();
}

void SelfOptimizationPanel::OnTelemetry(const SovereignTelemetry& t) {
    m_lastTelemetry = t;
    Update();
}

bool SelfOptimizationPanel::IsWired() {
    return true; // Panel is wired if it exists
}

LRESULT CALLBACK SelfOptimizationPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    SelfOptimizationPanel* panel = nullptr;
    if (msg == WM_CREATE) {
        panel = static_cast<SelfOptimizationPanel*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<SelfOptimizationPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            if (panel) panel->Render(hdc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void SelfOptimizationPanel::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);

    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &rc, bgBrush);
    DeleteObject(bgBrush);

    SetTextColor(hdc, RGB(100, 200, 255));
    SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, 20, 10, L"Self Optimization", 17);

    DrawTelemetry(hdc, 20, 35);

    int y = 100;
    for (auto it = m_decisions.rbegin(); it != m_decisions.rend() && y < rc.bottom - 30; ++it) {
        DrawDecision(hdc, 20, y, *it);
        y += 28;
    }
}

void SelfOptimizationPanel::DrawDecision(HDC hdc, int x, int y, const SelfOptimization::OptimizationDecision& dec) {
    COLORREF color = GetConfidenceColor(dec.confidence);
    HBRUSH brush = CreateSolidBrush(color);
    RECT rc = {x, y, x + 8, y + 20};
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);

    wchar_t buf[256];
    const wchar_t* typeName = GetDecisionTypeName(dec.type);
    swprintf_s(buf, L"%s: %.0f%% conf, +%.1f%%", typeName, dec.confidence * 100, dec.expectedImprovement * 100);

    SetTextColor(hdc, RGB(220, 220, 220));
    TextOutW(hdc, x + 15, y, buf, (int)wcslen(buf));
}

void SelfOptimizationPanel::DrawTelemetry(HDC hdc, int x, int y) {
    wchar_t buf[256];

    swprintf_s(buf, L"KV Pressure: %.1f%%", m_lastTelemetry.kvCachePressure * 100);
    SetTextColor(hdc, m_lastTelemetry.kvCachePressure > 0.8f ? RGB(255, 100, 100) : RGB(200, 200, 200));
    TextOutW(hdc, x, y, buf, (int)wcslen(buf));

    swprintf_s(buf, L"GPU Timing: %.2f ms", m_lastTelemetry.gpuTimingMs);
    SetTextColor(hdc, m_lastTelemetry.gpuTimingMs > 100.0f ? RGB(255, 150, 100) : RGB(200, 200, 200));
    TextOutW(hdc, x + 150, y, buf, (int)wcslen(buf));

    float maxLoad = 0;
    for (int i = 0; i < 8; i++) {
        maxLoad = std::max(maxLoad, m_lastTelemetry.moeHistogram[i]);
    }
    swprintf_s(buf, L"Max Expert Load: %.2f", maxLoad);
    SetTextColor(hdc, RGB(200, 200, 200));
    TextOutW(hdc, x, y + 18, buf, (int)wcslen(buf));
}

const wchar_t* SelfOptimizationPanel::GetDecisionTypeName(SelfOptimization::DecisionType type) {
    switch (type) {
        case SelfOptimization::DecisionType::REPLICATE_KV: return L"ReplKV";
        case SelfOptimization::DecisionType::MIGRATE_TIER: return L"Migr8";
        case SelfOptimization::DecisionType::REBALANCE_EXPERTS: return L"RebalExp";
        case SelfOptimization::DecisionType::RESHARD_GPUS: return L"Reshard";
        case SelfOptimization::DecisionType::ADJUST_ROUTING: return L"AdjRoute";
    }
    return L"Unknown";
}

COLORREF SelfOptimizationPanel::GetConfidenceColor(float confidence) {
    if (confidence > 0.8f) return RGB(100, 255, 100);
    if (confidence > 0.5f) return RGB(255, 255, 100);
    return RGB(255, 150, 100);
}

}
