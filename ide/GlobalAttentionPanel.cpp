#include "ide/GlobalAttentionPanel.hpp"
#include "sovereign/Beaconism.hpp"
#include <algorithm>

namespace IDE {

static const wchar_t* CLASS_NAME = L"GlobalAttentionPanel";

GlobalAttentionPanel::GlobalAttentionPanel()
    : m_hwnd(nullptr), m_parent(nullptr), m_visible(false) {
    for (int i = 0; i < 6; ++i) {
        m_stages.push_back({static_cast<GlobalAttentionRouter::AttentionStage>(i), 0.0f, 0, false});
    }
}

GlobalAttentionPanel::~GlobalAttentionPanel() {
    Shutdown();
}

bool GlobalAttentionPanel::Initialize(HWND parent) {
    m_parent = parent;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    m_hwnd = CreateWindowExW(
        0, CLASS_NAME, L"Global Attention Router",
        WS_CHILD | WS_CLIPSIBLINGS,
        0, 0, 400, 300,
        parent, nullptr, GetModuleHandle(nullptr), this
    );

    GlobalAttentionRouter::RegisterRoutingCallback(
        [this](const GlobalAttentionRouter::RoutingRecord& rec) { OnRoutingEvent(rec); }
    );
    GlobalAttentionRouter::RegisterErrorCallback(
        [this](const std::string& error, GlobalAttentionRouter::AttentionStage stage) { OnErrorEvent(error, stage); }
    );

    return m_hwnd != nullptr;
}

void GlobalAttentionPanel::Shutdown() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void GlobalAttentionPanel::Show() {
    m_visible = true;
    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
}

void GlobalAttentionPanel::Hide() {
    m_visible = false;
    ShowWindow(m_hwnd, SW_HIDE);
}

bool GlobalAttentionPanel::IsVisible() const {
    return m_visible;
}

void GlobalAttentionPanel::SetBounds(int x, int y, int width, int height) {
    SetWindowPos(m_hwnd, nullptr, x, y, width, height, SWP_NOZORDER);
}

void GlobalAttentionPanel::Update() {
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void GlobalAttentionPanel::OnRoutingEvent(const GlobalAttentionRouter::RoutingRecord& rec) {
    int idx = static_cast<int>(rec.stage);
    if (idx >= 0 && idx < static_cast<int>(m_stages.size())) {
        m_stages[idx].latency = rec.latencyMs;
        m_stages[idx].timestamp = rec.timestamp;
        m_stages[idx].active = true;
        Update();
    }
}

void GlobalAttentionPanel::OnErrorEvent(const std::string& error, GlobalAttentionRouter::AttentionStage stage) {
    Beaconism::Emit(Beaconism::BEACON_UIEvent, {{"panel", "GlobalAttention"}, {"error", error}});
}

bool GlobalAttentionPanel::IsWired() {
    return true; // Panel is wired if it exists
}

LRESULT CALLBACK GlobalAttentionPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GlobalAttentionPanel* panel = nullptr;
    if (msg == WM_CREATE) {
        panel = static_cast<GlobalAttentionPanel*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<GlobalAttentionPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
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

void GlobalAttentionPanel::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);

    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &rc, bgBrush);
    DeleteObject(bgBrush);

    const wchar_t* labels[] = {L"Q", L"K", L"V", L"QK", L"Softmax", L"Output"};
    int x = 20, y = 50;
    for (size_t i = 0; i < m_stages.size(); ++i) {
        DrawStage(hdc, x + (int)(i * 60), y, m_stages[i]);
        SetTextColor(hdc, RGB(200, 200, 200));
        SetBkMode(hdc, TRANSPARENT);
        TextOutW(hdc, x + (int)(i * 60), y + 40, labels[i], (int)wcslen(labels[i]));
    }

    SetTextColor(hdc, RGB(100, 200, 255));
    TextOutW(hdc, 20, 10, L"Global Attention Router", 23);
}

void GlobalAttentionPanel::DrawStage(HDC hdc, int x, int y, const StageVisual& stage) {
    COLORREF color = stage.active ? RGB(0, 200, 100) : RGB(80, 80, 80);
    if (stage.latency > 50.0f) color = RGB(200, 100, 0);
    if (stage.latency > 100.0f) color = RGB(200, 50, 50);

    HBRUSH brush = CreateSolidBrush(color);
    RECT rc = {x, y, x + 40, y + 30};
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);

    HPEN pen = CreatePen(PS_SOLID, 1, RGB(150, 150, 150));
    SelectObject(hdc, pen);
    Rectangle(hdc, x, y, x + 40, y + 30);
    DeleteObject(pen);
}

}
