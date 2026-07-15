#include "ide/MemoryLakePanel.hpp"
#include "sovereign/Beaconism.hpp"
#include <algorithm>

namespace IDE {

static const wchar_t* CLASS_NAME = L"MemoryLakePanel";

MemoryLakePanel::MemoryLakePanel()
    : m_hwnd(nullptr), m_parent(nullptr), m_visible(false) {
}

MemoryLakePanel::~MemoryLakePanel() {
    Shutdown();
}

bool MemoryLakePanel::Initialize(HWND parent) {
    m_parent = parent;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    m_hwnd = CreateWindowExW(
        0, CLASS_NAME, L"Memory Lake",
        WS_CHILD | WS_CLIPSIBLINGS,
        0, 0, 400, 300,
        parent, nullptr, GetModuleHandle(nullptr), this
    );

    MemoryLake::RegisterStateCallback(
        [this](const MemoryLake::LakeState& s) { OnStateUpdate(s); }
    );
    MemoryLake::RegisterSegmentCallback(
        [this](const MemoryLake::SegmentInfo& seg) { OnSegmentUpdate(seg); }
    );

    return m_hwnd != nullptr;
}

void MemoryLakePanel::Shutdown() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void MemoryLakePanel::Show() {
    m_visible = true;
    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
}

void MemoryLakePanel::Hide() {
    m_visible = false;
    ShowWindow(m_hwnd, SW_HIDE);
}

bool MemoryLakePanel::IsVisible() const {
    return m_visible;
}

void MemoryLakePanel::SetBounds(int x, int y, int width, int height) {
    SetWindowPos(m_hwnd, nullptr, x, y, width, height, SWP_NOZORDER);
}

void MemoryLakePanel::Update() {
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void MemoryLakePanel::OnStateUpdate(const MemoryLake::LakeState& state) {
    m_currentState = state;
    Update();
}

void MemoryLakePanel::OnSegmentUpdate(const MemoryLake::SegmentInfo& segment) {
    auto it = std::find_if(m_segments.begin(), m_segments.end(),
        [&](const MemoryLake::SegmentInfo& s) { return s.id == segment.id; });
    if (it != m_segments.end()) {
        *it = segment;
    } else {
        m_segments.push_back(segment);
    }
    if (m_segments.size() > 50) {
        m_segments.erase(m_segments.begin());
    }
    Update();
}

bool MemoryLakePanel::IsWired() {
    return true; // Panel is wired if it exists
}

LRESULT CALLBACK MemoryLakePanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MemoryLakePanel* panel = nullptr;
    if (msg == WM_CREATE) {
        panel = static_cast<MemoryLakePanel*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<MemoryLakePanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
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

void MemoryLakePanel::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);

    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &rc, bgBrush);
    DeleteObject(bgBrush);

    SetTextColor(hdc, RGB(100, 200, 255));
    SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, 20, 10, L"Memory Lake", 11);

    uint64_t total = m_currentState.hotBytes + m_currentState.warmBytes +
                     m_currentState.coldBytes + m_currentState.archivalBytes;
    if (total == 0) total = 1;

    int barWidth = rc.right - 60;
    int y = 50;

    DrawTierBar(hdc, 30, y, barWidth, m_currentState.hotBytes, RGB(255, 100, 100), L"Hot");
    y += 40;
    DrawTierBar(hdc, 30, y, barWidth, m_currentState.warmBytes, RGB(255, 200, 100), L"Warm");
    y += 40;
    DrawTierBar(hdc, 30, y, barWidth, m_currentState.coldBytes, RGB(100, 200, 255), L"Cold");
    y += 40;
    DrawTierBar(hdc, 30, y, barWidth, m_currentState.archivalBytes, RGB(150, 150, 150), L"Archival");

    wchar_t buf[256];
    swprintf_s(buf, L"Segments: %zu", m_segments.size());
    SetTextColor(hdc, RGB(200, 200, 200));
    TextOutW(hdc, 30, y + 50, buf, (int)wcslen(buf));
}

void MemoryLakePanel::DrawTierBar(HDC hdc, int x, int y, int width, uint64_t bytes, COLORREF color, const wchar_t* label) {
    uint64_t maxBytes = 1024ULL * 1024 * 1024;
    int fillWidth = static_cast<int>((bytes * width) / maxBytes);
    fillWidth = std::min(fillWidth, width);

    HBRUSH brush = CreateSolidBrush(color);
    RECT rc = {x, y, x + fillWidth, y + 25};
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);

    HPEN pen = CreatePen(PS_SOLID, 1, RGB(100, 100, 100));
    SelectObject(hdc, pen);
    Rectangle(hdc, x, y, x + width, y + 25);
    DeleteObject(pen);

    wchar_t buf[64];
    swprintf_s(buf, L"%s: %llu MB", label, bytes / (1024 * 1024));
    SetTextColor(hdc, RGB(220, 220, 220));
    TextOutW(hdc, x, y - 18, buf, (int)wcslen(buf));
}

}
