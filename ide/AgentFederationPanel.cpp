#include "ide/AgentFederationPanel.hpp"
#include "sovereign/Beaconism.hpp"
#include <algorithm>

namespace IDE {

static const wchar_t* CLASS_NAME = L"AgentFederationPanel";

AgentFederationPanel::AgentFederationPanel()
    : m_hwnd(nullptr), m_parent(nullptr), m_visible(false) {
}

AgentFederationPanel::~AgentFederationPanel() {
    Shutdown();
}

bool AgentFederationPanel::Initialize(HWND parent) {
    m_parent = parent;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    m_hwnd = CreateWindowExW(
        0, CLASS_NAME, L"Agent Federation",
        WS_CHILD | WS_CLIPSIBLINGS,
        0, 0, 400, 300,
        parent, nullptr, GetModuleHandle(nullptr), this
    );

    AgentFederation::RegisterAgentCallback(
        [this](const AgentFederation::AgentInfo& info) { OnAgentUpdate(info); }
    );
    AgentFederation::RegisterTokenCallback(
        [this](const AgentFederation::TokenMessage& msg) { OnTokenMessage(msg); }
    );

    return m_hwnd != nullptr;
}

void AgentFederationPanel::Shutdown() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void AgentFederationPanel::Show() {
    m_visible = true;
    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
}

void AgentFederationPanel::Hide() {
    m_visible = false;
    ShowWindow(m_hwnd, SW_HIDE);
}

bool AgentFederationPanel::IsVisible() const {
    return m_visible;
}

void AgentFederationPanel::SetBounds(int x, int y, int width, int height) {
    SetWindowPos(m_hwnd, nullptr, x, y, width, height, SWP_NOZORDER);
}

void AgentFederationPanel::Update() {
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void AgentFederationPanel::OnAgentUpdate(const AgentFederation::AgentInfo& info) {
    auto it = std::find_if(m_agents.begin(), m_agents.end(),
        [&](const AgentFederation::AgentInfo& a) { return a.id == info.id; });
    if (it != m_agents.end()) {
        *it = info;
    } else {
        m_agents.push_back(info);
    }
    Update();
}

void AgentFederationPanel::OnTokenMessage(const AgentFederation::TokenMessage& msg) {
    m_recentTokens.push_back(msg);
    if (m_recentTokens.size() > 20) {
        m_recentTokens.erase(m_recentTokens.begin());
    }
    Update();
}

bool AgentFederationPanel::IsWired() {
    return true; // Panel is wired if it exists
}

LRESULT CALLBACK AgentFederationPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AgentFederationPanel* panel = nullptr;
    if (msg == WM_CREATE) {
        panel = static_cast<AgentFederationPanel*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<AgentFederationPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
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

void AgentFederationPanel::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);

    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &rc, bgBrush);
    DeleteObject(bgBrush);

    SetTextColor(hdc, RGB(100, 200, 255));
    SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, 20, 10, L"Agent Federation", 16);

    int y = 40;
    for (const auto& agent : m_agents) {
        DrawAgent(hdc, 20, y, agent);
        y += 35;
        if (y > rc.bottom - 60) break;
    }

    SetTextColor(hdc, RGB(150, 150, 150));
    wchar_t buf[64];
    swprintf_s(buf, L"Recent tokens: %zu", m_recentTokens.size());
    TextOutW(hdc, 20, rc.bottom - 25, buf, (int)wcslen(buf));
}

void AgentFederationPanel::DrawAgent(HDC hdc, int x, int y, const AgentFederation::AgentInfo& agent) {
    COLORREF color = GetStateColor(agent.state);
    HBRUSH brush = CreateSolidBrush(color);
    RECT rc = {x, y, x + 15, y + 15};
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);

    wchar_t buf[256];
    std::wstring name(agent.name.begin(), agent.name.end());
    const wchar_t* stateStr = L"Unknown";
    switch (agent.state) {
        case AgentFederation::AgentState::IDLE: stateStr = L"IDLE"; break;
        case AgentFederation::AgentState::PROCESSING: stateStr = L"PROC"; break;
        case AgentFederation::AgentState::WAITING_KV: stateStr = L"WAIT"; break;
        case AgentFederation::AgentState::ERROR: stateStr = L"ERR"; break;
    }
    swprintf_s(buf, L"[%llu] %s - %s", agent.id, name.c_str(), stateStr);

    SetTextColor(hdc, RGB(220, 220, 220));
    TextOutW(hdc, x + 20, y, buf, (int)wcslen(buf));
}

COLORREF AgentFederationPanel::GetStateColor(AgentFederation::AgentState state) {
    switch (state) {
        case AgentFederation::AgentState::IDLE: return RGB(100, 200, 100);
        case AgentFederation::AgentState::PROCESSING: return RGB(255, 200, 100);
        case AgentFederation::AgentState::WAITING_KV: return RGB(100, 150, 255);
        case AgentFederation::AgentState::ERROR: return RGB(255, 80, 80);
    }
    return RGB(150, 150, 150);
}

}
