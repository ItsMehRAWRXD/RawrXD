#include "ide/SovereignFabricMonitor.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/GlobalAttentionRouter.hpp"
#include <cmath>

namespace IDE {

static const wchar_t* CLASS_NAME = L"SovereignFabricMonitor";

SovereignFabricMonitor::SovereignFabricMonitor()
    : m_hwnd(nullptr), m_parent(nullptr), m_visible(false) {
}

SovereignFabricMonitor::~SovereignFabricMonitor() {
    Shutdown();
}

bool SovereignFabricMonitor::Initialize(HWND parent) {
    m_parent = parent;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hbrBackground = CreateSolidBrush(RGB(20, 20, 30));
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    m_hwnd = CreateWindowExW(
        0, CLASS_NAME, L"Sovereign Fabric Monitor",
        WS_CHILD | WS_CLIPSIBLINGS,
        0, 0, 800, 600,
        parent, nullptr, GetModuleHandle(nullptr), this
    );

    LayoutNodes();
    return m_hwnd != nullptr;
}

void SovereignFabricMonitor::Shutdown() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void SovereignFabricMonitor::Show() {
    m_visible = true;
    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
}

void SovereignFabricMonitor::Hide() {
    m_visible = false;
    ShowWindow(m_hwnd, SW_HIDE);
}

bool SovereignFabricMonitor::IsVisible() const {
    return m_visible;
}

void SovereignFabricMonitor::SetBounds(int x, int y, int width, int height) {
    SetWindowPos(m_hwnd, nullptr, x, y, width, height, SWP_NOZORDER);
}

void SovereignFabricMonitor::Update() {
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void SovereignFabricMonitor::OnNodeUpdate(const std::string& nodeId, float load, bool online) {
    auto& node = m_nodes[nodeId];
    node.id = nodeId;
    node.load = load;
    node.online = online;
    Update();
}

void SovereignFabricMonitor::OnLinkUpdate(const std::string& from, const std::string& to, float bandwidth, float latency) {
    bool found = false;
    for (auto& link : m_links) {
        if (link.from == from && link.to == to) {
            link.bandwidth = bandwidth;
            link.latency = latency;
            found = true;
            break;
        }
    }
    if (!found) {
        FabricLinkVisual link{from, to, bandwidth, latency, true};
        m_links.push_back(link);
    }
    Update();
}

bool SovereignFabricMonitor::IsWired() {
    return true; // Panel is wired if it exists
}

LRESULT CALLBACK SovereignFabricMonitor::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    SovereignFabricMonitor* monitor = nullptr;
    if (msg == WM_CREATE) {
        monitor = static_cast<SovereignFabricMonitor*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(monitor));
    } else {
        monitor = reinterpret_cast<SovereignFabricMonitor*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            if (monitor) monitor->Render(hdc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void SovereignFabricMonitor::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);

    HBRUSH bgBrush = CreateSolidBrush(RGB(20, 20, 30));
    FillRect(hdc, &rc, bgBrush);
    DeleteObject(bgBrush);

    SetTextColor(hdc, RGB(100, 200, 255));
    SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, 20, 10, L"Sovereign Fabric Topology", 25);

    for (const auto& [id, node] : m_nodes) {
        DrawNode(hdc, node);
    }

    for (const auto& link : m_links) {
        DrawLink(hdc, link);
    }

    wchar_t buf[256];
    swprintf_s(buf, L"Nodes: %zu | Links: %zu", m_nodes.size(), m_links.size());
    SetTextColor(hdc, RGB(150, 150, 150));
    TextOutW(hdc, 20, rc.bottom - 25, buf, (int)wcslen(buf));
}

void SovereignFabricMonitor::DrawNode(HDC hdc, const FabricNodeVisual& node) {
    int x = static_cast<int>(node.x);
    int y = static_cast<int>(node.y);
    int size = 30;

    COLORREF color = node.online ?
        (node.load > 0.8f ? RGB(255, 100, 100) :
         node.load > 0.5f ? RGB(255, 200, 100) :
                           RGB(100, 255, 150)) :
        RGB(100, 100, 100);

    HBRUSH brush = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(200, 200, 200));
    SelectObject(hdc, brush);
    SelectObject(hdc, pen);

    Ellipse(hdc, x - size/2, y - size/2, x + size/2, y + size/2);

    DeleteObject(brush);
    DeleteObject(pen);

    std::wstring idWide(node.id.begin(), node.id.end());
    SetTextColor(hdc, RGB(220, 220, 220));
    TextOutW(hdc, x - 20, y + size/2 + 5, idWide.c_str(), (int)idWide.length());
}

void SovereignFabricMonitor::DrawLink(HDC hdc, const FabricLinkVisual& link) {
    auto fromIt = m_nodes.find(link.from);
    auto toIt = m_nodes.find(link.to);
    if (fromIt == m_nodes.end() || toIt == m_nodes.end()) return;

    int x1 = static_cast<int>(fromIt->second.x);
    int y1 = static_cast<int>(fromIt->second.y);
    int x2 = static_cast<int>(toIt->second.x);
    int y2 = static_cast<int>(toIt->second.y);

    COLORREF color = link.latency < 10.0f ? RGB(100, 255, 100) :
                     link.latency < 50.0f ? RGB(255, 255, 100) :
                                            RGB(255, 100, 100);

    HPEN pen = CreatePen(PS_SOLID, static_cast<int>(link.bandwidth / 10.0f) + 1, color);
    SelectObject(hdc, pen);

    MoveToEx(hdc, x1, y1, nullptr);
    LineTo(hdc, x2, y2);

    DeleteObject(pen);
}

void SovereignFabricMonitor::LayoutNodes() {
    auto nodes = GlobalAttentionRouter::GetClusterNodes();
    float centerX = 400.0f;
    float centerY = 300.0f;
    float radius = 200.0f;

    int i = 0;
    for (const auto& nodeId : nodes) {
        float angle = (2.0f * 3.14159f * i) / std::max(1, (int)nodes.size());
        m_nodes[nodeId].id = nodeId;
        m_nodes[nodeId].x = centerX + radius * cosf(angle);
        m_nodes[nodeId].y = centerY + radius * sinf(angle);
        m_nodes[nodeId].online = true;
        m_nodes[nodeId].load = 0.5f;
        i++;
    }

    if (m_nodes.empty()) {
        m_nodes["local"].id = "local";
        m_nodes["local"].x = centerX;
        m_nodes["local"].y = centerY;
        m_nodes["local"].online = true;
        m_nodes["local"].load = 0.5f;
    }
}

}
