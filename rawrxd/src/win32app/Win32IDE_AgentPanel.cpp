// Win32IDE_AgentPanel.cpp — agentic loop UI: plan steps, tool calls, sub-agent status
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>

namespace RawrXD::IDE {

HFONT IDECore_UIFont();
HFONT IDECore_MonoFont();

enum class StepState { Pending, Running, Done, Failed };

struct AgentStep {
    std::string label;
    StepState   state = StepState::Pending;
    std::string detail;
};

struct AgentPanelState {
    HWND hwnd = nullptr;
    std::vector<AgentStep> steps;
    std::string currentTask;
    int scrollOffset = 0;
    bool active = false;
};

static AgentPanelState g_agentPanel;

static COLORREF stepColor(StepState s) {
    switch (s) {
        case StepState::Running: return RGB(0, 200, 255);
        case StepState::Done:    return RGB(100, 200, 100);
        case StepState::Failed:  return RGB(220, 80, 80);
        default:                 return RGB(150, 150, 150);
    }
}

static const char* stepIcon(StepState s) {
    switch (s) {
        case StepState::Running: return ">";
        case StepState::Done:    return "v";
        case StepState::Failed:  return "x";
        default:                 return "o";
    }
}

static void AgentPanelPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP old = (HBITMAP)SelectObject(mem, bmp);

    HBRUSH bg = CreateSolidBrush(RGB(37, 37, 38));
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    HFONT font = IDECore_UIFont();
    HFONT oldFont = (HFONT)SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);

    const int lineH = 22, padX = 8;
    int y = padX - g_agentPanel.scrollOffset;

    // Header
    SetTextColor(mem, RGB(0, 122, 204));
    RECT hdrRc = {padX, y, W - padX, y + lineH};
    std::string hdr = g_agentPanel.active ? "Agent: " + g_agentPanel.currentTask : "Agent (idle)";
    DrawTextA(mem, hdr.c_str(), -1, &hdrRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    y += lineH + 4;

    // Separator
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
    HPEN oldPen = (HPEN)SelectObject(mem, pen);
    MoveToEx(mem, padX, y, nullptr); LineTo(mem, W - padX, y);
    SelectObject(mem, oldPen); DeleteObject(pen);
    y += 6;

    // Steps
    for (auto& step : g_agentPanel.steps) {
        if (y > H) break;
        SetTextColor(mem, stepColor(step.state));
        char buf[512];
        snprintf(buf, sizeof(buf), " %s  %s", stepIcon(step.state), step.label.c_str());
        RECT stepRc = {padX, y, W - padX, y + lineH};
        DrawTextA(mem, buf, -1, &stepRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        y += lineH;

        if (!step.detail.empty()) {
            SetTextColor(mem, RGB(130, 130, 130));
            HFONT mono = IDECore_MonoFont();
            SelectObject(mem, mono);
            RECT detRc = {padX + 24, y, W - padX, y + lineH};
            DrawTextA(mem, step.detail.c_str(), -1, &detRc, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
            SelectObject(mem, font);
            y += lineH;
        }
    }

    SelectObject(mem, oldFont);
    BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK AgentPanelWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT:      AgentPanelPaint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g_agentPanel.scrollOffset -= delta / WHEEL_DELTA * 30;
        g_agentPanel.scrollOffset = std::max(0, g_agentPanel.scrollOffset);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_SIZE: InvalidateRect(hwnd, nullptr, FALSE); return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

void AgentPanel_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = AgentPanelWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDAgentPanel";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExA(&wc);
}

HWND AgentPanel_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_agentPanel.hwnd = CreateWindowExA(0, "RawrXDAgentPanel", nullptr,
        WS_CHILD | WS_VISIBLE, x, y, w, h, parent, nullptr, hInst, nullptr);
    return g_agentPanel.hwnd;
}

void AgentPanel_SetTask(const std::string& task)
{
    g_agentPanel.currentTask = task;
    g_agentPanel.active = !task.empty();
    if (g_agentPanel.hwnd) InvalidateRect(g_agentPanel.hwnd, nullptr, FALSE);
}

void AgentPanel_AddStep(const std::string& label)
{
    AgentStep s; s.label = label; s.state = StepState::Pending;
    g_agentPanel.steps.push_back(s);
    if (g_agentPanel.hwnd) InvalidateRect(g_agentPanel.hwnd, nullptr, FALSE);
}

void AgentPanel_SetStepState(int idx, StepState state, const std::string& detail)
{
    if (idx >= 0 && idx < (int)g_agentPanel.steps.size()) {
        g_agentPanel.steps[idx].state  = state;
        g_agentPanel.steps[idx].detail = detail;
        if (g_agentPanel.hwnd) InvalidateRect(g_agentPanel.hwnd, nullptr, FALSE);
    }
}

void AgentPanel_Clear()
{
    g_agentPanel.steps.clear();
    g_agentPanel.currentTask.clear();
    g_agentPanel.active = false;
    if (g_agentPanel.hwnd) InvalidateRect(g_agentPanel.hwnd, nullptr, FALSE);
}

} // namespace RawrXD::IDE
