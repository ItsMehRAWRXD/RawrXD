// Win32IDE_AgentPanel.cpp — agentic loop UI: plan steps, tool calls, sub-agent status
#include <windows.h>
#include <atomic>
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

// RAWRXD_IDE_AGENT_PANEL_MARSHAL_001
// Declared here because AgentPanelWndProc (below) dispatches this message and
// applies the payload, while the marshalling helpers that produce it are defined
// further down. Both the message constant and the applier must be visible
// before the WndProc that switches on them.
#define AGENT_PANEL_WM_APPLY (WM_APP + 0x141)
struct AgentPanelPayload;
static void AgentPanel_ApplyOnOwnerThread(AgentPanelPayload* p);

// The window handle is read by the worker thread (to PostMessage) and written by
// the owner thread (on create/destroy), so it needs atomic access rather than a
// bare HWND read. g_agentPanel.hwnd stays for owner-thread use only -- the paint
// and apply paths all run on the owner thread -- and must never be read off it.
static std::atomic<HWND> g_agentPanelHwnd{nullptr};

// RAWRXD_IDE_AGENT_PANEL_SHUTDOWN_RACE_001
//
// Unpublishing the HWND before draining narrows the producer window but does not
// close it: a worker that loaded H microseconds before the store can still be
// between the load and its PostMessage, so the drain can complete before that
// post lands, leaking the payload.
//
// This counter closes it. A producer increments BEFORE it loads the handle and
// decrements AFTER its post returns. WM_DESTROY unpublishes, then waits for the
// count to reach zero, then drains. Because PostMessageA never blocks and the
// producer never waits on the UI thread, the wait is bounded and cannot deadlock:
// every in-flight producer completes on its own.
//
// Ordering matters in both directions. Increment-before-load is what makes the
// store->load in WM_DESTROY sufficient: any producer that observes the old handle
// is already counted.
static std::atomic<int> g_marshalInFlight{0};

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
    // RAWRXD_IDE_AGENT_PANEL_MARSHAL_001: worker-thread posts land here, on the
    // owner thread, which is the only place g_agentPanel is mutated.
    case AGENT_PANEL_WM_APPLY:
        AgentPanel_ApplyOnOwnerThread((AgentPanelPayload*)lParam);
        return 0;

    // RAWRXD_IDE_AGENT_PANEL_MARSHAL_001: payload lifetime on destruction.
    //
    // PostMessageA transfers the application's conceptual ownership of the
    // payload but Windows does NOT free it. AgentPanel_ApplyOnOwnerThread is
    // the one and only delete for a successful post -- but if the window is
    // destroyed while AGENT_PANEL_WM_APPLY messages are still queued, the
    // handler will never run and every queued payload leaks. A tool burst
    // followed immediately by IDE shutdown would leak them silently.
    //
    // WM_DESTROY is the last point at which the thread queue is still ours to
    // drain, so the remaining payloads are reclaimed here rather than left to
    // a handler that can no longer be reached.
    case WM_DESTROY: {
        // RAWRXD_IDE_AGENT_PANEL_SHUTDOWN_RACE_001
        //
        // Unpublish FIRST, then quiesce, then drain. The quiesce is what turns
        // "narrowed" into "closed": a worker that loaded H just before the store
        // is already counted in g_marshalInFlight, and its PostMessage either
        // succeeded (so the drain below finds it) or failed (so it freed the
        // payload itself). Draining without waiting would miss both.
        //
        // This cannot deadlock. PostMessageA does not block and the producer
        // never waits on the UI thread, so every counted producer terminates on
        // its own. Sleep(0) yields rather than spinning hot; the wait is bounded
        // by the length of a single PostMessageA call.
        g_agentPanelHwnd.store(nullptr, std::memory_order_release);
        g_agentPanel.hwnd = nullptr;          // owner-thread view

        while (g_marshalInFlight.load(std::memory_order_acquire) > 0) {
            Sleep(0);
        }

        MSG m{};
        while (PeekMessageA(&m, hwnd, AGENT_PANEL_WM_APPLY, AGENT_PANEL_WM_APPLY,
                            PM_REMOVE)) {
            delete reinterpret_cast<AgentPanelPayload*>(m.lParam);
        }
        return 0;
    }
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
    // Publish only after CreateWindowExA returns, so a worker that observes the
    // handle also observes a window that can accept the post.
    g_agentPanelHwnd.store(g_agentPanel.hwnd, std::memory_order_release);
    return g_agentPanel.hwnd;
    }

// ---------------------------------------------------------------------------
// RAWRXD_IDE_AGENT_PANEL_MARSHAL_001
//
// The agentic observer runs on the chat worker thread. Before this change it
// called AgentPanel_SetTask / AgentPanel_AddStep directly, which mutated
// g_agentPanel.steps -- an unsynchronized std::vector -- while the UI thread
// painted it. That is undefined behaviour: reallocation during iteration, torn
// reads, heap corruption.
//
// A mutex would have fixed mutual exclusion but not thread affinity, and
// AgentPanel is Win32 UI state. So the results are MARSHALED to the owner
// thread instead: the worker posts an owned payload, and the panel state is
// mutated only inside the panel's own WndProc.
//
// The payload carries its own strings by value; the heap block is freed by the
// UI thread after it is applied, so there is no shared ownership and nothing to
// lock.
// ---------------------------------------------------------------------------
struct AgentPanelPayload {
    enum class Kind { SetTask, AddStep, Clear, SetStepState };
    Kind        kind;
    std::string text;
    // SetStepState only. stepState stays Pending for the other kinds, so a
    // payload is always fully initialised before the post.
    int         index = -1;
    StepState   stepState = StepState::Pending;
};

// Owner-thread entry point. Applies one payload and repaints. Never called from
// the worker.
static void AgentPanel_ApplyOnOwnerThread(AgentPanelPayload* p)
{
    if (!p) return;
    switch (p->kind) {
        case AgentPanelPayload::Kind::SetTask:
            g_agentPanel.currentTask = p->text;
            g_agentPanel.active = !p->text.empty();
            break;
        case AgentPanelPayload::Kind::AddStep: {
            AgentStep s;
            s.label = p->text;
            s.state = StepState::Pending;
            g_agentPanel.steps.push_back(s);
            break;
        }
        case AgentPanelPayload::Kind::Clear:
            g_agentPanel.steps.clear();
            g_agentPanel.currentTask.clear();
            g_agentPanel.active = false;
            break;
        case AgentPanelPayload::Kind::SetStepState:
            if (p->index >= 0 && p->index < (int)g_agentPanel.steps.size()) {
                g_agentPanel.steps[p->index].state  = p->stepState;
                g_agentPanel.steps[p->index].detail = p->text;
            }
            break;
    }
    delete p;
    if (g_agentPanel.hwnd) InvalidateRect(g_agentPanel.hwnd, nullptr, FALSE);
}

// Callable from any thread. Marshals to the owner thread; if the panel has not
// been created yet the update is dropped rather than applied off-thread, because
// there is no window to post to and applying it here would reintroduce the race.
static void AgentPanel_Marshal(AgentPanelPayload* p)
{
    if (!p) return;
    // Counted in BEFORE the handle load, and out AFTER the post returns. See the
    // g_marshalInFlight comment for why that pairing is what lets WM_DESTROY
    // safely quiesce before draining.
    g_marshalInFlight.fetch_add(1, std::memory_order_acq_rel);

    const HWND hwnd = g_agentPanelHwnd.load(std::memory_order_acquire);
    if (!hwnd) {
        g_marshalInFlight.fetch_sub(1, std::memory_order_acq_rel);
        delete p;
        return;
    }

    const BOOL posted = PostMessageA(hwnd, AGENT_PANEL_WM_APPLY, 0, (LPARAM)p);

    g_marshalInFlight.fetch_sub(1, std::memory_order_acq_rel);

    // Failed post frees here. Successful post transfers ownership to the owner
    // thread, which deletes in AgentPanel_ApplyOnOwnerThread -- or, if the window
    // died first, in the WM_DESTROY drain. Exactly one delete on every path.
    if (!posted) delete p;
}

void AgentPanel_SetTask(const std::string& task)
{
    AgentPanelPayload* p = new AgentPanelPayload();
    p->kind = AgentPanelPayload::Kind::SetTask;
    p->text = task;
    AgentPanel_Marshal(p);
}

void AgentPanel_AddStep(const std::string& label)
{
    AgentPanelPayload* p = new AgentPanelPayload();
    p->kind = AgentPanelPayload::Kind::AddStep;
    p->text = label;
    AgentPanel_Marshal(p);
}

void AgentPanel_Clear()
{
    AgentPanelPayload* p = new AgentPanelPayload();
    p->kind = AgentPanelPayload::Kind::Clear;
    AgentPanel_Marshal(p);
}

void AgentPanel_SetStepState(int idx, StepState state, const std::string& detail)
{
    // RAWRXD_IDE_AGENT_PANEL_MARSHAL_001: this had no callers and mutated
    // g_agentPanel.steps directly, which is precisely the off-thread vector
    // write the rest of this file was changed to forbid. Leaving it would have
    // made the file's invariant false: any future caller reaching it from a
    // worker would reintroduce the race with no compiler or runtime signal.
    // It goes through the same AgentPanel_Marshal path so the in-flight count
    // covers it too.
    AgentPanelPayload* p = new AgentPanelPayload();
    p->kind      = AgentPanelPayload::Kind::SetStepState;
    p->index     = idx;
    p->stepState = state;
    p->text      = detail;
    AgentPanel_Marshal(p);
}

} // namespace RawrXD::IDE
