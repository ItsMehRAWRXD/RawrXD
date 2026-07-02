// ==============================================================================
// GhostHUD.cpp — Win32 Profiling HUD Renderer
// ==============================================================================
// Double-buffered GDI rendering. Drains GhostBuffer each frame.
// Compiled with: cl /c /O2 /GS- /GR- /EHsc /Fo GhostHUD.obj
// ==============================================================================

#include "GhostBuffer.hpp"
#include <windows.h>

// HUD dimensions
#define HUD_WIDTH   400
#define HUD_HEIGHT  280
#define LINE_HEIGHT 16

// HUD state (updated by consumer, read by renderer)
struct HUDState {
    bool        loading = false;
    int         load_percent = 0;
    uint64_t    load_bytes = 0;
    uint64_t    load_start_cycles = 0;

    uint64_t    vram_used = 0;
    uint64_t    vram_total = 16ULL * 1024 * 1024 * 1024;
    uint64_t    sys_used = 0;
    uint64_t    sys_total = 64ULL * 1024 * 1024 * 1024;

    bool        inferencing = false;
    uint32_t    tokens_generated = 0;
    uint64_t    infer_start_cycles = 0;
    double      tokens_per_sec = 0.0;

    uint32_t    tasks_pending = 0;
    uint32_t    tasks_running = 0;
    uint32_t    tasks_done = 0;
    uint32_t    tasks_failed = 0;
};

struct LockstepTelemetry {
    uint64_t LocalCRC = 0;
    uint64_t PeerCRC = 0;
    uint32_t DesyncCount = 0;
    int32_t  TickDelta = 0;
};

static HUDState g_HUD;
static LockstepTelemetry g_LockstepTelemetry;
static HDC      g_hdcBack = nullptr;
static HBITMAP  g_hbmBack = nullptr;
static HBITMAP  g_hbmOld = nullptr;

// Forward declarations
static void DrawProgressBar(HDC hdc, int x, int y, int width, int height, int percent);
static void DrawGauge(HDC hdc, int x, int y, int width, int height, uint64_t used, uint64_t total, COLORREF color);

// ==============================================================================
// GhostHUD_Init — Create double buffer
// ==============================================================================
extern "C" __declspec(dllexport) void GhostHUD_Init(HWND hwnd) {
    HDC hdcScreen = GetDC(hwnd);
    g_hdcBack = CreateCompatibleDC(hdcScreen);
    g_hbmBack = CreateCompatibleBitmap(hdcScreen, HUD_WIDTH, HUD_HEIGHT);
    g_hbmOld = (HBITMAP)SelectObject(g_hdcBack, g_hbmBack);
    ReleaseDC(hwnd, hdcScreen);
}

// ==============================================================================
// GhostHUD_Shutdown — Cleanup GDI resources
// ==============================================================================
extern "C" __declspec(dllexport) void GhostHUD_Shutdown() {
    if (g_hdcBack) {
        SelectObject(g_hdcBack, g_hbmOld);
        DeleteObject(g_hbmBack);
        DeleteDC(g_hdcBack);
        g_hdcBack = nullptr;
    }
}

// ==============================================================================
// GhostHUD_Update — Drain telemetry and update state
// ==============================================================================
extern "C" __declspec(dllexport) void GhostHUD_Update() {
    GhostRecord rec;
    uint64_t now = __rdtsc();

    while (g_GhostBuffer.Read(&rec)) {
        switch (rec.event_type) {
            case GHOST_LOAD_START:
                g_HUD.loading = true;
                g_HUD.load_percent = 0;
                g_HUD.load_bytes = 0;
                g_HUD.load_start_cycles = rec.timestamp;
                break;

            case GHOST_LOAD_PROGRESS: {
                uint32_t percent = static_cast<uint32_t>(rec.payload >> 32);
                uint32_t bytes = static_cast<uint32_t>(rec.payload & 0xFFFFFFFF);
                g_HUD.load_percent = static_cast<int>(percent);
                g_HUD.load_bytes = bytes;
                break;
            }

            case GHOST_LOAD_COMPLETE:
                g_HUD.loading = false;
                break;

            case GHOST_VRAM_ALLOC:
                g_HUD.vram_used += rec.payload;
                break;

            case GHOST_VRAM_FREE:
                if (g_HUD.vram_used >= rec.payload)
                    g_HUD.vram_used -= rec.payload;
                break;

            case GHOST_SYS_ALLOC:
                g_HUD.sys_used += rec.payload;
                break;

            case GHOST_INFER_START:
                g_HUD.inferencing = true;
                g_HUD.tokens_generated = 0;
                g_HUD.infer_start_cycles = rec.timestamp;
                break;

            case GHOST_INFER_TOKEN:
                ++g_HUD.tokens_generated;
                if (g_HUD.infer_start_cycles > 0) {
                    uint64_t elapsed = now - g_HUD.infer_start_cycles;
                    double seconds = static_cast<double>(elapsed) / 3.6e9;
                    if (seconds > 0.01) {
                        g_HUD.tokens_per_sec = g_HUD.tokens_generated / seconds;
                    }
                }
                break;

            case GHOST_INFER_COMPLETE:
                g_HUD.inferencing = false;
                break;

            case GHOST_SCHEDULER_TICK:
                g_HUD.tasks_pending = static_cast<uint16_t>(rec.payload >> 48);
                g_HUD.tasks_running = static_cast<uint16_t>(rec.payload >> 32);
                g_HUD.tasks_done    = static_cast<uint16_t>(rec.payload >> 16);
                g_HUD.tasks_failed  = static_cast<uint16_t>(rec.payload);
                break;

            default:
                break;
        }
    }
}

// ==============================================================================
// GhostHUD_SetLockstepTelemetry — Push lockstep drift stats from host loop
// ==============================================================================
extern "C" __declspec(dllexport) void GhostHUD_SetLockstepTelemetry(
    uint64_t localCRC,
    uint64_t peerCRC,
    uint32_t desyncCount,
    int32_t tickDelta) {
    g_LockstepTelemetry.LocalCRC = localCRC;
    g_LockstepTelemetry.PeerCRC = peerCRC;
    g_LockstepTelemetry.DesyncCount = desyncCount;
    g_LockstepTelemetry.TickDelta = tickDelta;
}

// ==============================================================================
// GhostHUD_Render — Draw HUD to target DC at (x,y)
// ==============================================================================
extern "C" __declspec(dllexport) void GhostHUD_Render(HDC hdcTarget, int x, int y) {
    if (!g_hdcBack) return;

    // Clear back buffer
    RECT rcAll = {0, 0, HUD_WIDTH, HUD_HEIGHT};
    FillRect(g_hdcBack, &rcAll, (HBRUSH)GetStockObject(BLACK_BRUSH));

    // Create font
    HFONT hFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    HFONT hOldFont = (HFONT)SelectObject(g_hdcBack, hFont);

    int line = 0;
    char buf[256];
    SetTextColor(g_hdcBack, RGB(0, 255, 0));
    SetBkColor(g_hdcBack, RGB(0, 0, 0));

    // Title
    TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, "SOVEREIGN TELEMETRY", 19);
    line += 2;

    // Load progress
    if (g_HUD.loading) {
        TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, "LOADING MODEL", 13);
        ++line;
        DrawProgressBar(g_hdcBack, 4, line * LINE_HEIGHT, 392, 12, g_HUD.load_percent);

        // Format: " 42% (1234 MB)"
        uint32_t mb = static_cast<uint32_t>(g_HUD.load_bytes / (1024 * 1024));
        int len = wsprintfA(buf, " %d%% (%u MB)", g_HUD.load_percent, mb);
        TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, buf, len);
        line += 2;
    }

    // VRAM gauge
    int len = wsprintfA(buf, "VRAM: %5.1f / %5.1f GB",
              g_HUD.vram_used / (1024.0 * 1024 * 1024),
              g_HUD.vram_total / (1024.0 * 1024 * 1024));
    TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, buf, len);
    ++line;
    DrawGauge(g_hdcBack, 4, line * LINE_HEIGHT, 392, 8,
              g_HUD.vram_used, g_HUD.vram_total, RGB(255, 128, 0));
    ++line;

    // System RAM gauge
    len = wsprintfA(buf, "SYS:  %5.1f / %5.1f GB",
              g_HUD.sys_used / (1024.0 * 1024 * 1024),
              g_HUD.sys_total / (1024.0 * 1024 * 1024));
    TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, buf, len);
    ++line;
    DrawGauge(g_hdcBack, 4, line * LINE_HEIGHT, 392, 8,
              g_HUD.sys_used, g_HUD.sys_total, RGB(0, 128, 255));
    line += 2;

    // Inference stats
    if (g_HUD.inferencing) {
        len = wsprintfA(buf, "INFER: %u tok @ %.1f TPS",
                  g_HUD.tokens_generated, g_HUD.tokens_per_sec);
        SetTextColor(g_hdcBack, RGB(255, 255, 0));
    } else {
        len = wsprintfA(buf, "INFER: IDLE");
        SetTextColor(g_hdcBack, RGB(128, 128, 128));
    }
    TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, buf, len);
    SetTextColor(g_hdcBack, RGB(0, 255, 0));
    ++line;

    // Scheduler stats
    len = wsprintfA(buf, "DAG: P=%u R=%u D=%u F=%u",
              g_HUD.tasks_pending, g_HUD.tasks_running,
              g_HUD.tasks_done, g_HUD.tasks_failed);
    TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, buf, len);
    line += 2;

    len = wsprintfA(buf, "LOCKSTEP: dTick=%d desync=%u",
              g_LockstepTelemetry.TickDelta,
              g_LockstepTelemetry.DesyncCount);
    SetTextColor(g_hdcBack, g_LockstepTelemetry.TickDelta == 0 ? RGB(0, 255, 255) : RGB(255, 96, 96));
    TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, buf, len);
    ++line;

    len = wsprintfA(buf, "LCRC=%016llX PCRC=%016llX",
              g_LockstepTelemetry.LocalCRC,
              g_LockstepTelemetry.PeerCRC);
    SetTextColor(g_hdcBack, g_LockstepTelemetry.LocalCRC == g_LockstepTelemetry.PeerCRC ? RGB(0, 255, 0) : RGB(255, 160, 64));
    TextOutA(g_hdcBack, 4, line * LINE_HEIGHT, buf, len);

    // Cleanup font
    SetTextColor(g_hdcBack, RGB(0, 255, 0));
    SelectObject(g_hdcBack, hOldFont);
    DeleteObject(hFont);

    // Blit to screen
    BitBlt(hdcTarget, x, y, HUD_WIDTH, HUD_HEIGHT, g_hdcBack, 0, 0, SRCCOPY);
}

// ==============================================================================
// Internal: Draw progress bar
// ==============================================================================
static void DrawProgressBar(HDC hdc, int x, int y, int width, int height, int percent) {
    RECT bg = {x, y, x + width, y + height};
    FillRect(hdc, &bg, (HBRUSH)GetStockObject(DKGRAY_BRUSH));

    int fill = (percent * (width - 4)) / 100;
    RECT fg = {x + 2, y + 2, x + 2 + fill, y + height - 2};
    FillRect(hdc, &fg, (HBRUSH)GetStockObject(WHITE_BRUSH));
}

// ==============================================================================
// Internal: Draw usage gauge
// ==============================================================================
static void DrawGauge(HDC hdc, int x, int y, int width, int height, uint64_t used, uint64_t total, COLORREF color) {
    RECT bg = {x, y, x + width, y + height};
    FillRect(hdc, &bg, (HBRUSH)GetStockObject(DKGRAY_BRUSH));

    if (total == 0) return;
    int fill = static_cast<int>((used * (width - 4)) / total);
    if (fill > width - 4) fill = width - 4;

    RECT fg = {x + 2, y + 2, x + 2 + fill, y + height - 2};
    HBRUSH hBrush = CreateSolidBrush(color);
    FillRect(hdc, &fg, hBrush);
    DeleteObject(hBrush);
}
