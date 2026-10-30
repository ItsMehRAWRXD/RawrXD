#include "terrain_studio.hpp"
#include <windows.h>
#include <cmath>
#include <cstdio>
#include <cstring>

static HWND gCursor = nullptr;
void studioMoveCursor(HWND owner, int x, int y) {
    if (!owner) return;
    if (!studioBrushOn()) { if (gCursor) ShowWindow(gCursor, SW_HIDE); return; }
    if (!gCursor) {
        gCursor = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
            L"STATIC", L"", WS_POPUP, 0, 0, 32, 32, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
        SetLayeredWindowAttributes(gCursor, RGB(255, 0, 255), 0, LWA_COLORKEY);
    }
    const StudioBrush& b = studioBrush();
    int d = static_cast<int>(b.radius); if (d < 16) d = 16; if (d > 240) d = 240;
    float half = b.falloff > 0.1f ? std::pow(0.5f, 1.0f / b.falloff) : 0.5f;
    int inner = static_cast<int>(d * (1.0f - half)); if (inner < 6) inner = 6; if (inner > d - 4) inner = d - 4;
    POINT p{x, y}; ClientToScreen(owner, &p);
    SetWindowPos(gCursor, HWND_TOPMOST, p.x - d / 2, p.y - d / 2, d, d, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    HDC dc = GetDC(gCursor);
    RECT rc{0, 0, d, d}; HBRUSH mag = CreateSolidBrush(RGB(255, 0, 255));
    FillRect(dc, &rc, mag); DeleteObject(mag);
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(255, 214, 64));
    HGDIOBJ old = SelectObject(dc, pen); SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
    Ellipse(dc, 1, 1, d - 2, d - 2);
    Ellipse(dc, (d - inner) / 2, (d - inner) / 2, (d + inner) / 2, (d + inner) / 2);
    SelectObject(dc, old); DeleteObject(pen); ReleaseDC(gCursor, dc);
}
bool studioCaptureCursor(const char* path) {
    if (!gCursor || !IsWindowVisible(gCursor)) return false;
    RECT rc{}; GetWindowRect(gCursor, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    if (w < 8 || h < 8) return false;
    HDC screen = GetDC(gCursor), mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    HGDIOBJ old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY);
    BITMAPINFO info{}; info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = w; info.bmiHeader.biHeight = h;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 24;
    int stride = (w * 3 + 3) & ~3;
    unsigned char* px = new unsigned char[stride * h];
    GetDIBits(mem, bmp, 0, h, px, &info, DIB_RGB_COLORS);
    FILE* f = nullptr; fopen_s(&f, path, "wb");
    bool wrote = false;
    if (f) {
        unsigned char hdr[54]{}; hdr[0] = 'B'; hdr[1] = 'M';
        int size = 54 + stride * h; std::memcpy(hdr + 2, &size, 4);
        int off = 54; std::memcpy(hdr + 10, &off, 4);
        int hs = 40; std::memcpy(hdr + 14, &hs, 4);
        std::memcpy(hdr + 18, &w, 4); std::memcpy(hdr + 22, &h, 4);
        short planes = 1, bits = 24; std::memcpy(hdr + 26, &planes, 2); std::memcpy(hdr + 28, &bits, 2);
        std::fwrite(hdr, 1, 54, f); std::fwrite(px, 1, stride * h, f); wrote = true; std::fclose(f);
    }
    delete[] px; SelectObject(mem, old); DeleteObject(bmp); DeleteDC(mem); ReleaseDC(gCursor, screen);
    return wrote;
}
