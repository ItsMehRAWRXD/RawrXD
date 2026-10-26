#include "editor_api.hpp"
#include <cstdio>
#include <cstring>
#include <windows.h>

HWND inspectorPanel();
bool inspectorCapture(const char* path) {
    HWND panel = inspectorPanel();
    if (!panel) return false;
    RECT rc{}; GetWindowRect(panel, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    if (w < 8 || h < 8) return false;
    HDC screen = GetDC(nullptr), mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    HGDIOBJ old = SelectObject(mem, bmp);
    BOOL ok = PrintWindow(panel, mem, PW_RENDERFULLCONTENT);
    BITMAPINFO info{}; info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = w; info.bmiHeader.biHeight = h;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 24;
    int stride = (w * 3 + 3) & ~3;
    unsigned char* px = ok ? new unsigned char[stride * h] : nullptr;
    if (px) GetDIBits(mem, bmp, 0, h, px, &info, DIB_RGB_COLORS);
    FILE* f = nullptr; fopen_s(&f, path, "wb");
    bool wrote = false;
    if (f && px) {
        unsigned char hdr[54]{}; hdr[0] = 'B'; hdr[1] = 'M';
        int size = 54 + stride * h; std::memcpy(hdr + 2, &size, 4);
        int off = 54; std::memcpy(hdr + 10, &off, 4);
        int hs = 40; std::memcpy(hdr + 14, &hs, 4);
        std::memcpy(hdr + 18, &w, 4); std::memcpy(hdr + 22, &h, 4);
        short planes = 1, bits = 24;
        std::memcpy(hdr + 26, &planes, 2); std::memcpy(hdr + 28, &bits, 2);
        std::fwrite(hdr, 1, 54, f); std::fwrite(px, 1, stride * h, f); wrote = true;
    }
    if (f) std::fclose(f);
    delete[] px; SelectObject(mem, old); DeleteObject(bmp); DeleteDC(mem); ReleaseDC(nullptr, screen);
    return wrote;
}
