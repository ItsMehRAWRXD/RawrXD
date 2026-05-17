// RawrXD Agentic IDE - Minimal Main
// Entry point for GUI application
// VSU Effects: Uses Adobe RGBa color space for professional color accuracy

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <cstdio>
#include <fstream>
#include "logger.h"
#include "RawrXD_Window.h"
#include "RawrXD_Foundation.h"
#include "universal_model_router.h"
#include "include/RawrXD_ColorSpace.h"

using namespace RawrXD;
using namespace RawrXD::ColorSpace;

// Helper to convert AdobeRGBa to COLORREF for Win32 GDI
inline COLORREF AdobeRGBaToCOLORREF(const AdobeRGBa& color) {
    auto srgb = color.TosRGB();
    return RGB(static_cast<int>(srgb.r * 255), 
               static_cast<int>(srgb.g * 255), 
               static_cast<int>(srgb.b * 255));
}

class IDEWindow : public Window {
    UniversalModelRouter router;
    String status = "Ready. Press F5 to run Titan+Assembly inference.";
    String outputText;
    
public:
    IDEWindow() {
        // Initialize logic - assume model path is auto-detected or configured
        // router.initializeLocalEngine(""); 
    }
    
    void paintEvent(PAINTSTRUCT& ps) override {
        HDC hdc = ps.hdc;
        RECT rect;
        GetClientRect(hwnd, &rect);
        
        // VSU Acrylic background
        HBRUSH bgBrush = CreateSolidBrush(AdobeRGBaToCOLORREF(VSU::Acrylic::DarkBase));
        FillRect(hdc, &rect, bgBrush);
        DeleteObject(bgBrush);
        
        SetBkMode(hdc, TRANSPARENT);
        
        // Draw Status with VSU text color
        SetTextColor(hdc, AdobeRGBaToCOLORREF(VSU::Accents::Blue));
        RECT rParam = {10, 10, rect.right, 40};
        DrawTextW(hdc, status.c_str(), -1, &rParam, DT_LEFT);
        
        // Draw Output with VSU text color
        SetTextColor(hdc, AdobeRGBaToCOLORREF(AdobeRGBa(0.86f, 0.86f, 0.86f, 1.00f)));
        RECT rOut = {10, 50, rect.right, rect.bottom};
        DrawTextW(hdc, outputText.c_str(), -1, &rOut, DT_LEFT | DT_WORDBREAK);
    }
    
    void keyPressEvent(int key, int mods) override {
        if (key == VK_F5) {
            status = "Running Inference via Titan Assembly Engine...";
            update(); // Repaint
             
            // Simple blocking inference
            // In a real app this would be threaded.
            String prompt = "This is a test of the Titan Engine.";
            
            // Note: routeQuery lazily loads the engine which lazily loads the DLL
            std::string response = router.routeQuery("local-default", prompt.toUtf8());
            
            outputText = String(response);
            status = "Inference Complete.";
            update();
        }
        else if (key == VK_ESCAPE) {
            PostQuitMessage(0);
        }
    }
};

// For GUI apps, we need WinMain, not main
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Convert Windows command line to argc/argv for Qt removal compatibility
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    LocalFree(argvW);

    // Create minimal main window
    IDEWindow window;
    window.create(nullptr, "RawrXD Agentic IDE Titan Powered", WS_OVERLAPPEDWINDOW | WS_VISIBLE);
    window.resize(1024, 768);

    // Message Loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}


