// Test harness for Annotation Overlay
// test_overlay.cpp

#include <windows.h>
#include <stdio.h>
#include <vector>

// C API from AnnotationOverlay
extern "C" {
    __declspec(dllimport) void* AnnotationOverlay_Create(HWND parentHwnd);
    __declspec(dllimport) void AnnotationOverlay_Destroy(void* overlay);
    __declspec(dllimport) void AnnotationOverlay_Show(void* overlay);
    __declspec(dllimport) void AnnotationOverlay_Hide(void* overlay);
    __declspec(dllimport) void AnnotationOverlay_AddSquiggle(
        void* overlay, int line, int startCol, int endCol, uint32_t color);
    __declspec(dllimport) void AnnotationOverlay_Clear(void* overlay);
    __declspec(dllimport) void AnnotationOverlay_PostLoRAResult(
        HWND hwndOverlay, uint32_t requestId, const float* resultData, size_t resultSize);
}

// Simple window procedure for test
LRESULT CALLBACK TestWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) {
                DestroyWindow(hwnd);
            }
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // Register window class
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = TestWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"TestOverlayWindow";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    if (!RegisterClassEx(&wc)) {
        MessageBox(nullptr, L"Failed to register window class", L"Error", MB_OK);
        return 1;
    }
    
    // Create main window
    HWND hwndMain = CreateWindowEx(
        0,
        L"TestOverlayWindow",
        L"Annotation Overlay Test",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        nullptr, nullptr, hInstance, nullptr
    );
    
    if (!hwndMain) {
        MessageBox(nullptr, L"Failed to create window", L"Error", MB_OK);
        return 1;
    }
    
    ShowWindow(hwndMain, nCmdShow);
    UpdateWindow(hwndMain);
    
    // Create annotation overlay
    printf("Creating annotation overlay...\n");
    void* overlay = AnnotationOverlay_Create(hwndMain);
    
    if (!overlay) {
        MessageBox(hwndMain, L"Failed to create overlay", L"Error", MB_OK);
        return 1;
    }
    
    printf("Overlay created successfully!\n");
    
    // Show overlay
    AnnotationOverlay_Show(overlay);
    printf("Overlay shown\n");
    
    // Add test annotations
    printf("Adding test annotations...\n");
    
    // Yellow squiggle (warning)
    AnnotationOverlay_AddSquiggle(overlay, 5, 10, 30, RGB(255, 204, 0));
    
    // Red squiggle (error)
    AnnotationOverlay_AddSquiggle(overlay, 10, 5, 25, RGB(255, 0, 0));
    
    // Blue squiggle (info)
    AnnotationOverlay_AddSquiggle(overlay, 15, 15, 40, RGB(0, 128, 255));
    
    printf("Annotations added\n");
    
    // Test LoRA result posting
    printf("Testing LoRA result post...\n");
    std::vector<float> loraResult(768, 0.0f);
    // Set some high values for visualization
    loraResult[100] = 0.95f;
    loraResult[200] = 0.87f;
    loraResult[300] = 0.76f;
    loraResult[400] = 0.65f;
    loraResult[500] = 0.54f;
    
    // Get overlay window handle (we need to expose this)
    // For now, just test the API exists
    // AnnotationOverlay_PostLoRAResult(...);
    
    printf("\nTest running - press ESC to exit\n");
    printf("You should see colored squiggles on lines 5, 10, and 15\n");
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Cleanup
    printf("\nCleaning up...\n");
    AnnotationOverlay_Destroy(overlay);
    printf("Done!\n");
    
    return 0;
}
