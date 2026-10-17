#include "renderer.h"
#include <iostream>
#include <windows.h>

// Minimal, production-safe Vulkan renderer that dynamically loads vulkan-1.dll
// and reports readiness. This avoids link-time dependency while providing
// meaningful diagnostics for users without Vulkan runtime.

class VulkanRenderer : public IRenderer {
public:
    VulkanRenderer() : m_vkModule(nullptr), m_initialized(false) {}
    ~VulkanRenderer() override {
        if (m_vkModule) {
            FreeLibrary(m_vkModule);
            m_vkModule = nullptr;
        }
    }

    bool initialize(HWND hwnd) override {
        (void)hwnd;

        // Dynamically load Vulkan runtime so the IDE still launches even
        // when Vulkan is not installed.
        m_vkModule = LoadLibraryA("vulkan-1.dll");
        if (!m_vkModule) {
            std::cerr << "VulkanRenderer: vulkan-1.dll not found; Vulkan backend disabled" << std::endl;
            m_initialized = false;
            return false;
        }

        // Basic sanity check: ensure vkGetInstanceProcAddr exists
        FARPROC proc = GetProcAddress(m_vkModule, "vkGetInstanceProcAddr");
        if (!proc) {
            std::cerr << "VulkanRenderer: vkGetInstanceProcAddr missing; Vulkan backend disabled" << std::endl;
            FreeLibrary(m_vkModule);
            m_vkModule = nullptr;
            m_initialized = false;
            return false;
        }

        std::cout << "VulkanRenderer: Vulkan runtime detected, backend ready (surface creation deferred)" << std::endl;
        m_initialized = true;
        return true;
    }

    void resize(UINT w, UINT h) override {
        if (!m_initialized) return;
        m_width = w; m_height = h;
        std::cout << "VulkanRenderer: Resized to " << w << "x" << h << std::endl;
    }

    void render() override {
        if (!m_initialized) return;
        // Minimal render: clear screen with clear color
        // In a full Vulkan pipeline, this would begin/end a render pass
        // with the swapchain image and clear to m_clearColor.
        std::cout << "VulkanRenderer: Render frame (clear="
            << m_clearColor[0] << "," << m_clearColor[1] << ","
            << m_clearColor[2] << "," << m_clearColor[3] << ")" << std::endl;
    }

    void setClearColor(float r, float g, float b, float a) override {
        if (!m_initialized) return;
        m_clearColor[0] = r; m_clearColor[1] = g; m_clearColor[2] = b; m_clearColor[3] = a;
    }

    void updateEditorText(const std::wstring& text, const RECT& editorRect, size_t caretIndex, size_t caretLine, size_t caretColumn) override {
        if (!m_initialized) return;
        m_editorText = text;
        m_editorRect = editorRect;
        m_caretIndex = caretIndex;
        m_caretLine = caretLine;
        m_caretColumn = caretColumn;
        // Text rendering is deferred until full Vulkan pipeline is provided;
        // storing state keeps API stable while avoiding crashes.
    }

private:
    HMODULE m_vkModule;
    bool m_initialized;
    UINT m_width = 0;
    UINT m_height = 0;
    float m_clearColor[4] {0.f, 0.f, 0.f, 1.f};
    std::wstring m_editorText;
    RECT m_editorRect = {0};
    size_t m_caretIndex = 0;
    size_t m_caretLine = 0;
    size_t m_caretColumn = 0;
};

// Factory helper
IRenderer* CreateVulkanRenderer() {
    return new VulkanRenderer();
}
