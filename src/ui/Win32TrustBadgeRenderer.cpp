#include "Win32TrustBadgeRenderer.h"
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

namespace RawrXD {

// GDI+ token for initialization
static ULONG_PTR g_gdiplusToken = 0;
static bool g_gdiplusInitialized = false;

Win32TrustBadgeRenderer::Win32TrustBadgeRenderer() {}

Win32TrustBadgeRenderer::~Win32TrustBadgeRenderer() {
    shutdown();
}

bool Win32TrustBadgeRenderer::initialize() {
    if (m_initialized) return true;
    
    // Initialize GDI+
    if (!g_gdiplusInitialized) {
        Gdiplus::GdiplusStartupInput input;
        Gdiplus::GdiplusStartupOutput output;
        Gdiplus::GdiplusStartup(&g_gdiplusToken, &input, &output);
        g_gdiplusInitialized = true;
    }
    
    // Create fonts
    m_font = CreateFontA(11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                         DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    
    m_bold_font = CreateFontA(11, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    
    m_initialized = true;
    return true;
}

void Win32TrustBadgeRenderer::shutdown() {
    if (!m_initialized) return;
    
    if (m_font) {
        DeleteObject(m_font);
        m_font = nullptr;
    }
    
    if (m_bold_font) {
        DeleteObject(m_bold_font);
        m_bold_font = nullptr;
    }
    
    m_initialized = false;
}

Win32TrustBadgeRenderer::BadgeColors Win32TrustBadgeRenderer::get_colors_for_type(TrustIndicatorType type) const {
    switch (type) {
        case TrustIndicatorType::LEARNED:
            return { RGB(230, 245, 230), RGB(34, 139, 34), RGB(144, 238, 144) }; // Green
        case TrustIndicatorType::PERSONALIZED:
            return { RGB(240, 230, 250), RGB(128, 0, 128), RGB(221, 160, 221) }; // Purple
        case TrustIndicatorType::SEMANTIC:
            return { RGB(230, 240, 255), RGB(0, 100, 200), RGB(173, 216, 230) }; // Blue
        case TrustIndicatorType::SYNTACTIC:
            return { RGB(255, 245, 230), RGB(200, 100, 0), RGB(255, 200, 150) }; // Orange
        case TrustIndicatorType::HYBRID:
            return { RGB(240, 240, 240), RGB(80, 80, 80), RGB(200, 200, 200) }; // Gray
        case TrustIndicatorType::CONFIDENT:
            return { RGB(230, 255, 230), RGB(0, 150, 0), RGB(144, 238, 144) }; // Dark Green
        case TrustIndicatorType::EXPERIMENTAL:
            return { RGB(255, 240, 240), RGB(200, 50, 50), RGB(255, 180, 180) }; // Red
        default:
            return { RGB(240, 240, 240), RGB(100, 100, 100), RGB(200, 200, 200) }; // Default
    }
}

std::string Win32TrustBadgeRenderer::get_badge_text(TrustIndicatorType type) const {
    switch (type) {
        case TrustIndicatorType::LEARNED:
            return "Learned";
        case TrustIndicatorType::PERSONALIZED:
            return "Personalized";
        case TrustIndicatorType::SEMANTIC:
            return "AI";
        case TrustIndicatorType::SYNTACTIC:
            return "Exact";
        case TrustIndicatorType::HYBRID:
            return "Hybrid";
        case TrustIndicatorType::CONFIDENT:
            return "Confident";
        case TrustIndicatorType::EXPERIMENTAL:
            return "New";
        default:
            return "";
    }
}

void Win32TrustBadgeRenderer::measure_text(const char* text, int& width, int& height) {
    HDC hdc = GetDC(nullptr);
    HFONT old_font = (HFONT)SelectObject(hdc, m_font);
    
    SIZE size;
    GetTextExtentPoint32A(hdc, text, strlen(text), &size);
    width = size.cx;
    height = size.cy;
    
    SelectObject(hdc, old_font);
    ReleaseDC(nullptr, hdc);
}

void Win32TrustBadgeRenderer::get_badge_size(const TrustMetadata& metadata, int& width, int& height) {
    auto type = metadata.get_indicator_type();
    std::string text = get_badge_text(type);
    
    if (text.empty()) {
        width = 0;
        height = 0;
        return;
    }
    
    int text_width, text_height;
    measure_text(text.c_str(), text_width, text_height);
    
    width = ICON_SIZE + ICON_TEXT_GAP + text_width + 2 * BADGE_PADDING_X;
    height = BADGE_HEIGHT;
}

void Win32TrustBadgeRenderer::render_badge(int x, int y, const TrustMetadata& metadata) {
    if (!m_initialized) return;
    
    auto type = metadata.get_indicator_type();
    std::string text = get_badge_text(type);
    
    if (text.empty()) return;
    
    auto colors = get_colors_for_type(type);
    
    int width, height;
    get_badge_size(metadata, width, height);
    
    HDC hdc = GetDC(nullptr);
    
    // Create memory DC for double buffering
    HDC mem_dc = CreateCompatibleDC(hdc);
    HBITMAP mem_bitmap = CreateCompatibleBitmap(hdc, width, height);
    HBITMAP old_bitmap = (HBITMAP)SelectObject(mem_dc, mem_bitmap);
    
    // Draw background
    HBRUSH bg_brush = CreateSolidBrush(colors.bg);
    RECT bg_rect = { 0, 0, width, height };
    FillRect(mem_dc, &bg_rect, bg_brush);
    DeleteObject(bg_brush);
    
    // Draw border
    HPEN border_pen = CreatePen(PS_SOLID, 1, colors.border);
    HPEN old_pen = (HPEN)SelectObject(mem_dc, border_pen);
    HBRUSH null_brush = (HBRUSH)GetStockObject(NULL_BRUSH);
    HBRUSH old_brush = (HBRUSH)SelectObject(mem_dc, null_brush);
    
    RoundRect(mem_dc, 0, 0, width, height, 4, 4);
    
    SelectObject(mem_dc, old_pen);
    DeleteObject(border_pen);
    SelectObject(mem_dc, old_brush);
    
    // Draw icon (simplified colored circle)
    HBRUSH icon_brush = CreateSolidBrush(colors.fg);
    HBRUSH old_icon_brush = (HBRUSH)SelectObject(mem_dc, icon_brush);
    Ellipse(mem_dc, BADGE_PADDING_X, (height - ICON_SIZE) / 2, 
              BADGE_PADDING_X + ICON_SIZE, (height + ICON_SIZE) / 2);
    SelectObject(mem_dc, old_icon_brush);
    DeleteObject(icon_brush);
    
    // Draw text
    SetBkMode(mem_dc, TRANSPARENT);
    SetTextColor(mem_dc, colors.fg);
    HFONT old_font = (HFONT)SelectObject(mem_dc, m_font);
    
    RECT text_rect = {
        BADGE_PADDING_X + ICON_SIZE + ICON_TEXT_GAP,
        0,
        width - BADGE_PADDING_X,
        height
    };
    DrawTextA(mem_dc, text.c_str(), -1, &text_rect, 
              DT_SINGLELINE | DT_VCENTER | DT_LEFT);
    
    SelectObject(mem_dc, old_font);
    
    // Copy to screen
    BitBlt(hdc, x, y, width, height, mem_dc, 0, 0, SRCCOPY);
    
    // Cleanup
    SelectObject(mem_dc, old_bitmap);
    DeleteObject(mem_bitmap);
    DeleteDC(mem_dc);
    ReleaseDC(nullptr, hdc);
}

void Win32TrustBadgeRenderer::render_tooltip(int x, int y, const TrustMetadata& metadata) {
    if (!m_initialized) return;
    
    std::string description = metadata.get_description();
    if (description.empty()) return;
    
    // Create tooltip window
    HWND hwnd_tooltip = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        "STATIC",
        description.c_str(),
        WS_POPUP | SS_LEFT,
        x, y, 200, 60,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr
    );
    
    if (hwnd_tooltip) {
        SetWindowPos(hwnd_tooltip, HWND_TOPMOST, x, y, 200, 60, 
                     SWP_SHOWWINDOW | SWP_NOACTIVATE);
    }
}

// ============================================================================
// Win32TrustIndicatorObserver Implementation
// ============================================================================

Win32TrustIndicatorObserver::Win32TrustIndicatorObserver() {}

Win32TrustIndicatorObserver::~Win32TrustIndicatorObserver() {
    shutdown();
}

bool Win32TrustIndicatorObserver::initialize(HWND hwnd_autocomplete) {
    m_hwnd_autocomplete = hwnd_autocomplete;
    
    // Create renderer
    m_renderer = std::make_unique<Win32TrustBadgeRenderer>();
    if (!m_renderer->initialize()) {
        return false;
    }
    
    // Register with TrustIndicatorSystem
    auto& system = TrustIndicatorSystem::instance();
    m_observer_id = system.register_observer(weak_from_this());
    
    return true;
}

void Win32TrustIndicatorObserver::shutdown() {
    if (m_observer_id >= 0) {
        auto& system = TrustIndicatorSystem::instance();
        system.unregister_observer(m_observer_id);
        m_observer_id = -1;
    }
    
    if (m_renderer) {
        m_renderer->shutdown();
        m_renderer.reset();
    }
    
    m_hwnd_autocomplete = nullptr;
}

void Win32TrustIndicatorObserver::on_completion_generated(const CompletionReport& report) {
    m_current_metadata = report.trust;
    update_ui();
}

void Win32TrustIndicatorObserver::on_training_state_changed(
    const std::string& adapter_id, bool is_training, float progress) {
    m_showing_training = is_training;
    show_training_indicator(is_training);
}

void Win32TrustIndicatorObserver::on_adapter_swapped(
    const std::string& old_adapter, const std::string& new_adapter) {
    // Could show a toast notification here
    update_ui();
}

void Win32TrustIndicatorObserver::update_ui() {
    if (!m_hwnd_autocomplete || !m_renderer) return;
    
    // Request redraw of autocomplete window
    InvalidateRect(m_hwnd_autocomplete, nullptr, FALSE);
    
    // Update badge display
    update_badge_display(m_current_metadata);
}

void Win32TrustIndicatorObserver::show_training_indicator(bool show) {
    // Could show a small animated indicator when training is active
    // For now, just log it
    if (show) {
        // Training started
    } else {
        // Training stopped
    }
}

void Win32TrustIndicatorObserver::update_badge_display(const TrustMetadata& metadata) {
    if (!m_renderer) return;
    
    // Calculate badge position (right side of completion item)
    int badge_width, badge_height;
    m_renderer->get_badge_size(metadata, badge_width, badge_height);
    
    // Position badge at right edge of autocomplete item
    // This would be called during WM_PAINT of the autocomplete window
}

} // namespace RawrXD
