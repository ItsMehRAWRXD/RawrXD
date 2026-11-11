#pragma once

#include "TrustIndicatorSystem.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {

/**
 * @brief Win32 GDI+ Trust Badge Renderer
 * 
 * Phase 18D: Windows-specific implementation of trust indicator rendering.
 * Renders badges in the autocomplete popup using GDI+.
 */
class Win32TrustBadgeRenderer : public ITrustBadgeRenderer {
public:
    Win32TrustBadgeRenderer();
    ~Win32TrustBadgeRenderer();
    
    /**
     * @brief Initialize GDI+ and resources
     */
    bool initialize();
    
    /**
     * @brief Cleanup GDI+ resources
     */
    void shutdown();

    // ITrustBadgeRenderer implementation
    void render_badge(int x, int y, const TrustMetadata& metadata) override;
    void render_tooltip(int x, int y, const TrustMetadata& metadata) override;
    void get_badge_size(const TrustMetadata& metadata, int& width, int& height) override;

private:
    // Badge dimensions
    static constexpr int BADGE_HEIGHT = 16;
    static constexpr int BADGE_PADDING_X = 6;
    static constexpr int BADGE_PADDING_Y = 2;
    static constexpr int ICON_SIZE = 12;
    static constexpr int ICON_TEXT_GAP = 4;
    
    // Colors for different indicator types
    struct BadgeColors {
        COLORREF bg;
        COLORREF fg;
        COLORREF border;
    };
    
    BadgeColors get_colors_for_type(TrustIndicatorType type) const;
    std::string get_badge_text(TrustIndicatorType type) const;
    
    // Measure text
    void measure_text(const char* text, int& width, int& height);
    
    // Render helper
    void draw_rounded_rect(HDC hdc, int x, int y, int width, int height, int radius);
    void draw_icon(HDC hdc, int x, int y, TrustIndicatorType type);
    
    bool m_initialized = false;
    HFONT m_font = nullptr;
    HFONT m_bold_font = nullptr;
};

/**
 * @brief Win32 Trust Indicator Observer
 * 
 * Connects TrustIndicatorSystem to Win32IDE autocomplete UI.
 */
class Win32TrustIndicatorObserver : public ITrustIndicatorObserver,
                                     public std::enable_shared_from_this<Win32TrustIndicatorObserver> {
public:
    Win32TrustIndicatorObserver();
    ~Win32TrustIndicatorObserver();
    
    /**
     * @brief Initialize and register with TrustIndicatorSystem
     */
    bool initialize(HWND hwnd_autocomplete);
    
    /**
     * @brief Cleanup and unregister
     */
    void shutdown();

    // ITrustIndicatorObserver implementation
    void on_completion_generated(const CompletionReport& report) override;
    void on_training_state_changed(const std::string& adapter_id, bool is_training, float progress) override;
    void on_adapter_swapped(const std::string& old_adapter, const std::string& new_adapter) override;

private:
    void update_ui();
    void show_training_indicator(bool show);
    void update_badge_display(const TrustMetadata& metadata);
    
    HWND m_hwnd_autocomplete = nullptr;
    std::unique_ptr<Win32TrustBadgeRenderer> m_renderer;
    int m_observer_id = -1;
    
    // Current state
    TrustMetadata m_current_metadata;
    bool m_showing_training = false;
};

} // namespace RawrXD
