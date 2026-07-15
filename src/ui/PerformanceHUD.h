// PerformanceHUD.h
// Phase 25: The Performance HUD - Real-Time Metrics Dashboard
// ============================================================================
// High-performance telemetry visualization for RawrXD kernels and system
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace UI {

// ============================================================================
// Metric Types
// ============================================================================
enum class MetricType {
    Latency,            // Time-based (µs, ms)
    Throughput,        // Rate-based (TPS, GB/s)
    Utilization,       // Percentage (0-100%)
    Counter,           // Absolute count
    Memory,            // Bytes allocated/used
};

enum class MetricSeverity {
    Normal,             // Within expected range
    Warning,            // Approaching limit
    Critical,           // Exceeds threshold
};

// ============================================================================
// Metric Data Point
// ============================================================================
struct MetricDataPoint {
    std::chrono::steady_clock::time_point timestamp;
    double value;                           // Raw value
    double normalizedValue;                 // 0.0 - 1.0 for visualization
    MetricSeverity severity;
    std::wstring label;                     // Display label
};

// ============================================================================
// Metric Configuration
// ============================================================================
struct MetricConfig {
    std::wstring name;
    std::wstring unit;                      // "µs", "TPS", "GB/s", "%"
    MetricType type;
    double minValue = 0.0;
    double maxValue = 100.0;
    double warningThreshold = 80.0;          // Percentage for warning
    double criticalThreshold = 95.0;       // Percentage for critical
    COLORREF normalColor = RGB(0, 200, 0);     // Green
    COLORREF warningColor = RGB(255, 165, 0);  // Orange
    COLORREF criticalColor = RGB(255, 0, 0);   // Red
    size_t historySize = 300;               // 5 seconds at 60fps
    bool showGraph = true;
    bool showValue = true;
    bool showBar = true;
};

// ============================================================================
// Performance Metric
// ============================================================================
class PerformanceMetric {
public:
    PerformanceMetric(const MetricConfig& config);
    ~PerformanceMetric();

    // Data updates
    void RecordValue(double value, const std::wstring& label = L"");
    void RecordValue(double value, const std::chrono::steady_clock::time_point& timestamp, 
                     const std::wstring& label = L"");
    
    // Accessors
    const std::vector<MetricDataPoint>& GetHistory() const;
    MetricDataPoint GetCurrent() const;
    MetricDataPoint GetAverage(size_t windowSize = 60) const;
    MetricDataPoint GetMin() const;
    MetricDataPoint GetMax() const;
    
    // Configuration
    const MetricConfig& GetConfig() const;
    void SetConfig(const MetricConfig& config);
    
    // Statistics
    double GetMovingAverage(size_t windowSize) const;
    double GetPercentile(double percentile) const;
    double GetStandardDeviation() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// HUD Widget Types
// ============================================================================
enum class HUDWidgetType {
    LineGraph,          // Time-series line chart
    BarGraph,           // Vertical/horizontal bars
    Gauge,              // Circular percentage gauge
    DigitalDisplay,     // Large numeric readout
    Sparkline,          // Mini line graph
    Heatmap,            // 2D activity heatmap
    TextLog,            // Scrolling text log
};

// ============================================================================
// HUD Widget Configuration
// ============================================================================
struct HUDWidgetConfig {
    std::wstring title;
    HUDWidgetType type;
    RECT position;                          // Relative to HUD panel
    std::vector<std::wstring> metricNames; // Metrics to display
    int refreshRateHz = 60;
    bool showLegend = true;
    bool showGrid = true;
    COLORREF backgroundColor = RGB(30, 30, 30);
    COLORREF gridColor = RGB(60, 60, 60);
    COLORREF textColor = RGB(200, 200, 200);
};

// ============================================================================
// HUD Widget
// ============================================================================
class HUDWidget {
public:
    HUDWidget(const HUDWidgetConfig& config);
    ~HUDWidget();

    // Rendering
    void Render(HDC hdc, const RECT& widgetRect);
    void Invalidate();

    // Data binding
    void BindMetric(const std::wstring& metricName, PerformanceMetric* metric);
    void UnbindMetric(const std::wstring& metricName);

    // Event handling
    bool OnMouseMove(int x, int y);
    bool OnMouseClick(int x, int y);
    bool OnMouseWheel(int delta);

    // Configuration
    void SetConfig(const HUDWidgetConfig& config);
    const HUDWidgetConfig& GetConfig() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Performance HUD Panel
// ============================================================================
class PerformanceHUD {
public:
    using TelemetryCallback = std::function<void(const std::wstring& metricName, double value)>;

    PerformanceHUD();
    ~PerformanceHUD();

    // Initialization
    bool Initialize(HWND parentWindow);
    void Shutdown();

    // Metric management
    void RegisterMetric(const std::wstring& name, const MetricConfig& config);
    void UnregisterMetric(const std::wstring& name);
    PerformanceMetric* GetMetric(const std::wstring& name);
    std::vector<std::wstring> GetMetricNames() const;

    // Widget management
    void AddWidget(const HUDWidgetConfig& config);
    void RemoveWidget(size_t index);
    void ClearWidgets();
    std::vector<HUDWidget*>& GetWidgets();

    // Data injection (called from kernel/inference code)
    void RecordMetric(const std::wstring& name, double value, const std::wstring& label = L"");
    void RecordKernelLatency(const std::wstring& kernelName, double microseconds);
    void RecordMemoryBandwidth(double gigabytesPerSecond);
    void RecordTPS(double tokensPerSecond);
    void RecordGPUUtilization(double percentage);

    // Rendering
    void Render(HDC hdc, const RECT& panelRect);
    void Invalidate();

    // Event handling
    void SetTelemetryCallback(TelemetryCallback callback);
    bool OnMouseMove(int x, int y);
    bool OnMouseClick(int x, int y);
    bool OnMouseWheel(int delta);
    bool OnKeyDown(WPARAM keyCode);

    // Layout
    void SetLayout(const std::wstring& layoutName);  // "default", "compact", "detailed"
    void AutoLayout();
    void SaveLayout(const std::wstring& filename);
    void LoadLayout(const std::wstring& filename);

    // Visibility
    void Show();
    void Hide();
    bool IsVisible() const;
    void Toggle();

    // Sizing
    SIZE GetPreferredSize() const;
    void SetSize(int width, int height);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Predefined Metric Presets
// ============================================================================
namespace MetricPresets {
    MetricConfig LoRAKernelLatency();      // 23.80 µs target
    MetricConfig MemoryBandwidth();          // GB/s
    MetricConfig TokenThroughput();          // TPS
    MetricConfig GPUUtilization();           // %
    MetricConfig CPUUtilization();           // %
    MetricConfig MemoryUsage();              // MB
    MetricConfig ThreadPoolActivity();       // Active threads
    MetricConfig InferenceQueueDepth();      // Pending requests
}

// ============================================================================
// Global HUD Access
// ============================================================================
PerformanceHUD* GetPerformanceHUD();
bool InitializePerformanceHUD(HWND parentWindow);
void ShutdownPerformanceHUD();

} // namespace UI
} // namespace RawrXD
