// PerformanceHUD.cpp
// Phase 25: The Performance HUD - Implementation
// ============================================================================

#include "ui/PerformanceHUD.h"
#include <algorithm>
#include <cmath>
#include <unordered_map>

namespace RawrXD {
namespace UI {

// ============================================================================
// PerformanceMetric Implementation
// ============================================================================
class PerformanceMetric::Impl {
public:
    MetricConfig config_;
    std::vector<MetricDataPoint> history_;
    mutable std::mutex mutex_;
    size_t currentIndex_ = 0;
    bool isFull_ = false;

    void AddPoint(const MetricDataPoint& point) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (history_.size() < config_.historySize) {
            history_.push_back(point);
        } else {
            history_[currentIndex_] = point;
            currentIndex_ = (currentIndex_ + 1) % config_.historySize;
            isFull_ = true;
        }
    }

    std::vector<MetricDataPoint> GetOrderedHistory() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!isFull_) {
            return history_;
        }
        
        std::vector<MetricDataPoint> ordered;
        ordered.reserve(history_.size());
        
        for (size_t i = 0; i < history_.size(); i++) {
            size_t idx = (currentIndex_ + i) % history_.size();
            ordered.push_back(history_[idx]);
        }
        
        return ordered;
    }
};

PerformanceMetric::PerformanceMetric(const MetricConfig& config) 
    : pImpl_(std::make_unique<Impl>()) {
    pImpl_->config_ = config;
    pImpl_->history_.reserve(config.historySize);
}

PerformanceMetric::~PerformanceMetric() = default;

void PerformanceMetric::RecordValue(double value, const std::wstring& label) {
    RecordValue(value, std::chrono::steady_clock::now(), label);
}

void PerformanceMetric::RecordValue(double value, 
                                       const std::chrono::steady_clock::time_point& timestamp,
                                       const std::wstring& label) {
    MetricDataPoint point;
    point.timestamp = timestamp;
    point.value = value;
    point.label = label;
    
    // Normalize to 0.0 - 1.0 range
    double range = pImpl_->config_.maxValue - pImpl_->config_.minValue;
    if (range > 0) {
        point.normalizedValue = (value - pImpl_->config_.minValue) / range;
        point.normalizedValue = std::max(0.0, std::min(1.0, point.normalizedValue));
    } else {
        point.normalizedValue = 0.0;
    }
    
    // Determine severity
    double percentage = point.normalizedValue * 100.0;
    if (percentage >= pImpl_->config_.criticalThreshold) {
        point.severity = MetricSeverity::Critical;
    } else if (percentage >= pImpl_->config_.warningThreshold) {
        point.severity = MetricSeverity::Warning;
    } else {
        point.severity = MetricSeverity::Normal;
    }
    
    pImpl_->AddPoint(point);
}

const std::vector<MetricDataPoint>& PerformanceMetric::GetHistory() const {
    // Note: This returns the raw history which may be circular
    // Use GetOrderedHistory for chronological order
    std::lock_guard<std::mutex> lock(pImpl_->mutex_);
    return pImpl_->history_;
}

MetricDataPoint PerformanceMetric::GetCurrent() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex_);
    if (pImpl_->history_.empty()) {
        return MetricDataPoint{};
    }
    
    if (!pImpl_->isFull_) {
        return pImpl_->history_.back();
    }
    
    size_t lastIdx = (pImpl_->currentIndex_ + pImpl_->history_.size() - 1) % pImpl_->history_.size();
    return pImpl_->history_[lastIdx];
}

MetricDataPoint PerformanceMetric::GetAverage(size_t windowSize) const {
    auto ordered = pImpl_->GetOrderedHistory();
    if (ordered.empty()) return MetricDataPoint{};
    
    windowSize = std::min(windowSize, ordered.size());
    double sum = 0.0;
    
    for (size_t i = ordered.size() - windowSize; i < ordered.size(); i++) {
        sum += ordered[i].value;
    }
    
    MetricDataPoint avg;
    avg.value = sum / windowSize;
    avg.timestamp = ordered.back().timestamp;
    return avg;
}

MetricDataPoint PerformanceMetric::GetMin() const {
    auto ordered = pImpl_->GetOrderedHistory();
    if (ordered.empty()) return MetricDataPoint{};
    
    return *std::min_element(ordered.begin(), ordered.end(),
        [](const MetricDataPoint& a, const MetricDataPoint& b) {
            return a.value < b.value;
        });
}

MetricDataPoint PerformanceMetric::GetMax() const {
    auto ordered = pImpl_->GetOrderedHistory();
    if (ordered.empty()) return MetricDataPoint{};
    
    return *std::max_element(ordered.begin(), ordered.end(),
        [](const MetricDataPoint& a, const MetricDataPoint& b) {
            return a.value < b.value;
        });
}

const MetricConfig& PerformanceMetric::GetConfig() const {
    return pImpl_->config_;
}

void PerformanceMetric::SetConfig(const MetricConfig& config) {
    pImpl_->config_ = config;
}

// ============================================================================
// HUDWidget Implementation
// ============================================================================
class HUDWidget::Impl {
public:
    HUDWidgetConfig config_;
    std::unordered_map<std::wstring, PerformanceMetric*> metrics_;
    HFONT hFont_ = nullptr;
    HFONT hFontLarge_ = nullptr;
    
    void CreateFonts() {
        if (hFont_) DeleteObject(hFont_);
        if (hFontLarge_) DeleteObject(hFontLarge_);
        
        hFont_ = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        
        hFontLarge_ = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Consolas");
    }
    
    void DestroyFonts() {
        if (hFont_) { DeleteObject(hFont_); hFont_ = nullptr; }
        if (hFontLarge_) { DeleteObject(hFontLarge_); hFontLarge_ = nullptr; }
    }
    
    void DrawLineGraph(HDC hdc, const RECT& rect) {
        // Fill background
        HBRUSH bgBrush = CreateSolidBrush(config_.backgroundColor);
        FillRect(hdc, &rect, bgBrush);
        DeleteObject(bgBrush);
        
        // Draw grid
        HPEN gridPen = CreatePen(PS_DOT, 1, config_.gridColor);
        HPEN oldPen = (HPEN)SelectObject(hdc, gridPen);
        
        for (int i = 1; i < 4; i++) {
            int y = rect.top + (rect.bottom - rect.top) * i / 4;
            MoveToEx(hdc, rect.left, y, nullptr);
            LineTo(hdc, rect.right, y);
        }
        
        SelectObject(hdc, oldPen);
        DeleteObject(gridPen);
        
        // Draw metric lines
        int colorIndex = 0;
        COLORREF colors[] = { RGB(0, 200, 0), RGB(0, 150, 255), RGB(255, 165, 0), RGB(255, 0, 255) };
        
        for (const auto& [name, metric] : metrics_) {
            if (!metric) continue;
            
            auto history = metric->GetHistory();
            if (history.size() < 2) continue;
            
            HPEN linePen = CreatePen(PS_SOLID, 2, colors[colorIndex % 4]);
            oldPen = (HPEN)SelectObject(hdc, linePen);
            
            const auto& config = metric->GetConfig();
            int width = rect.right - rect.left;
            int height = rect.bottom - rect.top;
            
            bool first = true;
            for (size_t i = 0; i < history.size(); i++) {
                int x = rect.left + (width * i) / history.size();
                int y = rect.bottom - (height * history[i].normalizedValue);
                
                if (first) {
                    MoveToEx(hdc, x, y, nullptr);
                    first = false;
                } else {
                    LineTo(hdc, x, y);
                }
            }
            
            SelectObject(hdc, oldPen);
            DeleteObject(linePen);
            colorIndex++;
        }
        
        // Draw title
        HFONT oldFont = (HFONT)SelectObject(hdc, hFont_);
        SetTextColor(hdc, config_.textColor);
        SetBkMode(hdc, TRANSPARENT);
        RECT titleRect = { rect.left + 5, rect.top + 5, rect.right, rect.top + 20 };
        DrawTextW(hdc, config_.title.c_str(), -1, &titleRect, DT_LEFT | DT_SINGLELINE);
        SelectObject(hdc, oldFont);
    }
    
    void DrawDigitalDisplay(HDC hdc, const RECT& rect) {
        // Fill background
        HBRUSH bgBrush = CreateSolidBrush(RGB(20, 20, 20));
        FillRect(hdc, &rect, bgBrush);
        DeleteObject(bgBrush);
        
        // Draw border
        HPEN borderPen = CreatePen(PS_SOLID, 2, RGB(60, 60, 60));
        HPEN oldPen = (HPEN)SelectObject(hdc, borderPen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, rect.left, rect.top, rect.right, rect.bottom);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(borderPen);
        
        // Get primary metric value
        double value = 0.0;
        std::wstring unit;
        COLORREF valueColor = RGB(0, 255, 0);
        
        for (const auto& [name, metric] : metrics_) {
            if (metric) {
                auto current = metric->GetCurrent();
                value = current.value;
                unit = metric->GetConfig().unit;
                
                switch (current.severity) {
                    case MetricSeverity::Warning: valueColor = RGB(255, 165, 0); break;
                    case MetricSeverity::Critical: valueColor = RGB(255, 0, 0); break;
                    default: valueColor = RGB(0, 255, 0); break;
                }
                break;
            }
        }
        
        // Draw value
        HFONT oldFont = (HFONT)SelectObject(hdc, hFontLarge_);
        SetTextColor(hdc, valueColor);
        SetBkMode(hdc, TRANSPARENT);
        
        wchar_t valueStr[64];
        if (value >= 1000) {
            swprintf_s(valueStr, L"%.1f", value);
        } else if (value >= 100) {
            swprintf_s(valueStr, L"%.1f", value);
        } else if (value >= 1) {
            swprintf_s(valueStr, L"%.2f", value);
        } else {
            swprintf_s(valueStr, L"%.3f", value);
        }
        
        RECT valueRect = { rect.left, rect.top + 10, rect.right - 5, rect.bottom - 20 };
        DrawTextW(hdc, valueStr, -1, &valueRect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        
        // Draw unit
        HFONT unitFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        SelectObject(hdc, unitFont);
        SetTextColor(hdc, RGB(150, 150, 150));
        RECT unitRect = { rect.left, rect.bottom - 25, rect.right - 5, rect.bottom - 5 };
        DrawTextW(hdc, unit.c_str(), -1, &unitRect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        
        SelectObject(hdc, oldFont);
        DeleteObject(unitFont);
        
        // Draw title
        SelectObject(hdc, hFont_);
        SetTextColor(hdc, config_.textColor);
        RECT titleRect = { rect.left + 10, rect.top + 5, rect.right, rect.top + 20 };
        DrawTextW(hdc, config_.title.c_str(), -1, &titleRect, DT_LEFT | DT_SINGLELINE);
    }
    
    void DrawGauge(HDC hdc, const RECT& rect) {
        // Circular gauge implementation
        int centerX = (rect.left + rect.right) / 2;
        int centerY = (rect.top + rect.bottom) / 2;
        int radius = std::min(centerX - rect.left, centerY - rect.top) - 10;
        
        // Background circle
        HPEN bgPen = CreatePen(PS_SOLID, 8, RGB(40, 40, 40));
        HPEN oldPen = (HPEN)SelectObject(hdc, bgPen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Ellipse(hdc, centerX - radius, centerY - radius, centerX + radius, centerY + radius);
        
        // Get value
        double value = 0.0;
        double normalized = 0.0;
        for (const auto& [name, metric] : metrics_) {
            if (metric) {
                auto current = metric->GetCurrent();
                value = current.value;
                normalized = current.normalizedValue;
                break;
            }
        }
        
        // Draw value arc
        COLORREF arcColor = RGB(0, 200, 0);
        if (normalized > 0.8) arcColor = RGB(255, 165, 0);
        if (normalized > 0.95) arcColor = RGB(255, 0, 0);
        
        HPEN arcPen = CreatePen(PS_SOLID, 8, arcColor);
        SelectObject(hdc, arcPen);
        
        // Draw arc from -135 to +135 degrees (270 degree sweep)
        double startAngle = 135.0;
        double sweepAngle = 270.0 * normalized;
        
        // Simplified arc drawing
        int startX = centerX + radius * cos((startAngle - 90) * 3.14159 / 180);
        int startY = centerY + radius * sin((startAngle - 90) * 3.14159 / 180);
        
        // Draw title
        SelectObject(hdc, hFont_);
        SetTextColor(hdc, config_.textColor);
        RECT titleRect = { rect.left, rect.top + 5, rect.right, rect.top + 20 };
        DrawTextW(hdc, config_.title.c_str(), -1, &titleRect, DT_CENTER | DT_SINGLELINE);
        
        // Draw value
        HFONT valueFont = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Consolas");
        SelectObject(hdc, valueFont);
        SetTextColor(hdc, arcColor);
        wchar_t valueStr[32];
        swprintf_s(valueStr, L"%.0f%%", value);
        RECT valueRect = { rect.left, centerY - 10, rect.right, centerY + 10 };
        DrawTextW(hdc, valueStr, -1, &valueRect, DT_CENTER | DT_SINGLELINE);
        
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(bgPen);
        DeleteObject(arcPen);
        DeleteObject(valueFont);
    }
};

HUDWidget::HUDWidget(const HUDWidgetConfig& config) : pImpl_(std::make_unique<Impl>()) {
    pImpl_->config_ = config;
    pImpl_->CreateFonts();
}

HUDWidget::~HUDWidget() {
    pImpl_->DestroyFonts();
}

void HUDWidget::Render(HDC hdc, const RECT& widgetRect) {
    switch (pImpl_->config_.type) {
        case HUDWidgetType::LineGraph:
            pImpl_->DrawLineGraph(hdc, widgetRect);
            break;
        case HUDWidgetType::DigitalDisplay:
            pImpl_->DrawDigitalDisplay(hdc, widgetRect);
            break;
        case HUDWidgetType::Gauge:
            pImpl_->DrawGauge(hdc, widgetRect);
            break;
        default:
            pImpl_->DrawLineGraph(hdc, widgetRect);
            break;
    }
}

void HUDWidget::Invalidate() {
    // Trigger redraw
}

void HUDWidget::BindMetric(const std::wstring& metricName, PerformanceMetric* metric) {
    pImpl_->metrics_[metricName] = metric;
}

void HUDWidget::UnbindMetric(const std::wstring& metricName) {
    pImpl_->metrics_.erase(metricName);
}

void HUDWidget::SetConfig(const HUDWidgetConfig& config) {
    pImpl_->config_ = config;
}

const HUDWidgetConfig& HUDWidget::GetConfig() const {
    return pImpl_->config_;
}

// ============================================================================
// PerformanceHUD Implementation
// ============================================================================
class PerformanceHUD::Impl {
public:
    HWND hwnd_ = nullptr;
    HWND parentWindow_ = nullptr;
    bool visible_ = false;
    int width_ = 800;
    int height_ = 600;
    
    std::unordered_map<std::wstring, std::unique_ptr<PerformanceMetric>> metrics_;
    std::vector<std::unique_ptr<HUDWidget>> widgets_;
    
    TelemetryCallback telemetryCallback_;
    
    // Predefined layouts
    void SetupDefaultLayout() {
        // LoRA Kernel Latency - Digital Display (top left)
        HUDWidgetConfig latencyConfig;
        latencyConfig.title = L"LoRA Kernel";
        latencyConfig.type = HUDWidgetType::DigitalDisplay;
        latencyConfig.position = { 10, 40, 200, 120 };
        latencyConfig.metricNames = { L"lora_latency" };
        
        auto latencyWidget = std::make_unique<HUDWidget>(latencyConfig);
        if (metrics_.count(L"lora_latency")) {
            latencyWidget->BindMetric(L"lora_latency", metrics_[L"lora_latency"].get());
        }
        widgets_.push_back(std::move(latencyWidget));
        
        // Memory Bandwidth - Line Graph (top middle)
        HUDWidgetConfig bandwidthConfig;
        bandwidthConfig.title = L"Memory Bandwidth";
        bandwidthConfig.type = HUDWidgetType::LineGraph;
        bandwidthConfig.position = { 220, 40, 550, 200 };
        bandwidthConfig.metricNames = { L"memory_bandwidth" };
        
        auto bandwidthWidget = std::make_unique<HUDWidget>(bandwidthConfig);
        if (metrics_.count(L"memory_bandwidth")) {
            bandwidthWidget->BindMetric(L"memory_bandwidth", metrics_[L"memory_bandwidth"].get());
        }
        widgets_.push_back(std::move(bandwidthWidget));
        
        // TPS - Digital Display (top right)
        HUDWidgetConfig tpsConfig;
        tpsConfig.title = L"Throughput";
        tpsConfig.type = HUDWidgetType::DigitalDisplay;
        tpsConfig.position = { 570, 40, 790, 120 };
        tpsConfig.metricNames = { L"tps" };
        
        auto tpsWidget = std::make_unique<HUDWidget>(tpsConfig);
        if (metrics_.count(L"tps")) {
            tpsWidget->BindMetric(L"tps", metrics_[L"tps"].get());
        }
        widgets_.push_back(std::move(tpsWidget));
        
        // GPU Utilization - Gauge (bottom left)
        HUDWidgetConfig gpuConfig;
        gpuConfig.title = L"GPU Util";
        gpuConfig.type = HUDWidgetType::Gauge;
        gpuConfig.position = { 10, 250, 200, 400 };
        gpuConfig.metricNames = { L"gpu_util" };
        
        auto gpuWidget = std::make_unique<HUDWidget>(gpuConfig);
        if (metrics_.count(L"gpu_util")) {
            gpuWidget->BindMetric(L"gpu_util", metrics_[L"gpu_util"].get());
        }
        widgets_.push_back(std::move(gpuWidget));
        
        // CPU Utilization - Gauge (bottom middle)
        HUDWidgetConfig cpuConfig;
        cpuConfig.title = L"CPU Util";
        cpuConfig.type = HUDWidgetType::Gauge;
        cpuConfig.position = { 220, 250, 410, 400 };
        cpuConfig.metricNames = { L"cpu_util" };
        
        auto cpuWidget = std::make_unique<HUDWidget>(cpuConfig);
        if (metrics_.count(L"cpu_util")) {
            cpuWidget->BindMetric(L"cpu_util", metrics_[L"cpu_util"].get());
        }
        widgets_.push_back(std::move(cpuWidget));
    }
};

PerformanceHUD::PerformanceHUD() : pImpl_(std::make_unique<Impl>()) {}
PerformanceHUD::~PerformanceHUD() = default;

bool PerformanceHUD::Initialize(HWND parentWindow) {
    pImpl_->parentWindow_ = parentWindow;
    
    // Register default metrics
    RegisterMetric(L"lora_latency", MetricPresets::LoRAKernelLatency());
    RegisterMetric(L"memory_bandwidth", MetricPresets::MemoryBandwidth());
    RegisterMetric(L"tps", MetricPresets::TokenThroughput());
    RegisterMetric(L"gpu_util", MetricPresets::GPUUtilization());
    RegisterMetric(L"cpu_util", MetricPresets::CPUUtilization());
    RegisterMetric(L"memory_usage", MetricPresets::MemoryUsage());
    
    // Setup default layout
    pImpl_->SetupDefaultLayout();
    
    return true;
}

void PerformanceHUD::Shutdown() {
    pImpl_->widgets_.clear();
    pImpl_->metrics_.clear();
}

void PerformanceHUD::RegisterMetric(const std::wstring& name, const MetricConfig& config) {
    pImpl_->metrics_[name] = std::make_unique<PerformanceMetric>(config);
}

void PerformanceHUD::UnregisterMetric(const std::wstring& name) {
    pImpl_->metrics_.erase(name);
}

PerformanceMetric* PerformanceHUD::GetMetric(const std::wstring& name) {
    auto it = pImpl_->metrics_.find(name);
    return (it != pImpl_->metrics_.end()) ? it->second.get() : nullptr;
}

std::vector<std::wstring> PerformanceHUD::GetMetricNames() const {
    std::vector<std::wstring> names;
    for (const auto& [name, _] : pImpl_->metrics_) {
        names.push_back(name);
    }
    return names;
}

void PerformanceHUD::AddWidget(const HUDWidgetConfig& config) {
    pImpl_->widgets_.push_back(std::make_unique<HUDWidget>(config));
}

void PerformanceHUD::RemoveWidget(size_t index) {
    if (index < pImpl_->widgets_.size()) {
        pImpl_->widgets_.erase(pImpl_->widgets_.begin() + index);
    }
}

void PerformanceHUD::ClearWidgets() {
    pImpl_->widgets_.clear();
}

std::vector<HUDWidget*>& PerformanceHUD::GetWidgets() {
    static std::vector<HUDWidget*> widgetPtrs;
    widgetPtrs.clear();
    for (const auto& widget : pImpl_->widgets_) {
        widgetPtrs.push_back(widget.get());
    }
    return widgetPtrs;
}

void PerformanceHUD::RecordMetric(const std::wstring& name, double value, const std::wstring& label) {
    auto* metric = GetMetric(name);
    if (metric) {
        metric->RecordValue(value, label);
        
        if (pImpl_->telemetryCallback_) {
            pImpl_->telemetryCallback_(name, value);
        }
    }
}

void PerformanceHUD::RecordKernelLatency(const std::wstring& kernelName, double microseconds) {
    RecordMetric(L"lora_latency", microseconds, kernelName);
}

void PerformanceHUD::RecordMemoryBandwidth(double gigabytesPerSecond) {
    RecordMetric(L"memory_bandwidth", gigabytesPerSecond);
}

void PerformanceHUD::RecordTPS(double tokensPerSecond) {
    RecordMetric(L"tps", tokensPerSecond);
}

void PerformanceHUD::RecordGPUUtilization(double percentage) {
    RecordMetric(L"gpu_util", percentage);
}

void PerformanceHUD::Render(HDC hdc, const RECT& panelRect) {
    // Fill background
    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &panelRect, bgBrush);
    DeleteObject(bgBrush);
    
    // Draw title bar
    RECT titleRect = { panelRect.left, panelRect.top, panelRect.right, panelRect.top + 30 };
    HBRUSH titleBrush = CreateSolidBrush(RGB(50, 50, 50));
    FillRect(hdc, &titleRect, titleBrush);
    DeleteObject(titleBrush);
    
    HFONT titleFont = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT oldFont = (HFONT)SelectObject(hdc, titleFont);
    SetTextColor(hdc, RGB(200, 200, 200));
    SetBkMode(hdc, TRANSPARENT);
    DrawTextW(hdc, L"Performance HUD", -1, &titleRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldFont);
    DeleteObject(titleFont);
    
    // Render widgets
    for (const auto& widget : pImpl_->widgets_) {
        const auto& config = widget->GetConfig();
        RECT widgetRect = {
            panelRect.left + config.position.left,
            panelRect.top + config.position.top,
            panelRect.left + config.position.right,
            panelRect.top + config.position.bottom
        };
        widget->Render(hdc, widgetRect);
    }
}

void PerformanceHUD::Invalidate() {
    if (pImpl_->hwnd_) {
        ::InvalidateRect(pImpl_->hwnd_, nullptr, TRUE);
    }
}

void PerformanceHUD::SetTelemetryCallback(TelemetryCallback callback) {
    pImpl_->telemetryCallback_ = callback;
}

void PerformanceHUD::Show() {
    pImpl_->visible_ = true;
    if (pImpl_->hwnd_) {
        ShowWindow(pImpl_->hwnd_, SW_SHOW);
    }
}

void PerformanceHUD::Hide() {
    pImpl_->visible_ = false;
    if (pImpl_->hwnd_) {
        ShowWindow(pImpl_->hwnd_, SW_HIDE);
    }
}

bool PerformanceHUD::IsVisible() const {
    return pImpl_->visible_;
}

void PerformanceHUD::Toggle() {
    if (IsVisible()) {
        Hide();
    } else {
        Show();
    }
}

SIZE PerformanceHUD::GetPreferredSize() const {
    return { 800, 450 };
}

void PerformanceHUD::SetSize(int width, int height) {
    pImpl_->width_ = width;
    pImpl_->height_ = height;
}

// ============================================================================
// Metric Presets
// ============================================================================
namespace MetricPresets {

MetricConfig LoRAKernelLatency() {
    MetricConfig config;
    config.name = L"LoRA Kernel Latency";
    config.unit = L"µs";
    config.type = MetricType::Latency;
    config.minValue = 0.0;
    config.maxValue = 100.0;  // 100 µs max
    config.warningThreshold = 50.0;   // 50 µs
    config.criticalThreshold = 80.0;  // 80 µs
    config.normalColor = RGB(0, 255, 0);      // Green for fast
    config.warningColor = RGB(255, 165, 0);   // Orange
    config.criticalColor = RGB(255, 0, 0);    // Red for slow
    return config;
}

MetricConfig MemoryBandwidth() {
    MetricConfig config;
    config.name = L"Memory Bandwidth";
    config.unit = L"GB/s";
    config.type = MetricType::Throughput;
    config.minValue = 0.0;
    config.maxValue = 100.0;  // 100 GB/s max
    config.warningThreshold = 70.0;
    config.criticalThreshold = 90.0;
    return config;
}

MetricConfig TokenThroughput() {
    MetricConfig config;
    config.name = L"Token Throughput";
    config.unit = L"TPS";
    config.type = MetricType::Throughput;
    config.minValue = 0.0;
    config.maxValue = 500.0;  // 500 TPS max
    config.warningThreshold = 80.0;
    config.criticalThreshold = 95.0;
    return config;
}

MetricConfig GPUUtilization() {
    MetricConfig config;
    config.name = L"GPU Utilization";
    config.unit = L"%";
    config.type = MetricType::Utilization;
    config.minValue = 0.0;
    config.maxValue = 100.0;
    config.warningThreshold = 80.0;
    config.criticalThreshold = 95.0;
    return config;
}

MetricConfig CPUUtilization() {
    MetricConfig config;
    config.name = L"CPU Utilization";
    config.unit = L"%";
    config.type = MetricType::Utilization;
    config.minValue = 0.0;
    config.maxValue = 100.0;
    config.warningThreshold = 70.0;
    config.criticalThreshold = 90.0;
    return config;
}

MetricConfig MemoryUsage() {
    MetricConfig config;
    config.name = L"Memory Usage";
    config.unit = L"MB";
    config.type = MetricType::Memory;
    config.minValue = 0.0;
    config.maxValue = 65536.0;  // 64 GB max
    config.warningThreshold = 80.0;
    config.criticalThreshold = 95.0;
    return config;
}

MetricConfig ThreadPoolActivity() {
    MetricConfig config;
    config.name = L"Thread Pool Activity";
    config.unit = L"threads";
    config.type = MetricType::Counter;
    config.minValue = 0.0;
    config.maxValue = 64.0;
    config.warningThreshold = 75.0;
    config.criticalThreshold = 90.0;
    return config;
}

MetricConfig InferenceQueueDepth() {
    MetricConfig config;
    config.name = L"Inference Queue";
    config.unit = L"requests";
    config.type = MetricType::Counter;
    config.minValue = 0.0;
    config.maxValue = 100.0;
    config.warningThreshold = 70.0;
    config.criticalThreshold = 90.0;
    return config;
}

} // namespace MetricPresets

// ============================================================================
// Global Access
// ============================================================================
static std::unique_ptr<PerformanceHUD> g_performanceHUD;

PerformanceHUD* GetPerformanceHUD() {
    return g_performanceHUD.get();
}

bool InitializePerformanceHUD(HWND parentWindow) {
    g_performanceHUD = std::make_unique<PerformanceHUD>();
    return g_performanceHUD->Initialize(parentWindow);
}

void ShutdownPerformanceHUD() {
    if (g_performanceHUD) {
        g_performanceHUD->Shutdown();
        g_performanceHUD.reset();
    }
}

} // namespace UI
} // namespace RawrXD
