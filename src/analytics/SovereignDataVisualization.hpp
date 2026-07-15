// Phase D.18 Batch 5/5: Data Visualization
// Dashboards, charts, and visual analytics
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Analytics {

// Forward declarations
struct Dashboard;
struct ChartConfig;
struct VisualizationData;

// ============================================================================
// Data Visualization Types
// ============================================================================

enum class ChartType {
    LINE = 0,
    BAR = 1,
    PIE = 2,
    SCATTER = 3,
    AREA = 4,
    HEATMAP = 5,
    GAUGE = 6,
    TABLE = 7,
    CUSTOM = 8
};

enum class TimeRange {
    LAST_5_MINUTES = 0,
    LAST_15_MINUTES = 1,
    LAST_30_MINUTES = 2,
    LAST_HOUR = 3,
    LAST_3_HOURS = 4,
    LAST_6_HOURS = 5,
    LAST_12_HOURS = 6,
    LAST_24_HOURS = 7,
    LAST_7_DAYS = 8,
    LAST_30_DAYS = 9,
    CUSTOM = 10
};

struct ChartConfig {
    std::string chart_id;
    std::string title;
    ChartType type;
    std::string data_source;
    std::map<std::string, std::string> query_params;
    std::map<std::string, std::any> visual_config;
    TimeRange time_range;
    std::chrono::seconds refresh_interval;
    bool auto_refresh;
};

struct Dashboard {
    std::string dashboard_id;
    std::string name;
    std::string description;
    std::vector<ChartConfig> charts;
    std::map<std::string, std::any> layout;
    std::vector<std::string> tags;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    bool is_public;
    std::string owner;
};

struct VisualizationData {
    std::string data_id;
    std::vector<std::map<std::string, std::any>> series;
    std::vector<std::string> labels;
    std::map<std::string, std::any> metadata;
    std::chrono::steady_clock::time_point generated_at;
};

// ============================================================================
// Dashboard Manager
// ============================================================================

class DashboardManager {
public:
    struct Config {
        int max_dashboards_per_user = 50;
        int max_charts_per_dashboard = 20;
        bool enable_templates = true;
    };
    
    explicit DashboardManager(const Config& config);
    ~DashboardManager();
    
    bool Initialize();
    void Shutdown();
    
    // Dashboard CRUD
    std::string CreateDashboard(const std::string& name, const std::string& owner);
    bool UpdateDashboard(const std::string& dashboard_id, const Dashboard& dashboard);
    bool DeleteDashboard(const std::string& dashboard_id);
    Dashboard GetDashboard(const std::string& dashboard_id) const;
    
    // Chart management
    std::string AddChart(const std::string& dashboard_id, const ChartConfig& chart);
    bool UpdateChart(const std::string& dashboard_id, const std::string& chart_id, 
                     const ChartConfig& chart);
    bool RemoveChart(const std::string& dashboard_id, const std::string& chart_id);
    bool ReorderCharts(const std::string& dashboard_id, const std::vector<std::string>& order);
    
    // Templates
    std::vector<Dashboard> GetTemplates() const;
    std::string CreateFromTemplate(const std::string& template_id, const std::string& owner);
    
    // Queries
    std::vector<Dashboard> GetDashboardsByOwner(const std::string& owner) const;
    std::vector<Dashboard> GetDashboardsByTag(const std::string& tag) const;
    std::vector<Dashboard> GetPublicDashboards() const;
    
private:
    Config config_;
    std::map<std::string, Dashboard> dashboards_;
    mutable std::mutex dashboards_mutex_;
    
    std::string GenerateDashboardId();
    std::string GenerateChartId();
};

// ============================================================================
// Chart Renderer
// ============================================================================

class ChartRenderer {
public:
    struct Config {
        std::string output_format = "svg";
        int width = 800;
        int height = 400;
        bool interactive = true;
    };
    
    struct RenderResult {
        bool success;
        std::vector<uint8_t> data;
        std::string mime_type;
        std::string error_message;
    };
    
    explicit ChartRenderer(const Config& config);
    ~ChartRenderer();
    
    bool Initialize();
    void Shutdown();
    
    // Rendering
    RenderResult RenderChart(const ChartConfig& config, const VisualizationData& data);
    RenderResult RenderToSVG(const ChartConfig& config, const VisualizationData& data);
    RenderResult RenderToPNG(const ChartConfig& config, const VisualizationData& data);
    RenderResult RenderToJSON(const ChartConfig& config, const VisualizationData& data);
    
    // Chart types
    RenderResult RenderLineChart(const VisualizationData& data, const std::map<std::string, std::any>& config);
    RenderResult RenderBarChart(const VisualizationData& data, const std::map<std::string, std::any>& config);
    RenderResult RenderPieChart(const VisualizationData& data, const std::map<std::string, std::any>& config);
    RenderResult RenderScatterPlot(const VisualizationData& data, const std::map<std::string, std::any>& config);
    RenderResult RenderHeatmap(const VisualizationData& data, const std::map<std::string, std::any>& config);
    RenderResult RenderGauge(const VisualizationData& data, const std::map<std::string, std::any>& config);
    
private:
    Config config_;
    
    std::string GenerateSVG(const ChartConfig& config, const VisualizationData& data);
    std::string GenerateChartJSConfig(const ChartConfig& config, const VisualizationData& data);
};

// ============================================================================
// Data Query Engine
// ============================================================================

class DataQueryEngine {
public:
    struct Config {
        std::chrono::seconds query_timeout{30};
        int max_query_results = 10000;
        bool enable_caching = true;
        std::chrono::seconds cache_ttl{300};
    };
    
    struct QueryRequest {
        std::string query_id;
        std::string data_source;
        std::string query_string;
        std::map<std::string, std::any> parameters;
        TimeRange time_range;
        std::chrono::steady_clock::time_point requested_at;
    };
    
    struct QueryResult {
        bool success;
        VisualizationData data;
        std::chrono::milliseconds execution_time;
        std::string error_message;
    };
    
    explicit DataQueryEngine(const Config& config);
    ~DataQueryEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Query execution
    QueryResult ExecuteQuery(const QueryRequest& request);
    QueryResult ExecuteQueryAsync(const QueryRequest& request);
    
    // Query building
    std::string BuildTimeSeriesQuery(const std::string& metric, TimeRange range);
    std::string BuildAggregationQuery(const std::string& metric, 
                                       AggregationFunction function,
                                       std::chrono::seconds interval);
    std::string BuildTopNQuery(const std::string& dimension, int n);
    
    // Data sources
    bool RegisterDataSource(const std::string& name, const std::string& connection_string);
    bool UnregisterDataSource(const std::string& name);
    std::vector<std::string> GetDataSources() const;
    
private:
    Config config_;
    std::map<std::string, std::string> data_sources_;
    std::map<std::string, std::pair<QueryResult, std::chrono::steady_clock::time_point>> cache_;
    mutable std::mutex query_mutex_;
    
    QueryResult ExecuteTimeSeriesQuery(const QueryRequest& request);
    QueryResult ExecuteMetricQuery(const QueryRequest& request);
    std::chrono::steady_clock::time_point TimeRangeToStart(TimeRange range);
};

// ============================================================================
// Real-Time Updates
// ============================================================================

class RealTimeUpdates {
public:
    struct Config {
        int max_subscriptions = 1000;
        std::chrono::milliseconds update_interval{1000};
        bool enable_websocket = true;
    };
    
    struct Subscription {
        std::string subscription_id;
        std::string chart_id;
        std::string client_id;
        std::chrono::steady_clock::time_point subscribed_at;
        std::chrono::steady_clock::time_point last_update;
    };
    
    explicit RealTimeUpdates(const Config& config);
    ~RealTimeUpdates();
    
    bool Initialize();
    void Shutdown();
    
    // Subscription management
    std::string Subscribe(const std::string& chart_id, const std::string& client_id);
    bool Unsubscribe(const std::string& subscription_id);
    bool UnsubscribeClient(const std::string& client_id);
    
    // Updates
    bool PushUpdate(const std::string& chart_id, const VisualizationData& data);
    bool BroadcastUpdate(const std::vector<std::string>& chart_ids, const VisualizationData& data);
    
    // Queries
    std::vector<Subscription> GetSubscriptions(const std::string& chart_id) const;
    std::vector<Subscription> GetClientSubscriptions(const std::string& client_id) const;
    
private:
    Config config_;
    std::map<std::string, Subscription> subscriptions_;
    mutable std::mutex subscriptions_mutex_;
    std::thread update_thread_;
    std::atomic<bool> running_{false};
    
    void UpdateLoop();
    void NotifySubscribers(const std::string& chart_id, const VisualizationData& data);
};

// ============================================================================
// Export Manager
// ============================================================================

class ExportManager {
public:
    struct Config {
        int max_export_size_mb = 100;
        std::vector<std::string> supported_formats = {"csv", "json", "xlsx", "pdf"};
        std::string export_directory;
    };
    
    struct ExportRequest {
        std::string export_id;
        std::string dashboard_id;
        std::string format;
        TimeRange time_range;
        bool include_charts;
        bool include_data;
        std::map<std::string, std::any> options;
    };
    
    struct ExportResult {
        bool success;
        std::string file_path;
        size_t file_size;
        std::string mime_type;
        std::string error_message;
    };
    
    explicit ExportManager(const Config& config);
    ~ExportManager();
    
    bool Initialize();
    void Shutdown();
    
    // Export operations
    ExportResult ExportDashboard(const ExportRequest& request);
    ExportResult ExportChart(const std::string& chart_id, const std::string& format);
    ExportResult ExportData(const QueryRequest& query, const std::string& format);
    
    // Formats
    ExportResult ExportToCSV(const VisualizationData& data, const std::string& file_path);
    ExportResult ExportToJSON(const VisualizationData& data, const std::string& file_path);
    ExportResult ExportToExcel(const Dashboard& dashboard, const std::string& file_path);
    ExportResult ExportToPDF(const Dashboard& dashboard, const std::string& file_path);
    
    // Scheduling
    std::string ScheduleExport(const ExportRequest& request, std::chrono::hours interval);
    bool CancelScheduledExport(const std::string& schedule_id);
    
private:
    Config config_;
    std::map<std::string, std::chrono::steady_clock::time_point> scheduled_exports_;
    mutable std::mutex export_mutex_;
    
    std::string GenerateExportPath(const std::string& format);
};

// ============================================================================
// Data Visualization Runtime
// ============================================================================

class DataVisualizationRuntime {
public:
    struct Config {
        DashboardManager::Config dashboard;
        ChartRenderer::Config renderer;
        DataQueryEngine::Config query;
        RealTimeUpdates::Config updates;
        ExportManager::Config export_mgr;
    };
    
    explicit DataVisualizationRuntime(const Config& config);
    ~DataVisualizationRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    DashboardManager* GetDashboardManager();
    ChartRenderer* GetChartRenderer();
    DataQueryEngine* GetQueryEngine();
    RealTimeUpdates* GetRealTimeUpdates();
    ExportManager* GetExportManager();
    
    // High-level API
    std::string CreateDashboard(const std::string& name, const std::string& owner);
    std::string AddChart(const std::string& dashboard_id, ChartType type, 
                         const std::string& title, const std::string& data_source);
    
    VisualizationData QueryData(const std::string& query, TimeRange range);
    std::vector<uint8_t> RenderChart(const std::string& chart_id);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<DashboardManager> dashboard_manager_;
    std::unique_ptr<ChartRenderer> chart_renderer_;
    std::unique_ptr<DataQueryEngine> query_engine_;
    std::unique_ptr<RealTimeUpdates> real_time_updates_;
    std::unique_ptr<ExportManager> export_manager_;
};

} // namespace Analytics
} // namespace Sovereign
