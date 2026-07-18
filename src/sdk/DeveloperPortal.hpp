/**
 * DeveloperPortal.hpp
 *
 * Phase Q Batch 4/5: Developer Portal
 *
 * Self-service developer portal with API explorer, documentation,
 * analytics dashboard, and application management.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace SDK {

// ============================================================================
// Forward Declarations
// ============================================================================

class DeveloperPortal;
class APIExplorer;
class DocumentationEngine;
class AnalyticsDashboard;
class ApplicationManager;
class APICatalog;

// ============================================================================
// Portal User
// ============================================================================

struct PortalUser {
    std::string userId;
    std::string email;
    std::string displayName;
    std::string organization;
    std::vector<std::string> roles;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastLogin;
    bool emailVerified;
    std::map<std::string, std::string> preferences;
};

// ============================================================================
// API Key
// ============================================================================

struct APIKey {
    std::string keyId;
    std::string keyHash;  // Only store hash, never plaintext
    std::string name;
    std::string description;
    std::string ownerId;
    std::vector<std::string> permissions;
    std::vector<std::string> allowedIPs;
    std::optional<std::string> allowedReferrer;
    std::chrono::system_clock::time_point createdAt;
    std::optional<std::chrono::system_clock::time_point> expiresAt;
    std::chrono::system_clock::time_point lastUsedAt;
    uint64_t requestCount;
    bool active;
};

// ============================================================================
// Application
// ============================================================================

struct Application {
    std::string appId;
    std::string name;
    std::string description;
    std::string ownerId;
    std::vector<std::string> apiKeys;
    std::map<std::string, std::string> settings;
    std::vector<std::string> webhookEndpoints;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    bool active;
    
    struct Stats {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        double averageLatencyMs;
        std::chrono::system_clock::time_point lastRequestAt;
    };
    Stats stats;
};

// ============================================================================
// API Endpoint Definition
// ============================================================================

struct APIEndpoint {
    std::string path;
    std::string method;
    std::string summary;
    std::string description;
    std::string category;
    std::vector<std::string> tags;
    
    struct Parameter {
        std::string name;
        std::string in;  // query, path, header, body
        std::string type;
        bool required;
        std::string description;
        std::optional<std::string> defaultValue;
        std::vector<std::string> enumValues;
    };
    std::vector<Parameter> parameters;
    
    struct Response {
        int statusCode;
        std::string description;
        std::string schema;  // JSON schema
        std::optional<std::string> example;
    };
    std::vector<Response> responses;
    
    std::vector<std::string> requiredPermissions;
    bool deprecated;
    std::optional<std::string> deprecationMessage;
};

// ============================================================================
// API Catalog
// ============================================================================

class APICatalog {
public:
    APICatalog();
    
    // Registration
    void RegisterEndpoint(const APIEndpoint& endpoint);
    void RegisterEndpoints(const std::vector<APIEndpoint>& endpoints);
    void RemoveEndpoint(const std::string& path, const std::string& method);
    
    // Discovery
    std::vector<APIEndpoint> GetAllEndpoints() const;
    std::vector<APIEndpoint> GetEndpointsByCategory(const std::string& category) const;
    std::vector<APIEndpoint> GetEndpointsByTag(const std::string& tag) const;
    std::optional<APIEndpoint> GetEndpoint(const std::string& path, 
                                           const std::string& method) const;
    
    // Search
    std::vector<APIEndpoint> Search(const std::string& query) const;
    std::vector<APIEndpoint> SearchByPermission(const std::string& permission) const;
    
    // OpenAPI generation
    std::string GenerateOpenAPISpec() const;
    std::string GenerateOpenAPISpec(const std::vector<std::string>& categories) const;
    
    // Categories and tags
    std::vector<std::string> GetCategories() const;
    std::vector<std::string> GetTags() const;
    
private:
    std::map<std::string, APIEndpoint> endpoints_;  // key: "METHOD:PATH"
    mutable std::mutex mutex_;
};

// ============================================================================
// API Explorer
// ============================================================================

class APIExplorer {
public:
    struct RequestConfig {
        std::string method;
        std::string path;
        std::map<std::string, std::string> headers;
        std::map<std::string, std::string> queryParams;
        std::optional<std::string> body;
        std::optional<std::string> apiKey;
    };
    
    struct ResponseView {
        int statusCode;
        std::map<std::string, std::string> headers;
        std::string body;
        std::chrono::milliseconds responseTime;
        std::string formattedBody;  // Pretty-printed
    };
    
    struct ExecutionHistory {
        std::string requestId;
        RequestConfig request;
        ResponseView response;
        std::chrono::system_clock::time_point executedAt;
        bool success;
    };
    
    explicit APIExplorer(std::shared_ptr<APIClient> client);
    
    // Request building
    void SetBaseUrl(const std::string& url);
    void SetDefaultHeaders(const std::map<std::string, std::string>& headers);
    void SetAPIKey(const std::string& apiKey);
    
    // Execution
    ResponseView Execute(const RequestConfig& config);
    std::future<ResponseView> ExecuteAsync(const RequestConfig& config);
    
    // Code generation
    std::string GenerateCurlCommand(const RequestConfig& config) const;
    std::string GeneratePythonCode(const RequestConfig& config) const;
    std::string GenerateJavaScriptCode(const RequestConfig& config) const;
    std::string GenerateGoCode(const RequestConfig& config) const;
    std::string GenerateCSharpCode(const RequestConfig& config) const;
    std::string GenerateJavaCode(const RequestConfig& config) const;
    std::string GenerateRubyCode(const RequestConfig& config) const;
    std::string GeneratePHPCode(const RequestConfig& config) const;
    
    // History
    void SaveToHistory(const ExecutionHistory& history);
    std::vector<ExecutionHistory> GetHistory(size_t limit = 100) const;
    void ClearHistory();
    void DeleteFromHistory(const std::string& requestId);
    
    // Collections
    void SaveRequest(const std::string& collectionName, 
                     const std::string& requestName,
                     const RequestConfig& config);
    std::vector<RequestConfig> GetCollection(const std::string& collectionName) const;
    std::vector<std::string> GetCollections() const;
    
private:
    std::shared_ptr<APIClient> client_;
    std::string baseUrl_;
    std::map<std::string, std::string> defaultHeaders_;
    std::optional<std::string> apiKey_;
    
    std::vector<ExecutionHistory> history_;
    mutable std::mutex historyMutex_;
    
    std::map<std::string, std::vector<std::pair<std::string, RequestConfig>>> collections_;
    mutable std::mutex collectionsMutex_;
};

// ============================================================================
// Documentation Engine
// ============================================================================

class DocumentationEngine {
public:
    struct DocPage {
        std::string id;
        std::string title;
        std::string content;  // Markdown
        std::string category;
        std::vector<std::string> tags;
        std::chrono::system_clock::time_point createdAt;
        std::chrono::system_clock::time_point updatedAt;
        std::string author;
        bool published;
    };
    
    struct CodeExample {
        std::string id;
        std::string title;
        std::string description;
        std::string language;
        std::string code;
        std::optional<std::string> output;
        std::vector<std::string> tags;
    };
    
    struct Tutorial {
        std::string id;
        std::string title;
        std::string description;
        std::vector<std::string> steps;
        std::string difficulty;  // beginner, intermediate, advanced
        std::chrono::minutes estimatedTime;
        std::vector<std::string> prerequisites;
        std::vector<std::string> tags;
        bool interactive;
    };
    
    DocumentationEngine();
    
    // Page management
    void CreatePage(const DocPage& page);
    void UpdatePage(const std::string& id, const DocPage& page);
    void DeletePage(const std::string& id);
    std::optional<DocPage> GetPage(const std::string& id) const;
    std::vector<DocPage> GetPagesByCategory(const std::string& category) const;
    std::vector<DocPage> SearchPages(const std::string& query) const;
    
    // Code examples
    void AddCodeExample(const CodeExample& example);
    void UpdateCodeExample(const std::string& id, const CodeExample& example);
    void DeleteCodeExample(const std::string& id);
    std::vector<CodeExample> GetCodeExamples(const std::string& language) const;
    std::vector<CodeExample> GetCodeExamplesByTag(const std::string& tag) const;
    
    // Tutorials
    void CreateTutorial(const Tutorial& tutorial);
    void UpdateTutorial(const std::string& id, const Tutorial& tutorial);
    void DeleteTutorial(const std::string& id);
    std::optional<Tutorial> GetTutorial(const std::string& id) const;
    std::vector<Tutorial> GetTutorialsByDifficulty(const std::string& difficulty) const;
    std::vector<Tutorial> GetTutorialsByTag(const std::string& tag) const;
    
    // Rendering
    std::string RenderMarkdown(const std::string& markdown) const;
    std::string RenderCodeBlock(const std::string& code, 
                                 const std::string& language) const;
    std::string GenerateTOC(const std::string& content) const;
    
    // Search index
    void BuildSearchIndex();
    std::vector<std::pair<std::string, float>> Search(const std::string& query) const;
    
private:
    std::map<std::string, DocPage> pages_;
    std::map<std::string, CodeExample> examples_;
    std::map<std::string, Tutorial> tutorials_;
    mutable std::mutex mutex_;
    
    // Simple search index
    std::map<std::string, std::vector<std::string>> searchIndex_;
};

// ============================================================================
// Analytics Dashboard
// ============================================================================

class AnalyticsDashboard {
public:
    struct TimeRange {
        std::chrono::system_clock::time_point start;
        std::chrono::system_clock::time_point end;
    };
    
    struct MetricValue {
        std::chrono::system_clock::time_point timestamp;
        double value;
        std::map<std::string, std::string> labels;
    };
    
    struct TimeSeries {
        std::string metricName;
        std::string description;
        std::vector<MetricValue> values;
    };
    
    struct APIMetrics {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        double successRate;
        double averageLatencyMs;
        double p50LatencyMs;
        double p95LatencyMs;
        double p99LatencyMs;
        std::map<int, uint64_t> statusCodeDistribution;
        std::map<std::string, uint64_t> endpointUsage;
        std::map<std::string, uint64_t> errorBreakdown;
    };
    
    struct UsageQuota {
        std::string metricName;
        uint64_t currentUsage;
        uint64_t quota;
        double percentageUsed;
        std::chrono::system_clock::time_point resetsAt;
    };
    
    explicit AnalyticsDashboard(std::shared_ptr<APIClient> client);
    
    // Time series data
    TimeSeries GetTimeSeries(const std::string& metric,
                             const TimeRange& range,
                             std::chrono::seconds granularity) const;
    
    // API metrics
    APIMetrics GetAPIMetrics(const TimeRange& range) const;
    APIMetrics GetAPIMetricsForEndpoint(const std::string& path,
                                        const std::string& method,
                                        const TimeRange& range) const;
    
    // Usage quotas
    std::vector<UsageQuota> GetUsageQuotas() const;
    UsageQuota GetUsageQuota(const std::string& metricName) const;
    
    // Real-time metrics
    struct RealTimeMetrics {
        uint64_t requestsPerSecond;
        uint64_t activeConnections;
        double currentErrorRate;
        double averageLatencyMs;
    };
    RealTimeMetrics GetRealTimeMetrics() const;
    
    // Export
    std::string ExportToCSV(const TimeRange& range) const;
    std::string ExportToJSON(const TimeRange& range) const;
    void ExportToPDF(const std::string& outputPath, const TimeRange& range) const;
    
    // Alerts
    struct Alert {
        std::string alertId;
        std::string name;
        std::string metric;
        std::string condition;  // >, <, ==, >=, <=
        double threshold;
        std::string severity;  // info, warning, critical
        bool enabled;
        std::vector<std::string> notificationChannels;
    };
    
    void CreateAlert(const Alert& alert);
    void UpdateAlert(const std::string& alertId, const Alert& alert);
    void DeleteAlert(const std::string& alertId);
    std::vector<Alert> GetAlerts() const;
    
    // Dashboards
    struct Dashboard {
        std::string id;
        std::string name;
        std::string description;
        std::vector<std::string> widgetIds;
        std::chrono::system_clock::time_point createdAt;
        std::chrono::system_clock::time_point updatedAt;
    };
    
    void CreateDashboard(const Dashboard& dashboard);
    void UpdateDashboard(const std::string& id, const Dashboard& dashboard);
    void DeleteDashboard(const std::string& id);
    std::optional<Dashboard> GetDashboard(const std::string& id) const;
    std::vector<Dashboard> GetDashboards() const;
    
private:
    std::shared_ptr<APIClient> client_;
    
    std::map<std::string, Alert> alerts_;
    std::map<std::string, Dashboard> dashboards_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Application Manager
// ============================================================================

class ApplicationManager {
public:
    explicit ApplicationManager(std::shared_ptr<APIClient> client);
    
    // Application lifecycle
    std::string CreateApplication(const std::string& name,
                                   const std::string& description,
                                   const std::string& ownerId);
    void UpdateApplication(const std::string& appId,
                           const std::map<std::string, std::string>& updates);
    void DeleteApplication(const std::string& appId);
    std::optional<Application> GetApplication(const std::string& appId) const;
    std::vector<Application> GetApplicationsForUser(const std::string& userId) const;
    
    // API Key management
    struct CreateKeyResult {
        std::string keyId;
        std::string apiKey;  // Only returned once at creation
    };
    
    CreateKeyResult CreateAPIKey(const std::string& appId,
                                  const std::string& name,
                                  const std::string& description,
                                  const std::vector<std::string>& permissions);
    void RevokeAPIKey(const std::string& keyId);
    void RotateAPIKey(const std::string& keyId);
    std::vector<APIKey> GetAPIKeys(const std::string& appId) const;
    void UpdateAPIKeyPermissions(const std::string& keyId,
                                    const std::vector<std::string>& permissions);
    
    // Settings
    void UpdateApplicationSettings(const std::string& appId,
                                    const std::map<std::string, std::string>& settings);
    std::map<std::string, std::string> GetApplicationSettings(const std::string& appId) const;
    
    // Webhooks
    void ConfigureWebhook(const std::string& appId,
                          const std::string& endpointUrl,
                          const std::vector<std::string>& eventTypes);
    void RemoveWebhook(const std::string& appId, const std::string& endpointUrl);
    std::vector<std::string> GetWebhooks(const std::string& appId) const;
    
    // Analytics
    Application::Stats GetApplicationStats(const std::string& appId,
                                            std::chrono::system_clock::time_point from,
                                            std::chrono::system_clock::time_point to) const;
    
private:
    std::shared_ptr<APIClient> client_;
    
    std::map<std::string, Application> applications_;
    std::map<std::string, APIKey> apiKeys_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Developer Portal
// ============================================================================

class DeveloperPortal {
public:
    struct Config {
        std::string portalUrl;
        std::string apiEndpoint;
        bool enableAnalytics = true;
        bool enableInteractiveDocs = true;
        bool enableCodeGeneration = true;
        bool enableSandbox = true;
        std::chrono::seconds sessionTimeout{3600};
    };
    
    explicit DeveloperPortal(const Config& config);
    ~DeveloperPortal();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Components
    APICatalog* GetAPICatalog() { return apiCatalog_.get(); }
    APIExplorer* GetAPIExplorer() { return apiExplorer_.get(); }
    DocumentationEngine* GetDocumentation() { return documentation_.get(); }
    AnalyticsDashboard* GetAnalytics() { return analytics_.get(); }
    ApplicationManager* GetApplicationManager() { return appManager_.get(); }
    
    // User management
    PortalUser GetCurrentUser() const;
    void UpdateUserProfile(const std::map<std::string, std::string>& updates);
    void ChangePassword(const std::string& oldPassword, const std::string& newPassword);
    
    // Authentication
    bool Login(const std::string& email, const std::string& password);
    void Logout();
    bool IsLoggedIn() const;
    void RefreshSession();
    
    // Notifications
    struct Notification {
        std::string id;
        std::string type;
        std::string title;
        std::string message;
        std::chrono::system_clock::time_point createdAt;
        bool read;
        std::optional<std::string> actionUrl;
    };
    
    std::vector<Notification> GetNotifications() const;
    void MarkNotificationRead(const std::string& notificationId);
    void ClearNotifications();
    
    // Support
    void SubmitSupportTicket(const std::string& subject,
                              const std::string& message,
                              const std::optional<std::string>& category = std::nullopt);
    std::vector<std::pair<std::string, std::string>> GetSupportTickets() const;
    
    // Feedback
    void SubmitFeedback(const std::string& type,
                        const std::string& message,
                        const std::optional<std::string>& context = std::nullopt);
    
private:
    Config config_;
    bool initialized_;
    
    std::unique_ptr<APICatalog> apiCatalog_;
    std::unique_ptr<APIExplorer> apiExplorer_;
    std::unique_ptr<DocumentationEngine> documentation_;
    std::unique_ptr<AnalyticsDashboard> analytics_;
    std::unique_ptr<ApplicationManager> appManager_;
    
    std::shared_ptr<APIClient> apiClient_;
    std::optional<PortalUser> currentUser_;
    mutable std::mutex mutex_;
};

} // namespace SDK
