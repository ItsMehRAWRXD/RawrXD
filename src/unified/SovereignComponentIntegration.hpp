// Phase D.9 Batch 2/5: Component Integration & Event Bus
// Integration layer connecting all Sovereign phases
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <queue>
#include <any>

namespace Sovereign {
namespace Unified {

// ============================================================================
// Event Bus
// ============================================================================

enum class EventPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

struct Event {
    std::string id;
    std::string type;
    std::string source;
    std::any payload;
    EventPriority priority = EventPriority::NORMAL;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
    std::string correlation_id;
    std::string causation_id;
};

class EventBus {
public:
    struct Config {
        size_t max_queue_size = 10000;
        int worker_threads = 4;
        std::chrono::milliseconds event_timeout{30000};
        bool persistent_events = false;
        std::string persistence_path;
    };
    
    explicit EventBus(const Config& config);
    ~EventBus();
    
    bool Initialize();
    void Shutdown();
    
    // Publishing
    bool Publish(const Event& event);
    bool PublishAsync(const Event& event);
    bool PublishDelayed(const Event& event, std::chrono::milliseconds delay);
    
    // Subscribing
    using EventHandler = std::function<void(const Event& event)>;
    std::string Subscribe(const std::string& event_type, EventHandler handler);
    std::string SubscribePattern(const std::string& pattern, EventHandler handler);
    bool Unsubscribe(const std::string& subscription_id);
    
    // Request/Response
    using RequestHandler = std::function<std::any(const std::any& request)>;
    bool RegisterRequestHandler(const std::string& request_type, RequestHandler handler);
    std::any Request(const std::string& request_type, const std::any& payload,
                     std::chrono::milliseconds timeout);
    
    // Event replay
    std::vector<Event> GetEvents(const std::string& event_type,
                                     std::chrono::steady_clock::time_point from,
                                     std::chrono::steady_clock::time_point to);
    bool ReplayEvents(const std::vector<Event>& events);
    
    // Statistics
    size_t GetQueueSize() const;
    size_t GetSubscriberCount(const std::string& event_type) const;
    std::map<std::string, size_t> GetEventCounts() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Subscription {
        std::string id;
        std::string pattern;
        EventHandler handler;
    };
    
    std::priority_queue<Event, std::vector<Event>,
                        std::function<bool(const Event&, const Event&)>> event_queue_;
    std::map<std::string, std::vector<Subscription>> subscriptions_;
    std::map<std::string, RequestHandler> request_handlers_;
    std::mutex queue_mutex_;
    std::mutex subscriptions_mutex_;
    
    std::vector<std::thread> worker_threads_;
    std::condition_variable queue_cv_;
    
    std::map<std::string, size_t> event_counts_;
    std::mutex counts_mutex_;
    
    void WorkerLoop();
    void ProcessEvent(const Event& event);
    std::vector<Subscription> FindSubscriptions(const std::string& event_type);
    bool MatchesPattern(const std::string& event_type, const std::string& pattern);
};

// ============================================================================
// Component Adapter Interface
// ============================================================================

class ComponentAdapter {
public:
    virtual ~ComponentAdapter() = default;
    
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
    
    virtual bool Initialize(const std::map<std::string, std::string>& config) = 0;
    virtual void Shutdown() = 0;
    
    virtual bool Start() = 0;
    virtual void Stop() = 0;
    
    virtual bool IsHealthy() const = 0;
    virtual std::map<std::string, std::string> GetHealthDetails() const = 0;
    
    virtual std::map<std::string, std::any> GetMetrics() const = 0;
    
    virtual void OnEvent(const Event& event) {}
    virtual std::any HandleRequest(const std::string& request_type, const std::any& payload) {
        return {};
    }
};

// ============================================================================
// Component Registry
// ============================================================================

class ComponentRegistry {
public:
    struct Config {
        bool auto_start_components = true;
        bool health_check_enabled = true;
        std::chrono::seconds health_check_interval{30};
    };
    
    struct ComponentInfo {
        std::string name;
        std::string version;
        std::unique_ptr<ComponentAdapter> adapter;
        std::map<std::string, std::string> config;
        bool initialized = false;
        bool running = false;
        std::chrono::steady_clock::time_point started_at;
    };
    
    explicit ComponentRegistry(const Config& config);
    ~ComponentRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Component registration
    bool RegisterComponent(const std::string& name,
                          std::unique_ptr<ComponentAdapter> adapter,
                          const std::map<std::string, std::string>& config = {});
    bool UnregisterComponent(const std::string& name);
    
    // Component lifecycle
    bool InitializeComponent(const std::string& name);
    bool StartComponent(const std::string& name);
    void StopComponent(const std::string& name);
    bool RestartComponent(const std::string& name);
    
    // Component access
    ComponentAdapter* GetComponent(const std::string& name);
    std::vector<std::string> GetComponentNames() const;
    bool HasComponent(const std::string& name) const;
    
    // Health management
    bool IsComponentHealthy(const std::string& name) const;
    std::map<std::string, bool> GetAllHealthStatus() const;
    std::vector<std::string> GetUnhealthyComponents() const;
    
    // Event routing
    void RouteEventToComponent(const std::string& component_name, const Event& event);
    void RouteEventToAll(const Event& event);
    
    // Metrics aggregation
    std::map<std::string, std::map<std::string, std::any>> GetAllMetrics() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    std::map<std::string, ComponentInfo> components_;
    mutable std::mutex components_mutex_;
    
    std::thread health_check_thread_;
    
    void HealthCheckLoop();
};

// ============================================================================
// Phase Adapters (Integration with previous phases)
// ============================================================================

// D.3 Distributed Runtime Adapter
class DistributedRuntimeAdapter : public ComponentAdapter {
public:
    std::string GetName() const override { return "distributed_runtime"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;
    std::map<std::string, std::string> GetHealthDetails() const override;
    std::map<std::string, std::any> GetMetrics() const override;
    
    void OnEvent(const Event& event) override;
    std::any HandleRequest(const std::string& request_type, const std::any& payload) override;
    
private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
};

// D.4 Cloud-Native Deployment Adapter
class CloudDeploymentAdapter : public ComponentAdapter {
public:
    std::string GetName() const override { return "cloud_deployment"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;
    std::map<std::string, std::string> GetHealthDetails() const override;
    std::map<std::string, std::any> GetMetrics() const override;
    
    void OnEvent(const Event& event) override;
    std::any HandleRequest(const std::string& request_type, const std::any& payload) override;
    
private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
};

// D.5 Multi-Region Federation Adapter
class FederationAdapter : public ComponentAdapter {
public:
    std::string GetName() const override { return "federation"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;
    std::map<std::string, std::string> GetHealthDetails() const override;
    std::map<std::string, std::any> GetMetrics() const override;
    
    void OnEvent(const Event& event) override;
    std::any HandleRequest(const std::string& request_type, const std::any& payload) override;
    
private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
};

// D.6 Intelligent Operations Adapter
class IntelligenceAdapter : public ComponentAdapter {
public:
    std::string GetName() const override { return "intelligence"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;
    std::map<std::string, std::string> GetHealthDetails() const override;
    std::map<std::string, std::any> GetMetrics() const override;
    
    void OnEvent(const Event& event) override;
    std::any HandleRequest(const std::string& request_type, const std::any& payload) override;
    
private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
};

// D.7 Security & Compliance Adapter
class SecurityAdapter : public ComponentAdapter {
public:
    std::string GetName() const override { return "security"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;
    std::map<std::string, std::string> GetHealthDetails() const override;
    std::map<std::string, std::any> GetMetrics() const override;
    
    void OnEvent(const Event& event) override;
    std::any HandleRequest(const std::string& request_type, const std::any& payload) override;
    
private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
};

// D.8 Developer Experience Adapter
class DevToolsAdapter : public ComponentAdapter {
public:
    std::string GetName() const override { return "devtools"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    bool Initialize(const std::map<std::string, std::string>& config) override;
    void Shutdown() override;
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;
    std::map<std::string, std::string> GetHealthDetails() const override;
    std::map<std::string, std::any> GetMetrics() const override;
    
    void OnEvent(const Event& event) override;
    std::any HandleRequest(const std::string& request_type, const std::any& payload) override;
    
private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
};

// ============================================================================
// Integration Runtime
// ============================================================================

class IntegrationRuntime {
public:
    struct Config {
        EventBus::Config event_bus;
        ComponentRegistry::Config component_registry;
        bool enable_all_adapters = true;
    };
    
    explicit IntegrationRuntime(const Config& config);
    ~IntegrationRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    EventBus* GetEventBus();
    ComponentRegistry* GetComponentRegistry();
    
    // Component shortcuts
    DistributedRuntimeAdapter* GetDistributedRuntime();
    CloudDeploymentAdapter* GetCloudDeployment();
    FederationAdapter* GetFederation();
    IntelligenceAdapter* GetIntelligence();
    SecurityAdapter* GetSecurity();
    DevToolsAdapter* GetDevTools();
    
    // Cross-component operations
    bool BroadcastToAll(const Event& event);
    std::any RequestFromComponent(const std::string& component_name,
                                   const std::string& request_type,
                                   const std::any& payload);
    
    // Health
    bool IsHealthy() const;
    std::map<std::string, std::map<std::string, std::string>> GetFullHealthStatus();
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<EventBus> event_bus_;
    std::unique_ptr<ComponentRegistry> component_registry_;
    
    // Component adapters
    DistributedRuntimeAdapter* distributed_runtime_ = nullptr;
    CloudDeploymentAdapter* cloud_deployment_ = nullptr;
    FederationAdapter* federation_ = nullptr;
    IntelligenceAdapter* intelligence_ = nullptr;
    SecurityAdapter* security_ = nullptr;
    DevToolsAdapter* devtools_ = nullptr;
    
    bool RegisterDefaultAdapters();
};

} // namespace Unified
} // namespace Sovereign
