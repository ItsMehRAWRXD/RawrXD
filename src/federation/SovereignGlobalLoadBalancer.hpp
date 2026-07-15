// Phase D.5 Batch 1/5: Global Load Balancer
// Multi-Region Traffic Management
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>

namespace Sovereign {
namespace Federation {

// ============================================================================
// Geo-DNS and Routing Types
// ============================================================================

enum class RoutingStrategy {
    GEOGRAPHIC = 0,      // Route to nearest region
    LATENCY_BASED = 1,   // Route based on measured latency
    LOAD_BALANCED = 2,   // Route based on region capacity
    FAILOVER = 3,        // Route to healthy regions only
    WEIGHTED = 4,        // Custom weight distribution
    STICKY = 5           // Session affinity
};

enum class HealthStatus {
    HEALTHY = 0,
    DEGRADED = 1,
    UNAVAILABLE = 2,
    MAINTENANCE = 3
};

struct GeoLocation {
    double latitude = 0.0;
    double longitude = 0.0;
    std::string continent;
    std::string country;
    std::string region;
    std::string city;
    std::string timezone;
    
    double DistanceTo(const GeoLocation& other) const;
};

struct RegionEndpoint {
    std::string region_id;
    std::string name;
    GeoLocation location;
    std::vector<std::string> ip_addresses;
    std::vector<std::string> ipv6_addresses;
    std::string hostname;
    int port = 443;
    HealthStatus health = HealthStatus::HEALTHY;
    
    // Performance metrics
    double avg_latency_ms = 0.0;
    double capacity_percent = 100.0;
    int active_connections = 0;
    int64_t requests_per_second = 0;
    
    std::chrono::steady_clock::time_point last_health_check;
    std::map<std::string, std::string> metadata;
};

struct RoutingDecision {
    std::string region_id;
    std::string endpoint;
    RoutingStrategy strategy_used;
    double estimated_latency_ms = 0.0;
    int priority = 0;
    std::string reason;
    std::chrono::steady_clock::time_point timestamp;
};

// ============================================================================
// Health Checker
// ============================================================================

class RegionHealthChecker {
public:
    struct Config {
        int check_interval_ms = 5000;
        int timeout_ms = 3000;
        int failure_threshold = 3;
        int success_threshold = 2;
        std::vector<std::string> health_check_paths;
    };
    
    explicit RegionHealthChecker(const Config& config);
    ~RegionHealthChecker();
    
    void Start();
    void Stop();
    
    void AddRegion(const RegionEndpoint& region);
    void RemoveRegion(const std::string& region_id);
    
    HealthStatus GetHealth(const std::string& region_id) const;
    std::vector<RegionEndpoint> GetHealthyRegions() const;
    
    using HealthChangeCallback = std::function<void(const std::string&, HealthStatus, HealthStatus)>;
    void OnHealthChange(HealthChangeCallback cb);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread check_thread_;
    
    mutable std::mutex regions_mutex_;
    std::map<std::string, RegionEndpoint> regions_;
    std::map<std::string, int> failure_counts_;
    std::map<std::string, int> success_counts_;
    
    HealthChangeCallback on_health_change_;
    
    void CheckLoop();
    bool PerformHealthCheck(const RegionEndpoint& region);
    void UpdateHealth(const std::string& region_id, bool healthy);
};

// ============================================================================
// Latency Monitor
// ============================================================================

class LatencyMonitor {
public:
    struct Config {
        int probe_interval_ms = 10000;
        int probe_count = 5;
        int history_size = 100;
    };
    
    explicit LatencyMonitor(const Config& config);
    
    void Start();
    void Stop();
    
    void AddProbeTarget(const std::string& region_id, const std::string& endpoint);
    void RemoveProbeTarget(const std::string& region_id);
    
    double GetLatency(const std::string& region_id) const;
    double GetLatencyPercentile(const std::string& region_id, double percentile) const;
    
    std::map<std::string, double> GetAllLatencies() const;
    std::string GetLowestLatencyRegion() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::thread probe_thread_;
    
    mutable std::mutex latency_mutex_;
    std::map<std::string, std::vector<double>> latency_history_;
    std::map<std::string, std::string> probe_targets_;
    
    void ProbeLoop();
    double MeasureLatency(const std::string& endpoint);
};

// ============================================================================
// Global Load Balancer
// ============================================================================

class GlobalLoadBalancer {
public:
    struct Config {
        RoutingStrategy default_strategy = RoutingStrategy::LATENCY_BASED;
        int health_check_interval_ms = 5000;
        int latency_probe_interval_ms = 10000;
        bool enable_geo_routing = true;
        bool enable_failover = true;
        int failover_timeout_ms = 30000;
        std::map<std::string, int> region_weights;
    };
    
    explicit GlobalLoadBalancer(const Config& config);
    ~GlobalLoadBalancer();
    
    bool Initialize();
    void Shutdown();
    
    // Region management
    void RegisterRegion(const RegionEndpoint& region);
    void DeregisterRegion(const std::string& region_id);
    void UpdateRegionMetrics(const std::string& region_id, 
                              const RegionEndpoint& metrics);
    
    // Routing
    RoutingDecision RouteRequest(const std::string& client_ip,
                                  const std::string& session_id = "");
    RoutingDecision RouteRequest(const GeoLocation& client_location,
                                  const std::string& session_id = "");
    
    // Strategy selection
    void SetRoutingStrategy(RoutingStrategy strategy);
    void SetRegionWeight(const std::string& region_id, int weight);
    
    // Health and metrics
    std::vector<RegionEndpoint> GetAllRegions() const;
    std::vector<RegionEndpoint> GetHealthyRegions() const;
    std::map<std::string, double> GetRegionLatencies() const;
    
    // Statistics
    struct Stats {
        int64_t total_requests = 0;
        int64_t routed_requests = 0;
        int64_t failed_requests = 0;
        int64_t failover_events = 0;
        double avg_routing_time_ms = 0.0;
    };
    Stats GetStats() const;
    
    // Callbacks
    using RoutingCallback = std::function<void(const RoutingDecision&)>;
    void OnRoute(RoutingCallback cb);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<RegionHealthChecker> health_checker_;
    std::unique_ptr<LatencyMonitor> latency_monitor_;
    
    mutable std::mutex regions_mutex_;
    std::map<std::string, RegionEndpoint> regions_;
    std::map<std::string, std::string> session_affinity_;  // session -> region
    
    RoutingCallback on_route_;
    
    std::atomic<int64_t> total_requests_{0};
    std::atomic<int64_t> routed_requests_{0};
    std::atomic<int64_t> failed_requests_{0};
    std::atomic<int64_t> failover_events_{0};
    std::atomic<int64_t> total_routing_time_us_{0};
    
    // Routing algorithms
    RoutingDecision RouteByGeography(const GeoLocation& client);
    RoutingDecision RouteByLatency(const GeoLocation& client);
    RoutingDecision RouteByLoad(const GeoLocation& client);
    RoutingDecision RouteByFailover(const GeoLocation& client);
    RoutingDecision RouteByWeight(const GeoLocation& client);
    RoutingDecision RouteSticky(const std::string& session_id);
    
    GeoLocation GeolocateIP(const std::string& ip);
};

// ============================================================================
// DNS Server Integration
// ============================================================================

class GeoDNSResolver {
public:
    struct Config {
        int ttl_seconds = 300;
        int health_check_ttl_seconds = 60;
        bool enable_geo_dns = true;
        std::vector<std::string> authoritative_nameservers;
    };
    
    explicit GeoDNSResolver(const Config& config);
    
    bool Initialize(GlobalLoadBalancer* load_balancer);
    
    // DNS query handling
    std::vector<std::string> ResolveA(const std::string& fqdn, 
                                        const std::string& client_ip);
    std::vector<std::string> ResolveAAAA(const std::string& fqdn,
                                          const std::string& client_ip);
    
    // Health check endpoint
    std::string GetHealthCheckEndpoint(const std::string& region_id);
    
private:
    Config config_;
    GlobalLoadBalancer* load_balancer_ = nullptr;
};

} // namespace Federation
} // namespace Sovereign
