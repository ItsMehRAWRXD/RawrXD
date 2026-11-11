// Phase S.4/5: Cross-Domain Integration
// RawrXD Cross-Domain Integration - Seamless integration across domains

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Universal {

// Domain types
enum class DomainType {
    CLOUD,              // Public cloud
    PRIVATE_CLOUD,      // Private cloud
    HYBRID,             // Hybrid cloud
    EDGE,               // Edge computing
    IOT,                // IoT devices
    MOBILE,             // Mobile devices
    ENTERPRISE,         // Enterprise systems
    LEGACY,             // Legacy systems
    PARTNER,            // Partner systems
    CUSTOMER            // Customer environments
};

// Integration pattern
enum class IntegrationPattern {
    API_GATEWAY,        // API gateway pattern
    EVENT_DRIVEN,       // Event-driven architecture
    MESSAGE_QUEUE,      // Message queuing
    DATA_SYNC,          // Data synchronization
    FILE_TRANSFER,      // File-based integration
    DATABASE_LINK,      // Database linking
    STREAMING,          // Real-time streaming
    BATCH_PROCESS,      // Batch processing
    SERVICE_MESH,       // Service mesh
    DIRECT_CONNECT      // Direct connection
};

// Domain endpoint
struct DomainEndpoint {
    std::string id;
    std::string name;
    DomainType domain_type;
    
    // Connection
    std::string endpoint_url;
    std::string protocol;
    std::unordered_map<std::string, std::string> connection_params;
    
    // Authentication
    std::string auth_method;
    std::unordered_map<std::string, std::string> auth_config;
    
    // Capabilities
    std::vector<std::string> supported_operations;
    std::vector<std::string> supported_formats;
    
    // State
    bool is_connected;
    std::chrono::system_clock::time_point last_connected;
    std::chrono::system_clock::time_point last_activity;
    
    // Health
    double health_score;
    uint64_t requests_succeeded;
    uint64_t requests_failed;
    double average_latency_ms;
};

// Integration flow
struct IntegrationFlow {
    std::string id;
    std::string name;
    std::string description;
    IntegrationPattern pattern;
    
    // Source and target
    std::string source_domain_id;
    std::string source_endpoint_id;
    std::string target_domain_id;
    std::string target_endpoint_id;
    
    // Transformation
    struct Transformation {
        std::string type;  // "map", "filter", "enrich", "aggregate", "split"
        std::string config;
        std::string script;
    };
    std::vector<Transformation> transformations;
    
    // Routing
    std::string routing_expression;
    std::vector<std::string> conditional_branches;
    
    // Error handling
    uint32_t retry_count;
    std::chrono::seconds retry_interval;
    std::string dead_letter_queue;
    std::string error_handler;
    
    // Monitoring
    bool track_metrics;
    bool log_payloads;
    std::vector<std::string> alert_conditions;
    
    // State
    bool enabled;
    uint64_t messages_processed;
    uint64_t messages_failed;
    double success_rate;
};

// Data mapping
struct DataMapping {
    std::string id;
    std::string name;
    std::string source_schema;
    std::string target_schema;
    
    struct FieldMapping {
        std::string source_field;
        std::string target_field;
        std::string transformation;  // Expression or function
        std::string default_value;
        bool required;
    };
    
    std::vector<FieldMapping> field_mappings;
    std::vector<std::string> validation_rules;
};

// Security policy
struct DomainSecurityPolicy {
    std::string id;
    std::string name;
    
    // Encryption
    bool encrypt_in_transit;
    bool encrypt_at_rest;
    std::string encryption_algorithm;
    uint32_t key_rotation_days;
    
    // Authentication
    bool require_mtls;
    bool require_oauth;
    std::vector<std::string> allowed_auth_providers;
    
    // Authorization
    std::vector<std::string> allowed_operations;
    std::vector<std::string> denied_operations;
    std::unordered_map<std::string, std::vector<std::string>> role_permissions;
    
    // Audit
    bool audit_all_requests;
    std::vector<std::string> sensitive_fields;
    uint32_t log_retention_days;
    
    // Rate limiting
    uint32_t requests_per_second;
    uint32_t requests_per_minute;
    uint32_t requests_per_hour;
    uint32_t burst_size;
};

// Cross-domain integration manager
class ICrossDomainIntegration {
public:
    virtual ~ICrossDomainIntegration() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Domain management
    virtual std::string RegisterDomain(const DomainEndpoint& domain) = 0;
    virtual bool UnregisterDomain(const std::string& domain_id) = 0;
    virtual bool UpdateDomain(const DomainEndpoint& domain) = 0;
    virtual std::optional<DomainEndpoint> GetDomain(const std::string& domain_id) = 0;
    virtual std::vector<DomainEndpoint> ListDomains() = 0;
    virtual std::vector<DomainEndpoint> ListDomainsByType(DomainType type) = 0;
    
    // Connection management
    virtual bool ConnectDomain(const std::string& domain_id) = 0;
    virtual void DisconnectDomain(const std::string& domain_id) = 0;
    virtual bool TestConnection(const std::string& domain_id) = 0;
    virtual bool IsDomainConnected(const std::string& domain_id) = 0;
    
    // Flow management
    virtual std::string CreateFlow(const IntegrationFlow& flow) = 0;
    virtual bool UpdateFlow(const IntegrationFlow& flow) = 0;
    virtual bool DeleteFlow(const std::string& flow_id) = 0;
    virtual std::optional<IntegrationFlow> GetFlow(const std::string& flow_id) = 0;
    virtual std::vector<IntegrationFlow> ListFlows() = 0;
    virtual std::vector<IntegrationFlow> GetFlowsForDomain(const std::string& domain_id) = 0;
    virtual bool EnableFlow(const std::string& flow_id) = 0;
    virtual bool DisableFlow(const std::string& flow_id) = 0;
    
    // Message processing
    virtual bool SendMessage(const std::string& flow_id, 
                             const std::unordered_map<std::string, std::string>& message) = 0;
    virtual bool SendMessageAsync(const std::string& flow_id,
                                   const std::unordered_map<std::string, std::string>& message) = 0;
    virtual std::optional<std::unordered_map<std::string, std::string>> SendRequest(
        const std::string& flow_id,
        const std::unordered_map<std::string, std::string>& request,
        std::chrono::seconds timeout) = 0;
    
    // Data mapping
    virtual std::string CreateMapping(const DataMapping& mapping) = 0;
    virtual bool UpdateMapping(const DataMapping& mapping) = 0;
    virtual bool DeleteMapping(const std::string& mapping_id) = 0;
    virtual std::optional<DataMapping> GetMapping(const std::string& mapping_id) = 0;
    virtual std::unordered_map<std::string, std::string> ApplyMapping(
        const std::string& mapping_id,
        const std::unordered_map<std::string, std::string>& source_data) = 0;
    
    // Security
    virtual std::string CreateSecurityPolicy(const DomainSecurityPolicy& policy) = 0;
    virtual bool UpdateSecurityPolicy(const DomainSecurityPolicy& policy) = 0;
    virtual bool DeleteSecurityPolicy(const std::string& policy_id) = 0;
    virtual bool ApplySecurityPolicy(const std::string& domain_id, 
                                      const std::string& policy_id) = 0;
    virtual bool ValidateSecurityPolicy(const std::string& policy_id) = 0;
    
    // Discovery
    virtual std::vector<std::string> DiscoverOperations(const std::string& domain_id) = 0;
    virtual std::optional<std::string> GetSchema(const std::string& domain_id,
                                                    const std::string& operation) = 0;
    virtual bool IntrospectDomain(const std::string& domain_id) = 0;
    
    // Monitoring
    virtual struct IntegrationStatistics {
        uint32_t connected_domains;
        uint32_t active_flows;
        uint64_t messages_processed;
        uint64_t messages_failed;
        double average_processing_time_ms;
        double success_rate;
        std::unordered_map<DomainType, uint32_t> domains_by_type;
        std::unordered_map<IntegrationPattern, uint32_t> flows_by_pattern;
    } GetStatistics() = 0;
};

// Local cross-domain integration
class LocalCrossDomainIntegration : public ICrossDomainIntegration {
public:
    LocalCrossDomainIntegration();
    ~LocalCrossDomainIntegration() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RegisterDomain(const DomainEndpoint& domain) override;
    bool UnregisterDomain(const std::string& domain_id) override;
    bool UpdateDomain(const DomainEndpoint& domain) override;
    std::optional<DomainEndpoint> GetDomain(const std::string& domain_id) override;
    std::vector<DomainEndpoint> ListDomains() override;
    std::vector<DomainEndpoint> ListDomainsByType(DomainType type) override;
    
    bool ConnectDomain(const std::string& domain_id) override;
    void DisconnectDomain(const std::string& domain_id) override;
    bool TestConnection(const std::string& domain_id) override;
    bool IsDomainConnected(const std::string& domain_id) override;
    
    std::string CreateFlow(const IntegrationFlow& flow) override;
    bool UpdateFlow(const IntegrationFlow& flow) override;
    bool DeleteFlow(const std::string& flow_id) override;
    std::optional<IntegrationFlow> GetFlow(const std::string& flow_id) override;
    std::vector<IntegrationFlow> ListFlows() override;
    std::vector<IntegrationFlow> GetFlowsForDomain(const std::string& domain_id) override;
    bool EnableFlow(const std::string& flow_id) override;
    bool DisableFlow(const std::string& flow_id) override;
    
    bool SendMessage(const std::string& flow_id, 
                     const std::unordered_map<std::string, std::string>& message) override;
    bool SendMessageAsync(const std::string& flow_id,
                          const std::unordered_map<std::string, std::string>& message) override;
    std::optional<std::unordered_map<std::string, std::string>> SendRequest(
        const std::string& flow_id,
        const std::unordered_map<std::string, std::string>& request,
        std::chrono::seconds timeout) override;
    
    std::string CreateMapping(const DataMapping& mapping) override;
    bool UpdateMapping(const DataMapping& mapping) override;
    bool DeleteMapping(const std::string& mapping_id) override;
    std::optional<DataMapping> GetMapping(const std::string& mapping_id) override;
    std::unordered_map<std::string, std::string> ApplyMapping(
        const std::string& mapping_id,
        const std::unordered_map<std::string, std::string>& source_data) override;
    
    std::string CreateSecurityPolicy(const DomainSecurityPolicy& policy) override;
    bool UpdateSecurityPolicy(const DomainSecurityPolicy& policy) override;
    bool DeleteSecurityPolicy(const std::string& policy_id) override;
    bool ApplySecurityPolicy(const std::string& domain_id, 
                              const std::string& policy_id) override;
    bool ValidateSecurityPolicy(const std::string& policy_id) override;
    
    std::vector<std::string> DiscoverOperations(const std::string& domain_id) override;
    std::optional<std::string> GetSchema(const std::string& domain_id,
                                            const std::string& operation) override;
    bool IntrospectDomain(const std::string& domain_id) override;
    
    IntegrationStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, DomainEndpoint> domains_;
    std::unordered_map<std::string, IntegrationFlow> flows_;
    std::unordered_map<std::string, DataMapping> mappings_;
    std::unordered_map<std::string, DomainSecurityPolicy> security_policies_;
    bool initialized_ = false;
    
    bool ExecuteTransformations(const std::vector<IntegrationFlow::Transformation>& transforms,
                                 std::unordered_map<std::string, std::string>& data);
    bool ApplyFieldMapping(const DataMapping::FieldMapping& mapping,
                           const std::unordered_map<std::string, std::string>& source,
                           std::unordered_map<std::string, std::string>& target);
    bool ValidateSecurity(const std::string& domain_id,
                          const std::unordered_map<std::string, std::string>& message);
};

// Transformation engine
class TransformationEngine {
public:
    using TransformFunction = std::function<bool(const std::unordered_map<std::string, std::string>&,
                                                   std::unordered_map<std::string, std::string>&)>;
    
    void RegisterTransform(const std::string& name, TransformFunction func);
    bool ExecuteTransform(const std::string& name,
                          const std::unordered_map<std::string, std::string>& input,
                          std::unordered_map<std::string, std::string>& output);
    
    // Built-in transforms
    static bool MapFields(const std::unordered_map<std::string, std::string>& config,
                          const std::unordered_map<std::string, std::string>& input,
                          std::unordered_map<std::string, std::string>& output);
    static bool FilterFields(const std::unordered_map<std::string, std::string>& config,
                              const std::unordered_map<std::string, std::string>& input,
                              std::unordered_map<std::string, std::string>& output);
    static bool EnrichData(const std::unordered_map<std::string, std::string>& config,
                            const std::unordered_map<std::string, std::string>& input,
                            std::unordered_map<std::string, std::string>& output);
    static bool AggregateData(const std::unordered_map<std::string, std::string>& config,
                               const std::unordered_map<std::string, std::string>& input,
                               std::unordered_map<std::string, std::string>& output);
    
private:
    std::unordered_map<std::string, TransformFunction> transforms_;
};

// Global cross-domain integration
extern std::unique_ptr<ICrossDomainIntegration> g_cross_domain_integration;

// Initialize cross-domain integration
bool InitializeCrossDomainIntegration(const std::string& config_path);
void ShutdownCrossDomainIntegration();
bool IsCrossDomainIntegrationEnabled();

// Domain helpers
std::string DomainTypeToString(DomainType type);
DomainType DomainTypeFromString(const std::string& str);
std::string IntegrationPatternToString(IntegrationPattern pattern);
IntegrationPattern IntegrationPatternFromString(const std::string& str);

} // namespace Universal
} // namespace RawrXD
