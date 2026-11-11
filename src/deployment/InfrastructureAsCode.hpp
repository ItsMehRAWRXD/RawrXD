/**
 * InfrastructureAsCode.hpp
 *
 * Phase K Batch 2/5: Infrastructure as Code
 *
 * Terraform, CloudFormation, and Pulumi integration for
 * infrastructure provisioning and management.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace Deployment {

// ============================================================================
// Forward Declarations
// ============================================================================

class TerraformClient;
class CloudFormationClient;
class PulumiClient;
class ResourceGraph;

// ============================================================================
// Cloud Provider
// ============================================================================

enum class CloudProvider {
    AWS,
    AZURE,
    GCP,
    DIGITAL_OCEAN,
    LINODE,
    VULTR,
    ORACLE,
    IBM,
    ALIBABA,
    PRIVATE
};

std::string CloudProviderToString(CloudProvider provider);

// ============================================================================
// Resource Types
// ============================================================================

enum class InfrastructureResourceType {
    COMPUTE,        // VMs, containers, serverless
    STORAGE,        // Block, object, file
    NETWORK,        // VPC, subnets, load balancers
    DATABASE,       // SQL, NoSQL, cache
    SECURITY,       // IAM, certificates, WAF
    MONITORING,     // Metrics, logs, alerts
    DNS,            // Zones, records
    CDN,            // Edge caching
    MESSAGING,      // Queues, topics
    COMPUTE_ORCH,   // Kubernetes, ECS
    SERVERLESS,     // Lambda, functions
    CACHE,          // Redis, Memcached
    SEARCH,         // Elasticsearch
    ANALYTICS,      // Data warehouses
    ML,             // AI/ML services
    UNKNOWN
};

// ============================================================================
// Resource Definition
// ============================================================================

/**
 * Infrastructure resource definition.
 */
struct InfrastructureResource {
    std::string id;
    std::string name;
    std::string type;
    InfrastructureResourceType category;
    CloudProvider provider;
    std::map<std::string, std::string> attributes;
    std::map<std::string, std::string> tags;
    std::vector<std::string> dependencies;
    std::optional<std::string> parent;
    bool managed;
    bool imported;
    
    // State
    std::string state;
    std::string stateFile;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point modified;
};

// ============================================================================
// Terraform Client
// ============================================================================

/**
 * Terraform CLI client.
 */
class TerraformClient {
public:
    struct Config {
        std::string workingDirectory;
        std::string terraformPath = "terraform";
        std::map<std::string, std::string> environmentVariables;
        std::string backendConfig;
        std::string varFile;
        std::map<std::string, std::string> variables;
        bool autoApprove = false;
        bool parallelism = 10;
    };
    
    struct State {
        std::string version;
        std::string terraformVersion;
        std::string serial;
        std::string lineage;
        std::vector<InfrastructureResource> resources;
        std::map<std::string, std::string> outputs;
    };
    
    struct Plan {
        std::string id;
        int add;
        int change;
        int destroy;
        std::vector<std::string> actions;
        bool hasChanges;
        std::string planFile;
    };
    
    struct Module {
        std::string source;
        std::string version;
        std::map<std::string, std::string> variables;
    };
    
    struct Provider {
        std::string name;
        std::string version;
        std::map<std::string, std::string> configuration;
    };
    
    explicit TerraformClient(const Config& config);
    
    // Initialization
    bool Init();
    bool Init(const std::map<std::string, std::string>& backendConfig);
    bool Validate();
    bool Fmt(bool check = false, bool recursive = false);
    
    // Planning
    Plan Plan(bool destroy = false);
    Plan PlanTarget(const std::string& target, bool destroy = false);
    Plan PlanTargets(const std::vector<std::string>& targets, bool destroy = false);
    bool ShowPlan(const std::string& planFile);
    
    // Apply
    bool Apply();
    bool Apply(const Plan& plan);
    bool ApplyTarget(const std::string& target);
    bool AutoApply();
    
    // Destroy
    bool Destroy();
    bool DestroyTarget(const std::string& target);
    bool DestroyAutoApprove();
    
    // State management
    State GetState();
    bool Refresh();
    bool Import(const std::string& address, const std::string& id);
    bool Taint(const std::string& address);
    bool Untaint(const std::string& address);
    bool StateRemove(const std::string& address);
    bool StateMv(const std::string& from, const std::string& to);
    bool StateReplaceProvider(const std::string& from, const std::string& to);
    bool StatePull(const std::string& outputFile);
    bool StatePush(const std::string& stateFile);
    
    // Workspace
    std::vector<std::string> WorkspaceList();
    bool WorkspaceNew(const std::string& name);
    bool WorkspaceSelect(const std::string& name);
    bool WorkspaceDelete(const std::string& name);
    std::string GetCurrentWorkspace();
    
    // Output
    std::map<std::string, std::string> Output();
    std::optional<std::string> Output(const std::string& name);
    bool OutputToFile(const std::string& file);
    
    // Graph
    std::string Graph();
    bool GraphToFile(const std::string& file);
    
    // Providers
    std::vector<Provider> Providers();
    bool ProviderInstall();
    bool ProviderUpdate();
    
    // Modules
    bool GetModules();
    bool UpdateModules();
    
    // Console
    std::string Console(const std::string& expression);
    
    // Version
    std::string Version();
    
    // Configuration generation
    bool GenerateConfiguration(const std::vector<InfrastructureResource>& resources);
    bool GenerateVariables(const std::map<std::string, std::string>& variables);
    bool GenerateOutputs(const std::vector<std::string>& outputs);
    
private:
    Config config_;
    
    std::string Execute(const std::string& command);
    std::string BuildCommand(const std::string& action);
};

// ============================================================================
// CloudFormation Client
// ============================================================================

/**
 * AWS CloudFormation client.
 */
class CloudFormationClient {
public:
    struct Config {
        std::string region;
        std::string accessKeyId;
        std::string secretAccessKey;
        std::string sessionToken;
        std::string profile;
        std::string roleArn;
    };
    
    struct Stack {
        std::string name;
        std::string id;
        std::string status;
        std::string statusReason;
        std::string description;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point updated;
        std::map<std::string, std::string> outputs;
        std::vector<std::string> resources;
        std::vector<std::map<std::string, std::string>> tags;
        bool disableRollback;
        std::string parentId;
        std::string rootId;
        int driftInformation;
    };
    
    struct ChangeSet {
        std::string id;
        std::string name;
        std::string stackName;
        std::string status;
        std::string executionStatus;
        std::string description;
        std::chrono::system_clock::time_point created;
        std::vector<std::map<std::string, std::string>> changes;
    };
    
    struct TemplateParameter {
        std::string key;
        std::string description;
        std::string type;
        std::string defaultValue;
        bool noEcho;
    };
    
    struct Template {
        std::string templateBody;
        std::string templateUrl;
        std::vector<TemplateParameter> parameters;
        std::vector<std::string> capabilities;
        std::vector<std::string> resourceTypes;
        std::string version;
        std::string description;
    };
    
    explicit CloudFormationClient(const Config& config);
    
    // Stacks
    std::vector<Stack> ListStacks();
    std::vector<Stack> ListStacks(const std::vector<std::string>& statusFilter);
    std::optional<Stack> DescribeStack(const std::string& name);
    bool CreateStack(const std::string& name, const Template& template_,
                     const std::map<std::string, std::string>& parameters);
    bool UpdateStack(const std::string& name, const Template& template_,
                     const std::map<std::string, std::string>& parameters);
    bool DeleteStack(const std::string& name);
    bool CreateChangeSet(const std::string& stackName, const std::string& changeSetName,
                         const Template& template_,
                         const std::map<std::string, std::string>& parameters);
    bool ExecuteChangeSet(const std::string& stackName, const std::string& changeSetName);
    bool DeleteChangeSet(const std::string& stackName, const std::string& changeSetName);
    std::vector<ChangeSet> ListChangeSets(const std::string& stackName);
    std::optional<ChangeSet> DescribeChangeSet(const std::string& stackName,
                                                  const std::string& changeSetName);
    
    // Stack resources
    std::vector<InfrastructureResource> ListStackResources(const std::string& stackName);
    std::optional<InfrastructureResource> DescribeStackResource(
        const std::string& stackName, const std::string& logicalResourceId);
    
    // Stack events
    struct StackEvent {
        std::string stackId;
        std::string stackName;
        std::string logicalResourceId;
        std::string physicalResourceId;
        std::string resourceType;
        std::string resourceStatus;
        std::string resourceStatusReason;
        std::chrono::system_clock::time_point timestamp;
    };
    std::vector<StackEvent> DescribeStackEvents(const std::string& stackName);
    
    // Drift detection
    bool DetectStackDrift(const std::string& stackName);
    std::optional<std::string> DescribeStackDriftDetectionStatus(const std::string& driftDetectionId);
    
    // Templates
    Template GetTemplate(const std::string& stackName);
    Template GetTemplateSummary(const std::string& templateBody);
    bool ValidateTemplate(const std::string& templateBody);
    
    // Exports
    struct Export {
        std::string name;
        std::string value;
        std::string exportingStackId;
    };
    std::vector<Export> ListExports();
    
    // Imports
    std::vector<std::string> ListImports(const std::string& exportName);
    
    // Stack sets
    struct StackSet {
        std::string name;
        std::string description;
        std::string status;
        std::string templateBody;
        std::vector<std::map<std::string, std::string>> parameters;
        std::vector<std::map<std::string, std::string>> tags;
    };
    bool CreateStackSet(const std::string& name, const Template& template_);
    bool UpdateStackSet(const std::string& name, const Template& template_);
    bool DeleteStackSet(const std::string& name);
    std::vector<StackSet> ListStackSets();
    std::optional<StackSet> DescribeStackSet(const std::string& name);
    
    // Waiters
    bool WaitForStackCreateComplete(const std::string& stackName, uint32_t timeoutMinutes = 30);
    bool WaitForStackUpdateComplete(const std::string& stackName, uint32_t timeoutMinutes = 30);
    bool WaitForStackDeleteComplete(const std::string& stackName, uint32_t timeoutMinutes = 30);
    
private:
    Config config_;
    
    std::string MakeRequest(const std::string& action, const std::map<std::string, std::string>& params);
};

// ============================================================================
// Pulumi Client
// ============================================================================

/**
 * Pulumi CLI client.
 */
class PulumiClient {
public:
    struct Config {
        std::string workingDirectory;
        std::string pulumiPath = "pulumi";
        std::string backendUrl;
        std::string passphrase;
        std::map<std::string, std::string> environmentVariables;
    };
    
    struct Stack {
        std::string name;
        std::string url;
        std::string resourceCount;
        std::string lastUpdate;
        std::string result;
    };
    
    struct PreviewResult {
        bool hasChanges;
        int createCount;
        int deleteCount;
        int updateCount;
        int sameCount;
        std::vector<std::string> changes;
    };
    
    struct UpdateResult {
        std::string updateId;
        std::string version;
        std::string result;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
    };
    
    struct ConfigValue {
        std::string key;
        std::string value;
        bool secret;
    };
    
    struct Plugin {
        std::string name;
        std::string version;
        std::string kind;
        std::string size;
        std::string installTime;
    };
    
    explicit PulumiClient(const Config& config);
    
    // Login/Logout
    bool Login();
    bool LoginLocal();
    bool LoginToBackend(const std::string& url);
    bool Logout();
    bool LogoutAll();
    
    // Project
    bool NewProject(const std::string& name, const std::string& template_ = "");
    bool NewProjectFromGit(const std::string& gitUrl);
    bool StackInit(const std::string& stackName);
    bool StackSelect(const std::string& stackName);
    bool StackRm(const std::string& stackName, bool force = false);
    std::vector<Stack> StackLs();
    std::vector<Stack> StackLsAll();
    std::string GetCurrentStack();
    
    // Preview/Update
    PreviewResult Preview();
    PreviewResult PreviewTarget(const std::string& urn);
    UpdateResult Update();
    UpdateResult UpdateTarget(const std::string& urn);
    bool Refresh();
    bool Destroy();
    bool DestroyTarget(const std::string& urn);
    bool Cancel();
    
    // Configuration
    bool ConfigSet(const std::string& key, const std::string& value);
    bool ConfigSetSecret(const std::string& key, const std::string& value);
    bool ConfigRm(const std::string& key);
    std::vector<ConfigValue> ConfigGetAll();
    std::optional<ConfigValue> ConfigGet(const std::string& key);
    bool ConfigCopy(const std::string& fromStack, const std::string& toStack);
    
    // State
    bool StateExport(const std::string& file);
    bool StateImport(const std::string& file);
    bool StateDelete(const std::string& urn, bool force = false);
    bool StateUnprotect(const std::string& urn);
    bool StateRename(const std::string& urn, const std::string& newName);
    
    // Plugins
    std::vector<Plugin> PluginLs();
    bool PluginInstall(const std::string& name, const std::string& version = "");
    bool PluginRm(const std::string& name, const std::string& version = "");
    bool PluginRmAll();
    
    // Logs
    std::string Logs();
    std::string LogsFollow();
    std::string LogsSince(std::chrono::system_clock::time_point since);
    
    // Console
    bool Console();
    
    // Version
    std::string Version();
    
    // Whoami
    std::string Whoami();
    
    // Policy
    bool PolicyPublish(const std::string& policyPackPath);
    bool PolicyEnable(const std::string& policyPackName, const std::string& version);
    bool PolicyDisable(const std::string& policyPackName);
    
private:
    Config config_;
    
    std::string Execute(const std::string& command);
};

// ============================================================================
// Resource Graph
// ============================================================================

/**
 * Infrastructure resource graph.
 */
class ResourceGraph {
public:
    struct Node {
        std::string id;
        std::string type;
        std::string provider;
        std::map<std::string, std::string> attributes;
        std::vector<std::string> dependencies;
        std::vector<std::string> dependents;
    };
    
    struct Edge {
        std::string from;
        std::string to;
        std::string type;
        std::map<std::string, std::string> attributes;
    };
    
    ResourceGraph();
    
    // Building
    void AddNode(const Node& node);
    void AddEdge(const Edge& edge);
    void AddResource(const InfrastructureResource& resource);
    
    // Querying
    std::vector<Node> GetNodes() const;
    std::vector<Node> GetNodesByType(const std::string& type) const;
    std::vector<Node> GetNodesByProvider(const std::string& provider) const;
    std::optional<Node> GetNode(const std::string& id) const;
    std::vector<Edge> GetEdges() const;
    std::vector<Edge> GetEdgesFrom(const std::string& nodeId) const;
    std::vector<Edge> GetEdgesTo(const std::string& nodeId) const;
    
    // Analysis
    std::vector<std::string> GetDependencies(const std::string& nodeId) const;
    std::vector<std::string> GetDependents(const std::string& nodeId) const;
    std::vector<std::vector<std::string>> FindCycles() const;
    std::vector<std::string> TopologicalSort() const;
    bool IsDAG() const;
    
    // Visualization
    std::string ToDot() const;
    std::string ToMermaid() const;
    std::string ToPlantUml() const;
    std::string ToJson() const;
    bool ExportToFile(const std::string& format, const std::string& path) const;
    
    // Import/Export
    bool ImportFromTerraformState(const std::string& stateFile);
    bool ImportFromCloudFormation(const std::string& stackName);
    bool ImportFromPulumiState(const std::string& stateFile);
    bool ImportFromAzureResourceGraph(const std::string& query);
    bool ImportFromGCPAssetInventory(const std::string& projectId);
    
private:
    std::map<std::string, Node> nodes_;
    std::vector<Edge> edges_;
    mutable std::mutex mutex_;
    
    void BuildEdges();
    void VisitNode(const std::string& nodeId, std::set<std::string>& visited,
                   std::set<std::string>& recStack, std::vector<std::string>& path,
                   std::vector<std::vector<std::string>>& cycles) const;
};

// ============================================================================
// Cost Estimator
// ============================================================================

/**
 * Infrastructure cost estimator.
 */
class CostEstimator {
public:
    struct CostComponent {
        std::string service;
        std::string resource;
        std::string region;
        double monthlyCost;
        std::string currency;
        std::map<std::string, std::string> details;
    };
    
    struct CostEstimate {
        double totalMonthly;
        double totalYearly;
        std::string currency;
        std::vector<CostComponent> components;
        std::map<std::string, double> byService;
        std::map<std::string, double> byRegion;
    };
    
    explicit CostEstimator(CloudProvider provider);
    
    // Estimation
    CostEstimate Estimate(const std::vector<InfrastructureResource>& resources);
    CostEstimate EstimateTerraform(const std::string& planFile);
    CostEstimate EstimateCloudFormation(const std::string& templateBody);
    CostEstimate EstimatePulumi(const std::string& stackName);
    
    // Pricing
    void LoadPricingData(const std::string& dataFile);
    void UpdatePricingData();
    double GetPrice(const std::string& service, const std::string& region,
                    const std::map<std::string, std::string>& attributes);
    
    // Comparison
    struct Comparison {
        CloudProvider provider;
        CostEstimate estimate;
        double savingsVsBaseline;
    };
    std::vector<Comparison> CompareProviders(const std::vector<InfrastructureResource>& resources);
    std::vector<Comparison> CompareRegions(const std::vector<InfrastructureResource>& resources);
    
    // Optimization
    std::vector<std::string> GetOptimizationRecommendations(const CostEstimate& estimate);
    CostEstimate Optimize(const std::vector<InfrastructureResource>& resources);
    
private:
    CloudProvider provider_;
    std::map<std::string, std::map<std::string, double>> pricingData_;
    
    double EstimateCompute(const InfrastructureResource& resource);
    double EstimateStorage(const InfrastructureResource& resource);
    double EstimateNetwork(const InfrastructureResource& resource);
    double EstimateDatabase(const InfrastructureResource& resource);
};

// ============================================================================
// Compliance Checker
// ============================================================================

/**
 * Infrastructure compliance checker.
 */
class ComplianceChecker {
public:
    struct Rule {
        std::string id;
        std::string name;
        std::string description;
        std::string severity;  // critical, high, medium, low
        std::string category;
        std::string query;
        std::string remediation;
        std::vector<std::string> references;
    };
    
    struct Finding {
        Rule rule;
        std::string resourceId;
        std::string resourceType;
        std::string message;
        std::map<std::string, std::string> details;
        bool remediated;
    };
    
    struct ComplianceReport {
        std::string framework;
        double complianceScore;
        int totalRules;
        int passedRules;
        int failedRules;
        std::vector<Finding> findings;
        std::chrono::system_clock::time_point generated;
    };
    
    ComplianceChecker();
    
    // Rules
    void AddRule(const Rule& rule);
    void RemoveRule(const std::string& ruleId);
    std::vector<Rule> GetRules() const;
    std::vector<Rule> GetRulesByCategory(const std::string& category) const;
    std::vector<Rule> GetRulesBySeverity(const std::string& severity) const;
    
    // Frameworks
    void LoadFramework(const std::string& framework);  // CIS, NIST, SOC2, etc.
    void LoadCISBenchmarks();
    void LoadNISTControls();
    void LoadSOC2Controls();
    void LoadPCIControls();
    void LoadHIPAAControls();
    void LoadGDPRControls();
    
    // Checking
    ComplianceReport Check(const std::vector<InfrastructureResource>& resources);
    ComplianceReport CheckTerraform(const std::string& planFile);
    ComplianceReport CheckCloudFormation(const std::string& templateBody);
    ComplianceReport CheckPulumi(const std::string& stackName);
    
    // Remediation
    std::string GenerateRemediationScript(const Finding& finding);
    bool ApplyRemediation(const Finding& finding);
    
    // Reporting
    std::string GenerateReport(const ComplianceReport& report, const std::string& format);
    bool ExportReport(const ComplianceReport& report, const std::string& path);
    
private:
    std::vector<Rule> rules_;
    
    bool EvaluateRule(const Rule& rule, const InfrastructureResource& resource);
};

} // namespace Deployment
