// Phase D.8 Batch 1/5: CLI Toolkit
// Command-Line Interface and Management Commands
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <iostream>

namespace Sovereign {
namespace DevTools {

// ============================================================================
// Command Types
// ============================================================================

enum class CommandCategory {
    CLUSTER = 0,
    NODE = 1,
    SERVICE = 2,
    CONFIG = 3,
    MONITOR = 4,
    DEBUG = 5,
    ADMIN = 6
};

struct Command {
    std::string name;
    std::string description;
    std::string usage;
    CommandCategory category;
    std::vector<std::string> aliases;
    std::vector<std::string> arguments;
    std::map<std::string, std::string> flags;
    std::function<int(const std::vector<std::string>&, const std::map<std::string, std::string>&)> handler;
    bool requires_auth = true;
    bool hidden = false;
};

// ============================================================================
// CLI Parser
// ============================================================================

class CLIParser {
public:
    struct ParseResult {
        std::string command;
        std::vector<std::string> args;
        std::map<std::string, std::string> flags;
        bool help_requested = false;
        std::string error_message;
    };
    
    CLIParser();
    
    bool RegisterCommand(const Command& cmd);
    bool UnregisterCommand(const std::string& name);
    
    ParseResult Parse(int argc, char* argv[]);
    ParseResult Parse(const std::vector<std::string>& args);
    
    std::string GenerateHelp(const std::string& command = "");
    std::string GenerateUsage(const std::string& command);
    
    std::vector<Command> GetCommands(CommandCategory category) const;
    std::vector<Command> GetAllCommands() const;
    
private:
    std::map<std::string, Command> commands_;
    std::map<std::string, std::string> alias_map_;
    
    bool IsFlag(const std::string& arg);
    std::pair<std::string, std::string> ParseFlag(const std::string& arg);
};

// ============================================================================
// Cluster Commands
// ============================================================================

class ClusterCommands {
public:
    // Cluster lifecycle
    static int CreateCluster(const std::vector<std::string>& args, 
                            const std::map<std::string, std::string>& flags);
    static int DeleteCluster(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
    static int ListClusters(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int GetCluster(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    
    // Cluster operations
    static int ScaleCluster(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int UpgradeCluster(const std::vector<std::string>& args,
                             const std::map<std::string, std::string>& flags);
    static int BackupCluster(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
    static int RestoreCluster(const std::vector<std::string>& args,
                             const std::map<std::string, std::string>& flags);
    
    // Health and status
    static int ClusterStatus(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
    static int ClusterHealth(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
    static int ClusterTopology(const std::vector<std::string>& args,
                              const std::map<std::string, std::string>& flags);
};

// ============================================================================
// Node Commands
// ============================================================================

class NodeCommands {
public:
    // Node lifecycle
    static int AddNode(const std::vector<std::string>& args,
                      const std::map<std::string, std::string>& flags);
    static int RemoveNode(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int ListNodes(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
    static int GetNode(const std::vector<std::string>& args,
                      const std::map<std::string, std::string>& flags);
    
    // Node operations
    static int DrainNode(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
    static int CordonNode(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int UncordonNode(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int RestartNode(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
    
    // Node diagnostics
    static int NodeLogs(const std::vector<std::string>& args,
                       const std::map<std::string, std::string>& flags);
    static int NodeMetrics(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
    static int NodeDebug(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
};

// ============================================================================
// Service Commands
// ============================================================================

class ServiceCommands {
public:
    // Service lifecycle
    static int DeployService(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
    static int DeleteService(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
    static int ListServices(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int GetService(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    
    // Service operations
    static int ScaleService(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int UpdateService(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
    static int RollbackService(const std::vector<std::string>& args,
                              const std::map<std::string, std::string>& flags);
    static int RestartService(const std::vector<std::string>& args,
                             const std::map<std::string, std::string>& flags);
    
    // Service introspection
    static int ServiceLogs(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
    static int ServiceExec(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
    static int ServicePortForward(const std::vector<std::string>& args,
                                 const std::map<std::string, std::string>& flags);
};

// ============================================================================
// Config Commands
// ============================================================================

class ConfigCommands {
public:
    // Config management
    static int GetConfig(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
    static int SetConfig(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
    static int DeleteConfig(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int ListConfigs(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
    
    // Config validation
    static int ValidateConfig(const std::vector<std::string>& args,
                             const std::map<std::string, std::string>& flags);
    static int DiffConfig(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int ApplyConfig(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
};

// ============================================================================
// Monitor Commands
// ============================================================================

class MonitorCommands {
public:
    // Metrics
    static int GetMetrics(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int QueryMetrics(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int TopMetrics(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    
    // Logs
    static int GetLogs(const std::vector<std::string>& args,
                      const std::map<std::string, std::string>& flags);
    static int FollowLogs(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int SearchLogs(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    
    // Events
    static int GetEvents(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
    static int WatchEvents(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
    
    // Traces
    static int GetTraces(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
    static int AnalyzeTraces(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
};

// ============================================================================
// Debug Commands
// ============================================================================

class DebugCommands {
public:
    // Debugging
    static int DebugService(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int ProfileService(const std::vector<std::string>& args,
                             const std::map<std::string, std::string>& flags);
    static int TraceService(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    
    // Diagnostics
    static int DiagnoseCluster(const std::vector<std::string>& args,
                              const std::map<std::string, std::string>& flags);
    static int DiagnoseNode(const std::vector<std::string>& args,
                           const std::map<std::string, std::string>& flags);
    static int DiagnoseNetwork(const std::vector<std::string>& args,
                              const std::map<std::string, std::string>& flags);
    
    // Testing
    static int TestConnectivity(const std::vector<std::string>& args,
                               const std::map<std::string, std::string>& flags);
    static int TestPerformance(const std::vector<std::string>& args,
                              const std::map<std::string, std::string>& flags);
    static int ChaosTest(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
};

// ============================================================================
// Admin Commands
// ============================================================================

class AdminCommands {
public:
    // User management
    static int CreateUser(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int DeleteUser(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int ListUsers(const std::vector<std::string>& args,
                        const std::map<std::string, std::string>& flags);
    static int UpdateUser(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    
    // RBAC
    static int CreateRole(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int DeleteRole(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    static int AssignRole(const std::vector<std::string>& args,
                         const std::map<std::string, std::string>& flags);
    
    // Maintenance
    static int MaintenanceMode(const std::vector<std::string>& args,
                              const std::map<std::string, std::string>& flags);
    static int SystemPrune(const std::vector<std::string>& args,
                          const std::map<std::string, std::string>& flags);
    static int SystemUpgrade(const std::vector<std::string>& args,
                            const std::map<std::string, std::string>& flags);
};

// ============================================================================
// CLI Runtime
// ============================================================================

class CLIRuntime {
public:
    struct Config {
        std::string app_name = "sovereign";
        std::string version = "1.0.0";
        std::string config_file;
        std::string api_endpoint;
        std::string auth_token;
        bool verbose = false;
        bool json_output = false;
        int timeout_seconds = 30;
    };
    
    explicit CLIRuntime(const Config& config);
    
    bool Initialize();
    int Run(int argc, char* argv[]);
    
    // Configuration
    void SetAPIEndpoint(const std::string& endpoint);
    void SetAuthToken(const std::string& token);
    void SetOutputFormat(const std::string& format);  // "table", "json", "yaml"
    
    // Output helpers
    void PrintTable(const std::vector<std::vector<std::string>>& data);
    void PrintJSON(const std::string& json);
    void PrintYAML(const std::string& yaml);
    void PrintError(const std::string& message);
    void PrintSuccess(const std::string& message);
    void PrintProgress(const std::string& message, int percent);
    
private:
    Config config_;
    std::unique_ptr<CLIParser> parser_;
    
    void RegisterAllCommands();
    bool Authenticate();
    std::string CallAPI(const std::string& method, const std::string& path,
                       const std::string& body = "");
};

} // namespace DevTools
} // namespace Sovereign
