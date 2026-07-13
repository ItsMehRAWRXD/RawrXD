/**
 * CLI.hpp
 *
 * Phase Q Batch 2/5: CLI Tools
 *
 * Command-line interface for the RawrXD platform with comprehensive
 * commands for tenant management, deployment, debugging, and operations.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <variant>

namespace SDK {
namespace CLI {

// ============================================================================
// Forward Declarations
// ============================================================================

class Command;
class CommandRegistry;
class CLIContext;
class OutputFormatter;
class ProgressIndicator;

// ============================================================================
// Argument Types
// ============================================================================

enum class ArgType {
    STRING,
    INT,
    FLOAT,
    BOOL,
    ARRAY,
    MAP,
    FILE_PATH,
    DIRECTORY_PATH,
    URL,
    EMAIL,
    UUID
};

// ============================================================================
// Command Argument
// ============================================================================

struct CommandArg {
    std::string name;
    std::string description;
    ArgType type;
    bool required;
    std::optional<std::variant<std::string, int, float, bool>> defaultValue;
    std::optional<std::string> shortName;
    std::vector<std::string> choices;
    std::function<bool(const std::string&)> validator;
};

// ============================================================================
// Command Flag
// ============================================================================

struct CommandFlag {
    std::string name;
    std::string description;
    char shortName;
    bool takesValue;
    std::optional<std::string> defaultValue;
};

// ============================================================================
// Parsed Arguments
// ============================================================================

class ParsedArgs {
public:
    // Getters
    std::string GetString(const std::string& name) const;
    int GetInt(const std::string& name) const;
    float GetFloat(const std::string& name) const;
    bool GetBool(const std::string& name) const;
    std::vector<std::string> GetArray(const std::string& name) const;
    std::map<std::string, std::string> GetMap(const std::string& name) const;
    
    // Optional getters
    std::optional<std::string> GetOptionalString(const std::string& name) const;
    std::optional<int> GetOptionalInt(const std::string& name) const;
    
    // Flag checking
    bool HasFlag(const std::string& name) const;
    std::optional<std::string> GetFlagValue(const std::string& name) const;
    
    // Positional arguments
    std::vector<std::string> GetPositionalArgs() const;
    std::string GetPositionalArg(size_t index) const;
    
    // Validation
    bool Has(const std::string& name) const;
    bool IsValid() const { return error_.empty(); }
    const std::string& GetError() const { return error_; }
    
private:
    std::map<std::string, std::string> args_;
    std::map<std::string, bool> flags_;
    std::vector<std::string> positionalArgs_;
    std::string error_;
    
    friend class ArgumentParser;
};

// ============================================================================
// Command Result
// ============================================================================

class CommandResult {
public:
    enum class Status {
        SUCCESS,
        FAILURE,
        PARTIAL_SUCCESS,
        CANCELLED,
        TIMEOUT
    };
    
    static CommandResult Success(const std::string& message = "");
    static CommandResult Failure(const std::string& error, int exitCode = 1);
    static CommandResult PartialSuccess(const std::string& message,
                                        const std::vector<std::string>& warnings);
    
    Status GetStatus() const { return status_; }
    const std::string& GetMessage() const { return message_; }
    int GetExitCode() const { return exitCode_; }
    const std::vector<std::string>& GetWarnings() const { return warnings_; }
    const std::optional<std::string>& GetOutput() const { return output_; }
    
    void SetOutput(const std::string& output) { output_ = output; }
    
private:
    Status status_;
    std::string message_;
    int exitCode_;
    std::vector<std::string> warnings_;
    std::optional<std::string> output_;
};

// ============================================================================
// Command
// ============================================================================

class Command {
public:
    using Handler = std::function<CommandResult(const ParsedArgs&, CLIContext&)>;
    using PreHook = std::function<bool(const ParsedArgs&, CLIContext&)>;
    using PostHook = std::function<void(const CommandResult&, CLIContext&)>;
    
    struct Config {
        std::string name;
        std::string description;
        std::string longDescription;
        std::vector<CommandArg> arguments;
        std::vector<CommandFlag> flags;
        Handler handler;
        std::vector<std::string> examples;
        std::vector<std::string> aliases;
        std::vector<std::string> requiredPermissions;
        bool hidden = false;
        bool deprecated = false;
        std::optional<std::string> deprecationMessage;
    };
    
    explicit Command(const Config& config);
    
    // Execution
    CommandResult Execute(const ParsedArgs& args, CLIContext& context);
    
    // Hooks
    void SetPreHook(PreHook hook);
    void SetPostHook(PostHook hook);
    
    // Accessors
    const std::string& GetName() const { return config_.name; }
    const std::string& GetDescription() const { return config_.description; }
    const std::vector<std::string>& GetAliases() const { return config_.aliases; }
    bool IsHidden() const { return config_.hidden; }
    bool IsDeprecated() const { return config_.deprecated; }
    
    // Help generation
    std::string GetUsage() const;
    std::string GetHelp() const;
    
private:
    Config config_;
    PreHook preHook_;
    PostHook postHook_;
};

// ============================================================================
// CLI Context
// ============================================================================

class CLIContext {
public:
    struct Config {
        std::string apiEndpoint;
        std::string apiKey;
        std::optional<std::string> tenantId;
        std::optional<std::string> outputFormat; // json, yaml, table, csv
        bool verbose = false;
        bool quiet = false;
        bool noColor = false;
        bool interactive = true;
        std::optional<std::string> configFile;
    };
    
    explicit CLIContext(const Config& config);
    
    // Configuration
    const Config& GetConfig() const { return config_; }
    void SetConfig(const Config& config) { config_ = config; }
    
    // API client
    std::shared_ptr<APIClient> GetAPIClient() const;
    bool IsAuthenticated() const;
    
    // Output
    void Print(const std::string& message) const;
    void PrintError(const std::string& message) const;
    void PrintWarning(const std::string& message) const;
    void PrintSuccess(const std::string& message) const;
    void PrintTable(const std::vector<std::vector<std::string>>& data,
                    const std::vector<std::string>& headers) const;
    void PrintJson(const std::string& json) const;
    void PrintYaml(const std::string& yaml) const;
    
    // Interactive
    std::string Prompt(const std::string& message) const;
    std::string PromptPassword(const std::string& message) const;
    bool Confirm(const std::string& message) const;
    std::optional<std::string> Select(const std::string& message,
                                      const std::vector<std::string>& options) const;
    
    // Progress
    std::unique_ptr<ProgressIndicator> CreateProgressIndicator(
        const std::string& description,
        uint32_t totalSteps) const;
    
    // Logging
    void LogVerbose(const std::string& message) const;
    void LogDebug(const std::string& message) const;
    
    // State
    void SetExitCode(int code) { exitCode_ = code; }
    int GetExitCode() const { return exitCode_; }
    
private:
    Config config_;
    mutable std::shared_ptr<APIClient> apiClient_;
    int exitCode_;
};

// ============================================================================
// Progress Indicator
// ============================================================================

class ProgressIndicator {
public:
    explicit ProgressIndicator(const std::string& description, uint32_t totalSteps);
    ~ProgressIndicator();
    
    void Update(uint32_t currentStep, const std::string& status = "");
    void Increment(const std::string& status = "");
    void Complete(const std::string& message = "");
    void Fail(const std::string& error);
    
    uint32_t GetCurrentStep() const { return currentStep_; }
    uint32_t GetTotalSteps() const { return totalSteps_; }
    double GetPercentage() const;
    
private:
    std::string description_;
    uint32_t totalSteps_;
    uint32_t currentStep_;
    std::chrono::system_clock::time_point startTime_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Command Registry
// ============================================================================

class CommandRegistry {
public:
    static CommandRegistry& Instance();
    
    // Registration
    void Register(std::shared_ptr<Command> command);
    void Register(const Command::Config& config);
    void Unregister(const std::string& name);
    
    // Discovery
    std::shared_ptr<Command> GetCommand(const std::string& name) const;
    std::vector<std::shared_ptr<Command>> GetCommands() const;
    std::vector<std::shared_ptr<Command>> GetCommandsByCategory(
        const std::string& category) const;
    std::vector<std::string> GetCommandNames() const;
    
    // Categories
    void SetCategory(const std::string& commandName, const std::string& category);
    std::vector<std::string> GetCategories() const;
    
    // Aliases
    void RegisterAlias(const std::string& alias, const std::string& commandName);
    void UnregisterAlias(const std::string& alias);
    
private:
    CommandRegistry() = default;
    
    std::map<std::string, std::shared_ptr<Command>> commands_;
    std::map<std::string, std::string> aliases_;
    std::map<std::string, std::string> commandCategories_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Built-in Commands
// ============================================================================

// Authentication commands
CommandResult LoginCommand(const ParsedArgs& args, CLIContext& context);
CommandResult LogoutCommand(const ParsedArgs& args, CLIContext& context);
CommandResult WhoamiCommand(const ParsedArgs& args, CLIContext& context);

// Tenant commands
CommandResult TenantCreateCommand(const ParsedArgs& args, CLIContext& context);
CommandResult TenantListCommand(const ParsedArgs& args, CLIContext& context);
CommandResult TenantDeleteCommand(const ParsedArgs& args, CLIContext& context);
CommandResult TenantSwitchCommand(const ParsedArgs& args, CLIContext& context);
CommandResult TenantStatusCommand(const ParsedArgs& args, CLIContext& context);

// Model commands
CommandResult ModelListCommand(const ParsedArgs& args, CLIContext& context);
CommandResult ModelLoadCommand(const ParsedArgs& args, CLIContext& context);
CommandResult ModelUnloadCommand(const ParsedArgs& args, CLIContext& context);
CommandResult ModelStatusCommand(const ParsedArgs& args, CLIContext& context);

// Inference commands
CommandResult InferenceRunCommand(const ParsedArgs& args, CLIContext& context);
CommandResult InferenceBatchCommand(const ParsedArgs& args, CLIContext& context);
CommandResult InferenceStreamCommand(const ParsedArgs& args, CLIContext& context);

// Workflow commands
CommandResult WorkflowListCommand(const ParsedArgs& args, CLIContext& context);
CommandResult WorkflowStartCommand(const ParsedArgs& args, CLIContext& context);
CommandResult WorkflowStatusCommand(const ParsedArgs& args, CLIContext& context);
CommandResult WorkflowCancelCommand(const ParsedArgs& args, CLIContext& context);

// Deployment commands
CommandResult DeployCommand(const ParsedArgs& args, CLIContext& context);
CommandResult RollbackCommand(const ParsedArgs& args, CLIContext& context);
CommandResult ScaleCommand(const ParsedArgs& args, CLIContext& context);

// Debug commands
CommandResult LogsCommand(const ParsedArgs& args, CLIContext& context);
CommandResult MetricsCommand(const ParsedArgs& args, CLIContext& context);
CommandResult TraceCommand(const ParsedArgs& args, CLIContext& context);
CommandResult ShellCommand(const ParsedArgs& args, CLIContext& context);

// Configuration commands
CommandResult ConfigGetCommand(const ParsedArgs& args, CLIContext& context);
CommandResult ConfigSetCommand(const ParsedArgs& args, CLIContext& context);
CommandResult ConfigListCommand(const ParsedArgs& args, CLIContext& context);

// Utility commands
CommandResult VersionCommand(const ParsedArgs& args, CLIContext& context);
CommandResult HelpCommand(const ParsedArgs& args, CLIContext& context);
CommandResult CompletionCommand(const ParsedArgs& args, CLIContext& context);

// ============================================================================
// CLI Application
// ============================================================================

class CLIApplication {
public:
    struct Config {
        std::string name;
        std::string version;
        std::string description;
        std::optional<std::string> defaultCommand;
    };
    
    explicit CLIApplication(const Config& config);
    
    // Setup
    void RegisterBuiltInCommands();
    void RegisterCommand(const Command::Config& config);
    void SetGlobalFlag(const CommandFlag& flag);
    
    // Execution
    int Run(int argc, char* argv[]);
    int Run(const std::vector<std::string>& args);
    
    // Help
    std::string GetGlobalHelp() const;
    std::string GetVersionInfo() const;
    
private:
    Config config_;
    std::vector<CommandFlag> globalFlags_;
    
    ParsedArgs ParseArguments(const std::vector<std::string>& args) const;
    void PrintUsage() const;
    CLIContext CreateContext(const ParsedArgs& args) const;
};

// ============================================================================
// Auto-completion
// ============================================================================

class AutoCompletion {
public:
    static std::vector<std::string> CompleteCommand(const std::string& partial);
    static std::vector<std::string> CompleteFlag(const std::string& command,
                                                  const std::string& partial);
    static std::vector<std::string> CompleteArgument(const std::string& command,
                                                       const std::string& argName,
                                                       const std::string& partial);
    
    // Shell integration
    static std::string GenerateBashCompletion();
    static std::string GenerateZshCompletion();
    static std::string GenerateFishCompletion();
    static std::string GeneratePowerShellCompletion();
};

// ============================================================================
// Configuration Management
// ============================================================================

class ConfigManager {
public:
    struct UserConfig {
        std::string apiEndpoint;
        std::string apiKey;
        std::optional<std::string> defaultTenant;
        std::string outputFormat = "table";
        bool verbose = false;
        bool autoUpdate = true;
        std::map<std::string, std::string> aliases;
    };
    
    static std::string GetConfigPath();
    static UserConfig Load();
    static void Save(const UserConfig& config);
    static bool Exists();
    
    // Profile management
    static void CreateProfile(const std::string& name, const UserConfig& config);
    static void SwitchProfile(const std::string& name);
    static void DeleteProfile(const std::string& name);
    static std::vector<std::string> ListProfiles();
};

} // namespace CLI
} // namespace SDK
