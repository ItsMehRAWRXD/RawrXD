// Phase Y.3/5: Developer CLI
// RawrXD Developer CLI - Command-line tools for developers

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <variant>

namespace RawrXD {
namespace Developer {

// CLI command result
struct CLIResult {
    bool success;
    int exit_code;
    std::string output;
    std::string error;
    std::chrono::milliseconds duration;
};

// CLI command definition
struct CLICommand {
    std::string name;
    std::string description;
    std::string usage;
    std::vector<std::string> aliases;
    
    // Arguments
    struct Argument {
        std::string name;
        std::string description;
        bool required;
        std::string default_value;
        std::vector<std::string> choices;
    };
    std::vector<Argument> arguments;
    
    // Options
    struct Option {
        std::string name;
        std::string short_name;
        std::string description;
        std::string default_value;
        bool is_flag;
    };
    std::vector<Option> options;
    
    // Handler
    std::function<CLIResult(const std::unordered_map<std::string, std::string>& args,
                             const std::unordered_map<std::string, std::string>& opts)> handler;
    
    // Subcommands
    std::vector<CLICommand> subcommands;
};

// Project template
struct ProjectTemplate {
    std::string name;
    std::string description;
    std::string category;  // "plugin", "extension", "model", "tool"
    
    // Files to generate
    struct TemplateFile {
        std::string path;
        std::string content;
        bool is_executable;
    };
    std::vector<TemplateFile> files;
    
    // Variables to substitute
    std::vector<std::string> required_variables;
    std::unordered_map<std::string, std::string> default_variables;
};

// Build task
struct BuildTask {
    std::string name;
    std::string description;
    std::string command;
    std::vector<std::string> args;
    std::unordered_map<std::string, std::string> env;
    std::string working_directory;
    std::chrono::seconds timeout;
    bool is_background;
};

// Test result
struct TestResult {
    std::string test_name;
    std::string suite_name;
    bool passed;
    std::chrono::milliseconds duration;
    std::string output;
    std::string error;
    std::string stack_trace;
    std::unordered_map<std::string, std::string> metadata;
};

// Benchmark result
struct BenchmarkResult {
    std::string benchmark_name;
    std::string category;
    double value;
    std::string unit;
    std::chrono::milliseconds duration;
    std::unordered_map<std::string, double> metrics;
    std::unordered_map<std::string, std::string> context;
};

// Package info
struct PackageInfo {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string license;
    std::vector<std::string> dependencies;
    std::vector<std::string> files;
    std::chrono::system_clock::time_point created_at;
    std::string checksum;
};

// Developer CLI interface
class IDeveloperCLI {
public:
    virtual ~IDeveloperCLI() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Command registration
    virtual bool RegisterCommand(const CLICommand& command) = 0;
    virtual bool UnregisterCommand(const std::string& name) = 0;
    virtual std::vector<CLICommand> ListCommands() = 0;
    virtual std::optional<CLICommand> GetCommand(const std::string& name) = 0;
    
    // Command execution
    virtual CLIResult Execute(const std::vector<std::string>& args) = 0;
    virtual CLIResult ExecuteString(const std::string& command_line) = 0;
    
    // Interactive mode
    virtual void StartInteractiveMode() = 0;
    virtual void StopInteractiveMode() = 0;
    virtual bool IsInteractiveMode() const = 0;
    
    // Project scaffolding
    virtual std::vector<ProjectTemplate> ListTemplates() = 0;
    virtual bool CreateProject(const std::string& template_name,
                                 const std::string& project_path,
                                 const std::unordered_map<std::string, std::string>& variables) = 0;
    virtual bool AddTemplate(const ProjectTemplate& template_def) = 0;
    
    // Build system
    virtual bool RegisterBuildTask(const BuildTask& task) = 0;
    virtual bool RunBuildTask(const std::string& task_name) = 0;
    virtual bool RunBuildPipeline(const std::vector<std::string>& task_names) = 0;
    virtual std::vector<BuildTask> ListBuildTasks() = 0;
    
    // Testing
    virtual std::vector<TestResult> RunTests(const std::string& pattern = "",
                                                 const std::string& suite = "") = 0;
    virtual bool RunTestCoverage(const std::string& output_path = "") = 0;
    virtual std::vector<std::string> ListTestSuites() = 0;
    
    // Benchmarking
    virtual std::vector<BenchmarkResult> RunBenchmarks(const std::string& pattern = "") = 0;
    virtual bool CompareBenchmarks(const std::string& baseline,
                                      const std::string& current) = 0;
    virtual std::string GenerateBenchmarkReport() = 0;
    
    // Packaging
    virtual bool BuildPackage(const std::string& source_path,
                                const std::string& output_path) = 0;
    virtual bool ValidatePackage(const std::string& package_path) = 0;
    virtual bool PublishPackage(const std::string& package_path,
                                   const std::string& registry = "") = 0;
    virtual std::vector<PackageInfo> ListPackages() = 0;
    
    // Debugging
    virtual bool AttachDebugger(uint32_t process_id) = 0;
    virtual bool StartProfiling(const std::string& output_path) = 0;
    virtual bool StopProfiling() = 0;
    virtual std::string AnalyzeCoreDump(const std::string& dump_path) = 0;
    
    // Documentation
    virtual bool GenerateDocumentation(const std::string& source_path,
                                         const std::string& output_path) = 0;
    virtual bool GenerateAPIReference(const std::string& output_path) = 0;
    
    // Configuration
    virtual bool SetConfig(const std::string& key, const std::string& value) = 0;
    virtual std::optional<std::string> GetConfig(const std::string& key) = 0;
    virtual std::unordered_map<std::string, std::string> GetAllConfig() = 0;
    
    // Completion
    virtual std::vector<std::string> GetCompletions(const std::string& partial) = 0;
    virtual std::vector<std::string> GetCommandCompletions(const std::string& partial) = 0;
    virtual std::vector<std::string> GetFileCompletions(const std::string& partial) = 0;
    
    // History
    virtual std::vector<std::string> GetCommandHistory() = 0;
    virtual void ClearCommandHistory() = 0;
    
    // Help
    virtual std::string GenerateHelp(const std::string& command = "") = 0;
    virtual std::string GenerateMarkdownHelp() = 0;
};

// Built-in commands
namespace BuiltInCommands {

// Project commands
CLIResult CmdInit(const std::unordered_map<std::string, std::string>& args,
                   const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdBuild(const std::unordered_map<std::string, std::string>& args,
                    const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdTest(const std::unordered_map<std::string, std::string>& args,
                   const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdRun(const std::unordered_map<std::string, std::string>& args,
                  const std::unordered_map<std::string, std::string>& opts);

// Plugin commands
CLIResult CmdPluginCreate(const std::unordered_map<std::string, std::string>& args,
                          const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdPluginBuild(const std::unordered_map<std::string, std::string>& args,
                          const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdPluginInstall(const std::unordered_map<std::string, std::string>& args,
                            const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdPluginPublish(const std::unordered_map<std::string, std::string>& args,
                            const std::unordered_map<std::string, std::string>& opts);

// Extension commands
CLIResult CmdExtensionCreate(const std::unordered_map<std::string, std::string>& args,
                              const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdExtensionPackage(const std::unordered_map<std::string, std::string>& args,
                               const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdExtensionInstall(const std::unordered_map<std::string, std::string>& args,
                               const std::unordered_map<std::string, std::string>& opts);

// Debug commands
CLIResult CmdDebug(const std::unordered_map<std::string, std::string>& args,
                    const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdProfile(const std::unordered_map<std::string, std::string>& args,
                      const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdTrace(const std::unordered_map<std::string, std::string>& args,
                    const std::unordered_map<std::string, std::string>& opts);

// Documentation commands
CLIResult CmdDocs(const std::unordered_map<std::string, std::string>& args,
                   const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdGenerate(const std::unordered_map<std::string, std::string>& args,
                       const std::unordered_map<std::string, std::string>& opts);

// System commands
CLIResult CmdStatus(const std::unordered_map<std::string, std::string>& args,
                     const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdConfig(const std::unordered_map<std::string, std::string>& args,
                     const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdUpdate(const std::unordered_map<std::string, std::string>& args,
                     const std::unordered_map<std::string, std::string>& opts);
CLIResult CmdVersion(const std::unordered_map<std::string, std::string>& args,
                      const std::unordered_map<std::string, std::string>& opts);

} // namespace BuiltInCommands

// Local developer CLI implementation
class LocalDeveloperCLI : public IDeveloperCLI {
public:
    LocalDeveloperCLI();
    ~LocalDeveloperCLI() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    bool RegisterCommand(const CLICommand& command) override;
    bool UnregisterCommand(const std::string& name) override;
    std::vector<CLICommand> ListCommands() override;
    std::optional<CLICommand> GetCommand(const std::string& name) override;
    
    CLIResult Execute(const std::vector<std::string>& args) override;
    CLIResult ExecuteString(const std::string& command_line) override;
    
    void StartInteractiveMode() override;
    void StopInteractiveMode() override;
    bool IsInteractiveMode() const override;
    
    std::vector<ProjectTemplate> ListTemplates() override;
    bool CreateProject(const std::string& template_name,
                       const std::string& project_path,
                       const std::unordered_map<std::string, std::string>& variables) override;
    bool AddTemplate(const ProjectTemplate& template_def) override;
    
    bool RegisterBuildTask(const BuildTask& task) override;
    bool RunBuildTask(const std::string& task_name) override;
    bool RunBuildPipeline(const std::vector<std::string>& task_names) override;
    std::vector<BuildTask> ListBuildTasks() override;
    
    std::vector<TestResult> RunTests(const std::string& pattern = "",
                                         const std::string& suite = "") override;
    bool RunTestCoverage(const std::string& output_path = "") override;
    std::vector<std::string> ListTestSuites() override;
    
    std::vector<BenchmarkResult> RunBenchmarks(const std::string& pattern = "") override;
    bool CompareBenchmarks(const std::string& baseline,
                              const std::string& current) override;
    std::string GenerateBenchmarkReport() override;
    
    bool BuildPackage(const std::string& source_path,
                       const std::string& output_path) override;
    bool ValidatePackage(const std::string& package_path) override;
    bool PublishPackage(const std::string& package_path,
                          const std::string& registry = "") override;
    std::vector<PackageInfo> ListPackages() override;
    
    bool AttachDebugger(uint32_t process_id) override;
    bool StartProfiling(const std::string& output_path) override;
    bool StopProfiling() override;
    std::string AnalyzeCoreDump(const std::string& dump_path) override;
    
    bool GenerateDocumentation(const std::string& source_path,
                                 const std::string& output_path) override;
    bool GenerateAPIReference(const std::string& output_path) override;
    
    bool SetConfig(const std::string& key, const std::string& value) override;
    std::optional<std::string> GetConfig(const std::string& key) override;
    std::unordered_map<std::string, std::string> GetAllConfig() override;
    
    std::vector<std::string> GetCompletions(const std::string& partial) override;
    std::vector<std::string> GetCommandCompletions(const std::string& partial) override;
    std::vector<std::string> GetFileCompletions(const std::string& partial) override;
    
    std::vector<std::string> GetCommandHistory() override;
    void ClearCommandHistory() override;
    
    std::string GenerateHelp(const std::string& command = "") override;
    std::string GenerateMarkdownHelp() override;
    
private:
    std::unordered_map<std::string, CLICommand> commands_;
    std::vector<ProjectTemplate> templates_;
    std::vector<BuildTask> build_tasks_;
    std::unordered_map<std::string, std::string> config_;
    std::vector<std::string> command_history_;
    bool interactive_mode_ = false;
    bool initialized_ = false;
    
    void RegisterBuiltInCommands();
    std::vector<std::string> Tokenize(const std::string& line);
    std::pair<std::unordered_map<std::string, std::string>,
               std::unordered_map<std::string, std::string>> ParseArgs(
        const std::vector<std::string>& tokens,
        const CLICommand& command);
    void InteractiveLoop();
};

// Global developer CLI
extern std::unique_ptr<IDeveloperCLI> g_developer_cli;

// Initialize developer CLI
bool InitializeDeveloperCLI(const std::string& config_path);
void ShutdownDeveloperCLI();
bool IsDeveloperCLIEnabled();

} // namespace Developer
} // namespace RawrXD
