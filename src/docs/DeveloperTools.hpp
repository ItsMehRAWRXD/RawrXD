/**
 * DeveloperTools.hpp
 *
 * Phase J Batch 3/5: Developer Tools & CLI
 *
 * Command-line tools for developers including project scaffolding,
 code generators, and development workflow automation.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace Docs {

// ============================================================================
// Forward Declarations
// ============================================================================

class CLICommand;
class CLIApplication;
class ProjectScaffolder;
class CodeGenerator;
class DevWorkflow;

// ============================================================================
// CLI Types
// ============================================================================

enum class CLIArgumentType {
    STRING,
    INTEGER,
    FLOAT,
    BOOLEAN,
    FLAG,
    CHOICE,
    PATH,
    FILE,
    DIRECTORY,
    LIST,
    MAP
};

// ============================================================================
// CLI Argument
// ============================================================================

/**
 * CLI argument definition.
 */
struct CLIArgument {
    std::string name;
    std::string shortName;
    std::string description;
    CLIArgumentType type;
    bool required;
    bool positional;
    std::optional<std::string> defaultValue;
    std::vector<std::string> choices;
    std::string helpText;
    std::string envVar;
    
    CLIArgument();
    
    static CLIArgument String(const std::string& name, const std::string& description);
    static CLIArgument Int(const std::string& name, const std::string& description);
    static CLIArgument Float(const std::string& name, const std::string& description);
    static CLIArgument Bool(const std::string& name, const std::string& description);
    static CLIArgument Flag(const std::string& name, const std::string& description);
    static CLIArgument Choice(const std::string& name, const std::string& description,
                               const std::vector<std::string>& choices);
    static CLIArgument Path(const std::string& name, const std::string& description);
    static CLIArgument File(const std::string& name, const std::string& description);
    static CLIArgument Directory(const std::string& name, const std::string& description);
};

// ============================================================================
// CLI Command
// ============================================================================

/**
 * CLI command.
 */
class CLICommand {
public:
    using HandlerFunc = std::function<int(const std::map<std::string, std::string>&)>;
    
    CLICommand(const std::string& name, const std::string& description);
    
    // Arguments
    void AddArgument(const CLIArgument& arg);
    void AddArguments(const std::vector<CLIArgument>& args);
    std::vector<CLIArgument> GetArguments() const;
    
    // Subcommands
    void AddSubcommand(std::shared_ptr<CLICommand> cmd);
    std::shared_ptr<CLICommand> GetSubcommand(const std::string& name) const;
    std::vector<std::shared_ptr<CLICommand>> GetSubcommands() const;
    
    // Handler
    void SetHandler(HandlerFunc handler);
    int Execute(const std::map<std::string, std::string>& args) const;
    
    // Help
    std::string GetHelp() const;
    std::string GetUsage() const;
    
    // Accessors
    std::string GetName() const { return name_; }
    std::string GetDescription() const { return description_; }
    
private:
    std::string name_;
    std::string description_;
    std::vector<CLIArgument> arguments_;
    std::vector<std::shared_ptr<CLICommand>> subcommands_;
    HandlerFunc handler_;
};

// ============================================================================
// CLI Application
// ============================================================================

/**
 * CLI application framework.
 */
class CLIApplication {
public:
    struct Config {
        std::string name;
        std::string version;
        std::string description;
        std::string author;
        std::string helpText;
        bool enableColors = true;
        bool enableHelp = true;
        bool enableVersion = true;
        bool enableCompletion = true;
    };
    
    explicit CLIApplication(const Config& config);
    
    // Commands
    void AddCommand(std::shared_ptr<CLICommand> cmd);
    void SetDefaultCommand(std::shared_ptr<CLICommand> cmd);
    
    // Global flags
    void AddGlobalFlag(const CLIArgument& flag);
    
    // Middleware
    using MiddlewareFunc = std::function<bool(const std::map<std::string, std::string>&)>;
    void AddMiddleware(MiddlewareFunc middleware);
    
    // Execution
    int Run(int argc, char** argv);
    int Run(const std::vector<std::string>& args);
    
    // Help
    void PrintHelp();
    void PrintVersion();
    void PrintCompletionScript(const std::string& shell);
    
private:
    Config config_;
    std::vector<std::shared_ptr<CLICommand>> commands_;
    std::shared_ptr<CLICommand> defaultCommand_;
    std::vector<CLIArgument> globalFlags_;
    std::vector<MiddlewareFunc> middleware_;
    
    std::map<std::string, std::string> ParseArgs(int argc, char** argv);
    std::shared_ptr<CLICommand> FindCommand(const std::string& name);
};

// ============================================================================
// Project Scaffolder
// ============================================================================

/**
 * Project scaffolding tool.
 */
class ProjectScaffolder {
public:
    struct Template {
        std::string name;
        std::string description;
        std::string category;
        std::vector<std::string> files;
        std::map<std::string, std::string> variables;
    };
    
    struct Config {
        std::string projectName;
        std::string projectType;
        std::string outputDirectory;
        std::string templateName;
        std::map<std::string, std::string> variables;
        bool initializeGit = true;
        bool createReadme = true;
        bool installDependencies = false;
    };
    
    explicit ProjectScaffolder(const std::string& templatesDir);
    
    // Templates
    void RegisterTemplate(const Template& tmpl);
    std::vector<Template> GetTemplates() const;
    std::vector<Template> GetTemplatesByCategory(const std::string& category) const;
    std::optional<Template> GetTemplate(const std::string& name) const;
    
    // Scaffolding
    bool Scaffold(const Config& config);
    bool ScaffoldFromTemplate(const std::string& templateName, const Config& config);
    
    // Interactive
    Config InteractiveScaffold();
    
private:
    std::string templatesDir_;
    std::vector<Template> templates_;
    
    bool CreateDirectoryStructure(const Config& config);
    bool GenerateFiles(const Config& config, const Template& tmpl);
    bool InitializeGit(const std::string& directory);
    bool InstallDependencies(const std::string& directory);
    std::string ProcessTemplate(const std::string& content,
                                 const std::map<std::string, std::string>& variables);
};

// ============================================================================
// Code Generator
// ============================================================================

/**
 * Code generation tool.
 */
class CodeGenerator {
public:
    struct Config {
        std::string templateFile;
        std::string outputFile;
        std::map<std::string, std::string> variables;
        bool overwrite = false;
        bool backup = true;
    };
    
    // Template-based generation
    bool GenerateFromTemplate(const Config& config);
    
    // Language-specific generators
    bool GenerateClass(const std::string& language, const std::string& className,
                       const std::map<std::string, std::string>& options);
    bool GenerateInterface(const std::string& language, const std::string& interfaceName,
                           const std::map<std::string, std::string>& options);
    bool GenerateEnum(const std::string& language, const std::string& enumName,
                      const std::vector<std::string>& values);
    bool GenerateStruct(const std::string& language, const std::string& structName,
                        const std::map<std::string, std::string>& fields);
    bool GenerateFunction(const std::string& language, const std::string& funcName,
                          const std::map<std::string, std::string>& signature);
    
    // Boilerplate generators
    bool GenerateCMakeLists(const std::string& projectName,
                            const std::vector<std::string>& sources);
    bool GenerateMakefile(const std::string& projectName,
                          const std::vector<std::string>& sources);
    bool GeneratePackageJson(const std::string& projectName,
                             const std::map<std::string, std::string>& deps);
    bool GenerateSetupPy(const std::string& projectName,
                         const std::map<std::string, std::string>& deps);
    bool GenerateCargoToml(const std::string& projectName,
                           const std::vector<std::string>& deps);
    
    // Test generators
    bool GenerateUnitTest(const std::string& language, const std::string& className);
    bool GenerateIntegrationTest(const std::string& language, const std::string& testName);
    bool GenerateMock(const std::string& language, const std::string& interfaceName);
    
private:
    std::string GenerateCppClass(const std::string& className,
                                  const std::map<std::string, std::string>& options);
    std::string GeneratePythonClass(const std::string& className,
                                     const std::map<std::string, std::string>& options);
    std::string GenerateJavaScriptClass(const std::string& className,
                                          const std::map<std::string, std::string>& options);
};

// ============================================================================
// Development Workflow
// ============================================================================

/**
 * Development workflow automation.
 */
class DevWorkflow {
public:
    struct Task {
        std::string name;
        std::string description;
        std::vector<std::string> commands;
        std::vector<std::string> dependsOn;
        std::map<std::string, std::string> envVars;
        std::string workingDirectory;
        bool parallel;
        uint64_t timeoutMs;
    };
    
    struct Workflow {
        std::string name;
        std::string description;
        std::vector<Task> tasks;
        std::string defaultTask;
    };
    
    // Workflow management
    void LoadWorkflow(const std::string& filepath);
    void SaveWorkflow(const std::string& filepath);
    void CreateWorkflow(const std::string& name);
    
    // Tasks
    void AddTask(const Task& task);
    void RemoveTask(const std::string& name);
    void UpdateTask(const std::string& name, const Task& task);
    
    // Execution
    bool RunTask(const std::string& name);
    bool RunWorkflow();
    bool RunTaskWithDeps(const std::string& name);
    
    // Watch mode
    void Watch(const std::vector<std::string>& paths,
               const std::vector<std::string>& tasks);
    void StopWatching();
    
    // Hooks
    void AddPreHook(const std::string& task, const std::string& command);
    void AddPostHook(const std::string& task, const std::string& command);
    
private:
    Workflow workflow_;
    std::map<std::string, std::vector<std::string>> preHooks_;
    std::map<std::string, std::vector<std::string>> postHooks_;
    std::atomic<bool> watching_{false};
    std::thread watchThread_;
    
    std::vector<std::string> GetTaskOrder(const std::string& taskName);
    bool ExecuteTask(const Task& task);
    void WatchLoop(const std::vector<std::string>& paths,
                   const std::vector<std::string>& tasks);
};

// ============================================================================
// Package Manager
// ============================================================================

/**
 * Package management tool.
 */
class PackageManager {
public:
    enum class PackageType {
        NPM,
        PIP,
        CARGO,
        GEM,
        COMPOSER,
        MAVEN,
        NUGET,
        CONAN,
        VCPKG
    };
    
    struct Package {
        std::string name;
        std::string version;
        std::string description;
        std::string author;
        std::string license;
        std::string repository;
        std::vector<std::string> dependencies;
        std::vector<std::string> devDependencies;
    };
    
    explicit PackageManager(PackageType type);
    
    // Initialization
    bool Init(const std::string& projectName);
    
    // Dependencies
    bool Install(const std::string& package, const std::string& version = "");
    bool InstallDev(const std::string& package, const std::string& version = "");
    bool InstallAll();
    bool Uninstall(const std::string& package);
    bool Update(const std::string& package = "");
    
    // Search
    std::vector<Package> Search(const std::string& query);
    std::optional<Package> Info(const std::string& package);
    
    // Audit
    bool Audit();
    std::vector<std::map<std::string, std::string>> GetVulnerabilities();
    bool Fix();
    
    // Scripts
    bool RunScript(const std::string& name);
    void AddScript(const std::string& name, const std::string& command);
    
private:
    PackageType type_;
    std::string manifestFile_;
    
    std::string GetInstallCommand(const std::string& package, const std::string& version);
    std::string GetUninstallCommand(const std::string& package);
};

// ============================================================================
// Linting & Formatting
// ============================================================================

/**
 * Code linting and formatting tool.
 */
class CodeFormatter {
public:
    enum class Language {
        CPP,
        C,
        C_SHARP,
        JAVA,
        PYTHON,
        JAVASCRIPT,
        TYPESCRIPT,
        GO,
        RUST,
        HTML,
        CSS,
        JSON,
        XML,
        YAML,
        MARKDOWN
    };
    
    struct Config {
        Language language;
        std::string configFile;
        bool fix = false;
        bool check = false;
        bool quiet = false;
        std::vector<std::string> excludePatterns;
    };
    
    explicit CodeFormatter(const Config& config);
    
    // Formatting
    bool FormatFile(const std::string& filepath);
    bool FormatFiles(const std::vector<std::string>& filepaths);
    bool FormatDirectory(const std::string& dirpath);
    
    // Checking
    bool CheckFile(const std::string& filepath);
    bool CheckFiles(const std::vector<std::string>& filepaths);
    bool CheckDirectory(const std::string& dirpath);
    
    // Results
    struct Result {
        std::string file;
        bool formatted;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
    };
    std::vector<Result> GetResults() const;
    
private:
    Config config_;
    std::vector<Result> results_;
    
    std::string GetFormatterCommand();
    std::string GetLinterCommand();
};

// ============================================================================
// Git Utilities
// ============================================================================

/**
 * Git utility functions.
 */
class GitUtils {
public:
    // Repository
    static bool IsRepository(const std::string& path = ".");
    static bool Init(const std::string& path = ".");
    static std::string GetRoot(const std::string& path = ".");
    
    // Status
    static bool HasChanges(const std::string& path = ".");
    static std::vector<std::string> GetModifiedFiles(const std::string& path = ".");
    static std::vector<std::string> GetUntrackedFiles(const std::string& path = ".");
    
    // Branches
    static std::string GetCurrentBranch(const std::string& path = ".");
    static std::vector<std::string> GetBranches(const std::string& path = ".");
    static bool CreateBranch(const std::string& name, const std::string& path = ".");
    static bool CheckoutBranch(const std::string& name, const std::string& path = ".");
    static bool DeleteBranch(const std::string& name, bool force = false,
                             const std::string& path = ".");
    
    // Commits
    static bool Add(const std::string& file, const std::string& path = ".");
    static bool AddAll(const std::string& path = ".");
    static bool Commit(const std::string& message, const std::string& path = ".");
    static std::string GetLastCommitMessage(const std::string& path = ".");
    static std::string GetLastCommitHash(const std::string& path = ".");
    
    // Remotes
    static std::vector<std::string> GetRemotes(const std::string& path = ".");
    static bool AddRemote(const std::string& name, const std::string& url,
                          const std::string& path = ".");
    static bool RemoveRemote(const std::string& name, const std::string& path = ".");
    static bool Fetch(const std::string& remote = "origin",
                      const std::string& path = ".");
    static bool Pull(const std::string& remote = "origin",
                     const std::string& branch = "",
                     const std::string& path = ".");
    static bool Push(const std::string& remote = "origin",
                     const std::string& branch = "",
                     const std::string& path = ".");
    
    // Tags
    static std::vector<std::string> GetTags(const std::string& path = ".");
    static bool CreateTag(const std::string& name, const std::string& message = "",
                          const std::string& path = ".");
    static bool DeleteTag(const std::string& name, const std::string& path = ".");
    static bool PushTag(const std::string& name, const std::string& remote = "origin",
                        const std::string& path = ".");
    
    // Stash
    static bool Stash(const std::string& message = "", const std::string& path = ".");
    static bool StashPop(const std::string& path = ".");
    static std::vector<std::string> GetStashes(const std::string& path = ".");
    
    // Hooks
    static bool InstallHook(const std::string& name, const std::string& script,
                            const std::string& path = ".");
    static bool UninstallHook(const std::string& name, const std::string& path = ".");
    
    // Info
    struct CommitInfo {
        std::string hash;
        std::string author;
        std::string email;
        std::string date;
        std::string message;
    };
    static std::vector<CommitInfo> GetLog(uint32_t count = 10,
                                             const std::string& path = ".");
    static CommitInfo GetCommitInfo(const std::string& hash,
                                    const std::string& path = ".");
};

// ============================================================================
// Build System
// ============================================================================

/**
 * Build system abstraction.
 */
class BuildSystem {
public:
    enum class Type {
        CMAKE,
        MAKE,
        NINJA,
        MSBUILD,
        GRADLE,
        MAVEN,
        NPM,
        CARGO,
        MESON,
        BAZEL
    };
    
    struct Config {
        Type type;
        std::string buildDirectory;
        std::string config;  // Debug, Release, etc.
        uint32_t parallelJobs;
        bool verbose;
        std::vector<std::string> targets;
        std::map<std::string, std::string> options;
    };
    
    explicit BuildSystem(const Config& config);
    
    // Configuration
    bool Configure();
    bool Configure(const std::map<std::string, std::string>& options);
    
    // Building
    bool Build();
    bool Build(const std::string& target);
    bool Build(const std::vector<std::string>& targets);
    bool Rebuild();
    bool Clean();
    
    // Testing
    bool Test();
    bool Test(const std::string& pattern);
    
    // Installation
    bool Install(const std::string& prefix = "");
    bool Package();
    
    // Info
    std::vector<std::string> GetTargets();
    std::vector<std::string> GetConfigurations();
    
private:
    Config config_;
    
    std::string GetConfigureCommand();
    std::string GetBuildCommand();
    std::string GetTestCommand();
    std::string GetInstallCommand();
};

// ============================================================================
// Interactive Prompts
// ============================================================================

/**
 * Interactive CLI prompts.
 */
class InteractivePrompts {
public:
    // Input
    static std::string Input(const std::string& message,
                              const std::optional<std::string>& defaultValue = std::nullopt);
    static std::string Password(const std::string& message);
    static bool Confirm(const std::string& message, bool defaultValue = false);
    static std::string Choice(const std::string& message,
                               const std::vector<std::string>& choices);
    static std::vector<std::string> MultiChoice(const std::string& message,
                                                    const std::vector<std::string>& choices);
    static int Number(const std::string& message, int min = INT_MIN, int max = INT_MAX);
    static std::string Path(const std::string& message, bool mustExist = false);
    static std::string File(const std::string& message, bool mustExist = false);
    static std::string Directory(const std::string& message, bool mustExist = false);
    
    // Progress
    class ProgressBar {
    public:
        ProgressBar(const std::string& title, int total);
        void Update(int current);
        void Finish();
        
    private:
        std::string title_;
        int total_;
        int current_;
    };
    
    // Spinner
    class Spinner {
    public:
        explicit Spinner(const std::string& message);
        ~Spinner();
        void Stop();
        void Succeed(const std::string& message = "");
        void Fail(const std::string& message = "");
        void Warn(const std::string& message = "");
        void Info(const std::string& message = "");
        
    private:
        std::string message_;
        std::atomic<bool> running_{false};
        std::thread thread_;
        
        void Spin();
    };
    
    // Output
    static void Success(const std::string& message);
    static void Error(const std::string& message);
    static void Warning(const std::string& message);
    static void Info(const std::string& message);
    static void Debug(const std::string& message);
    
    // Tables
    static void Table(const std::vector<std::string>& headers,
                      const std::vector<std::vector<std::string>>& rows);
    
    // Lists
    static void List(const std::vector<std::string>& items);
    static void OrderedList(const std::vector<std::string>& items);
    static void Tree(const std::string& root,
                     const std::map<std::string, std::vector<std::string>>& structure);
};

} // namespace Docs
