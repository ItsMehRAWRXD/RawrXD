// Phase M.4/5: Advanced Inference Features - Function Calling
// RawrXD Function Calling - Tool use and external API integration

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <variant>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Advanced {

// JSON Schema types for function parameters
enum class SchemaType {
    STRING,
    INTEGER,
    NUMBER,
    BOOLEAN,
    ARRAY,
    OBJECT,
    NULL_TYPE
};

// JSON Schema property definition
struct SchemaProperty {
    std::string name;
    SchemaType type;
    std::string description;
    bool required = false;
    std::vector<std::string> enum_values;  // For enum types
    std::optional<double> minimum;          // For numbers
    std::optional<double> maximum;
    std::optional<int32_t> min_length;    // For strings
    std::optional<int32_t> max_length;
    std::optional<std::string> pattern;    // Regex pattern
    std::vector<SchemaProperty> properties; // For objects
    SchemaProperty* items = nullptr;       // For arrays
};

// Function definition
struct FunctionDefinition {
    std::string name;
    std::string description;
    std::vector<SchemaProperty> parameters;
    std::vector<std::string> required_params;
    bool strict = false;  // Reject extra parameters
};

// Function call result
struct FunctionResult {
    std::string function_name;
    std::string call_id;
    bool success;
    std::string result;           // JSON result
    std::string error_message;
    uint32_t execution_time_ms;
};

// Tool definition (function + metadata)
struct Tool {
    std::string type = "function";  // Currently only "function" supported
    FunctionDefinition function;
    std::optional<std::string> id;  // Tool identifier
};

// Tool call from model
struct ToolCall {
    std::string id;
    std::string type = "function";
    std::string function_name;
    std::string arguments;  // JSON string of arguments
};

// Tool choice configuration
enum class ToolChoice {
    NONE,       // Don't use tools
    AUTO,       // Let model decide
    REQUIRED    // Must use a tool
};

// Function calling configuration
struct FunctionCallingConfig {
    std::vector<Tool> tools;
    ToolChoice tool_choice = ToolChoice::AUTO;
    std::optional<std::string> specific_tool;  // If tool_choice == REQUIRED
    uint32_t max_parallel_calls = 5;
    uint32_t timeout_ms = 30000;
    bool validate_arguments = true;
    bool retry_on_failure = true;
    uint32_t max_retries = 3;
};

// Built-in tool implementations
namespace BuiltInTools {
    // Web search tool
    struct WebSearchTool {
        static FunctionDefinition GetDefinition();
        static FunctionResult Execute(const std::map<std::string, std::string>& args);
    };
    
    // Code execution tool
    struct CodeExecutionTool {
        static FunctionDefinition GetDefinition();
        static FunctionResult Execute(const std::map<std::string, std::string>& args);
        static bool IsLanguageSupported(const std::string& language);
    };
    
    // File operations tool
    struct FileOperationsTool {
        static FunctionDefinition GetDefinition();
        static FunctionResult Execute(const std::map<std::string, std::string>& args);
    };
    
    // Calculator tool
    struct CalculatorTool {
        static FunctionDefinition GetDefinition();
        static FunctionResult Execute(const std::map<std::string, std::string>& args);
    };
    
    // Date/time tool
    struct DateTimeTool {
        static FunctionDefinition GetDefinition();
        static FunctionResult Execute(const std::map<std::string, std::string>& args);
    };
}

// Function calling interface
class IFunctionCaller {
public:
    virtual ~IFunctionCaller() = default;
    
    // Initialization
    virtual bool Initialize(const FunctionCallingConfig& config) = 0;
    virtual void Shutdown() = 0;
    
    // Tool management
    virtual bool RegisterTool(const Tool& tool) = 0;
    virtual bool UnregisterTool(const std::string& name) = 0;
    virtual bool HasTool(const std::string& name) const = 0;
    virtual std::vector<Tool> GetRegisteredTools() const = 0;
    
    // Tool execution
    virtual FunctionResult ExecuteTool(const ToolCall& call) = 0;
    virtual std::vector<FunctionResult> ExecuteTools(const std::vector<ToolCall>& calls) = 0;
    
    // Argument validation
    virtual bool ValidateArguments(const std::string& function_name, 
                                   const std::string& arguments_json) = 0;
    virtual std::optional<std::string> GetValidationError(const std::string& function_name,
                                                            const std::string& arguments_json) = 0;
    
    // Parsing
    virtual std::vector<ToolCall> ParseToolCalls(const std::string& model_output) = 0;
    virtual std::string FormatToolResults(const std::vector<FunctionResult>& results) = 0;
    
    // Configuration
    virtual const FunctionCallingConfig& GetConfig() const = 0;
    virtual bool UpdateConfig(const FunctionCallingConfig& config) = 0;
    
    // Status
    virtual bool IsInitialized() const = 0;
    virtual size_t GetToolCount() const = 0;
};

// Tool registry for managing available tools
class ToolRegistry {
public:
    ToolRegistry();
    ~ToolRegistry();
    
    // Registration
    bool RegisterBuiltInTools();
    bool RegisterCustomTool(const Tool& tool, 
                             std::function<FunctionResult(const std::map<std::string, std::string>&)> handler);
    bool RegisterExternalTool(const Tool& tool, const std::string& endpoint);
    bool UnregisterTool(const std::string& name);
    
    // Query
    bool HasTool(const std::string& name) const;
    std::optional<Tool> GetTool(const std::string& name) const;
    std::vector<Tool> GetAllTools() const;
    std::vector<Tool> GetToolsByCategory(const std::string& category) const;
    
    // Execution
    FunctionResult ExecuteTool(const ToolCall& call);
    
    // Categories
    void SetToolCategory(const std::string& tool_name, const std::string& category);
    std::vector<std::string> GetCategories() const;
    
private:
    struct ToolEntry {
        Tool tool;
        std::function<FunctionResult(const std::map<std::string, std::string>&)> handler;
        std::string category;
        bool is_external;
        std::string endpoint;
    };
    
    std::map<std::string, ToolEntry> tools_;
    mutable std::mutex mutex_;
};

// Schema utilities
namespace SchemaUtils {
    // Convert SchemaType to string
    std::string TypeToString(SchemaType type);
    
    // Parse JSON schema
    std::vector<SchemaProperty> ParseSchema(const std::string& json_schema);
    
    // Validate value against schema
    bool ValidateValue(const std::string& value, const SchemaProperty& schema);
    
    // Generate JSON schema from definition
    std::string GenerateSchema(const FunctionDefinition& func);
    
    // Parse arguments JSON
    std::map<std::string, std::string> ParseArguments(const std::string& arguments_json);
    
    // Serialize result
    std::string SerializeResult(const FunctionResult& result);
}

// Function calling for chat completion
struct ChatFunctionMessage {
    std::string role;  // "assistant" or "tool"
    std::optional<ToolCall> tool_call;  // If role == "assistant"
    std::optional<FunctionResult> tool_result;  // If role == "tool"
    std::string content;  // Text content
};

// Integration with chat completion
class FunctionCallingIntegration {
public:
    // Prepare messages with tool definitions for model
    static std::string PrepareSystemPrompt(const std::vector<Tool>& tools);
    
    // Extract tool calls from model response
    static std::vector<ToolCall> ExtractToolCalls(const std::string& response);
    
    // Build continuation prompt with tool results
    static std::string BuildContinuationPrompt(const std::vector<FunctionResult>& results);
    
    // Check if response contains tool calls
    static bool ContainsToolCalls(const std::string& response);
    
    // Format tools for different model formats
    static std::string FormatToolsOpenAI(const std::vector<Tool>& tools);
    static std::string FormatToolsAnthropic(const std::vector<Tool>& tools);
    static std::string FormatToolsGeneric(const std::vector<Tool>& tools);
};

// Safety and sandboxing
class ToolSandbox {
public:
    struct SandboxConfig {
        bool allow_network = false;
        bool allow_filesystem = false;
        bool allow_execution = false;
        std::vector<std::string> allowed_paths;
        uint32_t max_memory_mb = 512;
        uint32_t timeout_seconds = 30;
        bool log_all_calls = true;
    };
    
    ToolSandbox(const SandboxConfig& config);
    
    // Execute with sandbox restrictions
    FunctionResult ExecuteSandboxed(const std::string& tool_name,
                                     const std::map<std::string, std::string>& args);
    
    // Check if operation is allowed
    bool IsOperationAllowed(const std::string& operation) const;
    
    // Logging
    void LogToolCall(const std::string& tool_name, const std::map<std::string, std::string>& args,
                     const FunctionResult& result);
    
private:
    SandboxConfig config_;
    std::vector<std::string> call_log_;
};

// Statistics and monitoring
struct FunctionCallingStats {
    uint64_t total_calls;
    uint64_t successful_calls;
    uint64_t failed_calls;
    uint64_t validation_errors;
    
    double average_execution_time_ms;
    double success_rate;
    
    std::map<std::string, uint64_t> calls_by_tool;
    std::map<std::string, double> avg_time_by_tool;
};

// Global function calling configuration
extern FunctionCallingConfig g_function_calling_config;
extern std::unique_ptr<ToolRegistry> g_tool_registry;

// Initialize function calling subsystem
bool InitializeFunctionCalling(const FunctionCallingConfig& config);
void ShutdownFunctionCalling();
bool IsFunctionCallingEnabled();

// Get statistics
FunctionCallingStats GetFunctionCallingStats();
void ResetFunctionCallingStats();

} // namespace Advanced
} // namespace RawrXD
