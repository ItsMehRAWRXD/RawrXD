/**
 * RawrXD Tool Calling Example
 *
 * Demonstrates how to implement and register custom tools
 * that can be called by the agentic framework.
 */

#include <rawrxd/RawrXD.hpp>
#include <rawrxd/agentic/ToolRegistry.hpp>
#include <iostream>
#include <memory>

using namespace rawrxd;

// Calculator Tool - performs mathematical operations
class CalculatorTool : public ITool {
public:
    std::string GetName() const override { return "calculator"; }
    std::string GetDescription() const override {
        return "Perform mathematical calculations. Supports: add, subtract, multiply, divide";
    }

    ToolSchema GetSchema() const override {
        ToolSchema schema;
        schema.name = "calculator";
        schema.description = "Perform mathematical calculations";
        schema.parameters = {
            {"operation", "string", true, "add, subtract, multiply, or divide"},
            {"a", "number", true, "First operand"},
            {"b", "number", true, "Second operand"}
        };
        return schema;
    }

    Result<std::string> Execute(const ToolArgs& args) override {
        auto operation = args.GetString("operation");
        auto a = args.GetDouble("a");
        auto b = args.GetDouble("b");

        if (!operation.IsOk() || !a.IsOk() || !b.IsOk()) {
            return Err<std::string>(ErrorCode::InvalidArgument, "Missing required parameters");
        }

        double result = 0.0;
        std::string op = operation.Value();

        if (op == "add") {
            result = a.Value() + b.Value();
        } else if (op == "subtract") {
            result = a.Value() - b.Value();
        } else if (op == "multiply") {
            result = a.Value() * b.Value();
        } else if (op == "divide") {
            if (b.Value() == 0) {
                return Err<std::string>(ErrorCode::InvalidArgument, "Division by zero");
            }
            result = a.Value() / b.Value();
        } else {
            return Err<std::string>(ErrorCode::InvalidArgument, "Unknown operation: " + op);
        }

        return Ok(std::to_string(result));
    }
};

// Weather Tool - simulates weather lookup
class WeatherTool : public ITool {
public:
    std::string GetName() const override { return "weather"; }
    std::string GetDescription() const override {
        return "Get current weather for a location";
    }

    ToolSchema GetSchema() const override {
        ToolSchema schema;
        schema.name = "weather";
        schema.description = "Get current weather";
        schema.parameters = {
            {"location", "string", true, "City name or coordinates"},
            {"units", "string", false, "metric or imperial (default: metric)"}
        };
        return schema;
    }

    Result<std::string> Execute(const ToolArgs& args) override {
        auto location = args.GetString("location");
        if (!location.IsOk()) {
            return Err<std::string>(ErrorCode::InvalidArgument, "Location required");
        }

        // Simulate weather lookup (in real implementation, call weather API)
        std::string loc = location.Value();
        std::string response = "Weather in " + loc + ": 22°C, Partly Cloudy, Wind 15 km/h";

        return Ok(response);
    }
};

// File System Tool - file operations
class FileSystemTool : public ITool {
public:
    std::string GetName() const override { return "filesystem"; }
    std::string GetDescription() const override {
        return "Perform file system operations: read, write, list, delete";
    }

    ToolSchema GetSchema() const override {
        ToolSchema schema;
        schema.name = "filesystem";
        schema.description = "File system operations";
        schema.parameters = {
            {"operation", "string", true, "read, write, list, or delete"},
            {"path", "string", true, "File or directory path"},
            {"content", "string", false, "Content for write operation"}
        };
        return schema;
    }

    Result<std::string> Execute(const ToolArgs& args) override {
        auto operation = args.GetString("operation");
        auto path = args.GetString("path");

        if (!operation.IsOk() || !path.IsOk()) {
            return Err<std::string>(ErrorCode::InvalidArgument, "Missing required parameters");
        }

        std::string op = operation.Value();
        std::string p = path.Value();

        // Note: In production, add path validation and sandboxing
        if (op == "read") {
            // Simulate file read
            return Ok("Contents of " + p + ": [File contents would appear here]");
        } else if (op == "write") {
            auto content = args.GetString("content");
            if (!content.IsOk()) {
                return Err<std::string>(ErrorCode::InvalidArgument, "Content required for write");
            }
            return Ok("Wrote " + std::to_string(content.Value().length()) + " bytes to " + p);
        } else if (op == "list") {
            return Ok("Directory listing for " + p + ":\n- file1.txt\n- file2.txt\n- subdir/");
        } else if (op == "delete") {
            return Ok("Deleted " + p);
        }

        return Err<std::string>(ErrorCode::InvalidArgument, "Unknown operation: " + op);
    }
};

int main() {
    std::cout << "RawrXD Tool Calling Example\n";
    std::cout << "===========================\n\n";

    // Initialize runtime
    auto runtime = Runtime::Create();
    if (!runtime->Initialize()) {
        std::cerr << "Failed to initialize runtime\n";
        return 1;
    }

    std::cout << "✓ Runtime initialized\n\n";

    // Get tool registry
    auto toolRegistry = runtime->GetToolRegistry();
    if (!toolRegistry) {
        std::cerr << "Tool registry not available\n";
        return 1;
    }

    // Register tools
    std::cout << "Registering tools...\n";

    toolRegistry->Register(std::make_unique<CalculatorTool>());
    std::cout << "  ✓ calculator\n";

    toolRegistry->Register(std::make_unique<WeatherTool>());
    std::cout << "  ✓ weather\n";

    toolRegistry->Register(std::make_unique<FileSystemTool>());
    std::cout << "  ✓ filesystem\n\n";

    // List registered tools
    std::cout << "Registered Tools:\n";
    std::cout << "-----------------\n";
    auto tools = toolRegistry->ListTools();
    for (const auto& tool : tools) {
        std::cout << "  " << tool.name << ": " << tool.description << "\n";
    }
    std::cout << "\n";

    // Demonstrate tool calls
    std::cout << "Tool Call Examples:\n";
    std::cout << "------------------\n";

    // Example 1: Calculator
    {
        std::cout << "\n1. Calculator (add 5 + 3):\n";
        ToolArgs args;
        args.SetString("operation", "add");
        args.SetDouble("a", 5.0);
        args.SetDouble("b", 3.0);

        auto result = toolRegistry->Call("calculator", args);
        if (result.IsOk()) {
            std::cout << "   Result: " << result.Value() << "\n";
        } else {
            std::cout << "   Error: " << result.Error().message << "\n";
        }
    }

    // Example 2: Weather
    {
        std::cout << "\n2. Weather (San Francisco):\n";
        ToolArgs args;
        args.SetString("location", "San Francisco");

        auto result = toolRegistry->Call("weather", args);
        if (result.IsOk()) {
            std::cout << "   " << result.Value() << "\n";
        } else {
            std::cout << "   Error: " << result.Error().message << "\n";
        }
    }

    // Example 3: File System
    {
        std::cout << "\n3. File System (list /tmp):\n";
        ToolArgs args;
        args.SetString("operation", "list");
        args.SetString("path", "/tmp");

        auto result = toolRegistry->Call("filesystem", args);
        if (result.IsOk()) {
            std::cout << "   " << result.Value() << "\n";
        } else {
            std::cout << "   Error: " << result.Error().message << "\n";
        }
    }

    // Example 4: Error handling
    {
        std::cout << "\n4. Error Handling (divide by zero):\n";
        ToolArgs args;
        args.SetString("operation", "divide");
        args.SetDouble("a", 10.0);
        args.SetDouble("b", 0.0);

        auto result = toolRegistry->Call("calculator", args);
        if (result.IsOk()) {
            std::cout << "   Result: " << result.Value() << "\n";
        } else {
            std::cout << "   Error (expected): " << result.Error().message << "\n";
        }
    }

    std::cout << "\n✓ Tool calling example complete\n";

    // Cleanup
    runtime->Shutdown();
    return 0;
}