// MyPlugin.hpp
// Example custom plugin for RawrXD

#pragma once
#include <rawrxd/developer/PluginSDK.hpp>
#include <iostream>

class MyPlugin : public RawrXD::Developer::IPlugin {
public:
    MyPlugin() = default;
    ~MyPlugin() override = default;

    bool Initialize(const RawrXD::Developer::PluginContext& context) override {
        context_ = context;
        context.log_callback("INFO", "MyPlugin initialized successfully");
        return true;
    }

    void Shutdown() override {
        if (context_.log_callback) {
            context_.log_callback("INFO", "MyPlugin shutting down");
        }
    }

    RawrXD::Developer::PluginManifest GetManifest() const override {
        return {
            "com.example.myplugin",
            "My Custom Plugin",
            "1.0.0",
            "A sample plugin demonstrating RawrXD plugin development",
            "Example Author",
            "MIT",
            "https://example.com/myplugin",
            "https://github.com/example/myplugin",
            RawrXD::Developer::PLUGIN_API_VERSION,
            {"1.0.0"},
            {RawrXD::Developer::PluginCapability::TOOL_PROVIDER}
        };
    }

    std::string GetStatus() const override {
        return "Running - " + std::to_string(tools_provided_) + " tools active";
    }

    std::vector<RawrXD::Developer::ToolDefinition> GetTools() override {
        tools_provided_ = 2;
        return {
            CreateEchoTool(),
            CreateCalculateTool()
        };
    }

private:
    RawrXD::Developer::PluginContext context_;
    mutable size_t tools_provided_ = 0;

    RawrXD::Developer::ToolDefinition CreateEchoTool() {
        return {
            "myplugin_echo",
            "Echoes back the input text with optional formatting",
            "Utility",
            R"({
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to echo"},
                    "uppercase": {"type": "boolean", "description": "Convert to uppercase"},
                    "prefix": {"type": "string", "description": "Prefix to add"}
                },
                "required": ["text"]
            })",
            R"({"type": "string"})",
            [this](const std::string& input_json) -> std::string {
                // Simple JSON parsing (in production, use a proper JSON library)
                std::string text = ExtractValue(input_json, "text");
                bool uppercase = ExtractBool(input_json, "uppercase");
                std::string prefix = ExtractValue(input_json, "prefix");
                
                std::string result = prefix + text;
                if (uppercase) {
                    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
                }
                
                return "{\"result\": \"" + result + "\"}";
            },
            std::chrono::seconds(5),
            false,
            false,
            {}
        };
    }

    RawrXD::Developer::ToolDefinition CreateCalculateTool() {
        return {
            "myplugin_calculate",
            "Performs basic mathematical calculations",
            "Math",
            R"({
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "Mathematical expression"},
                    "precision": {"type": "integer", "description": "Decimal precision", "default": 2}
                },
                "required": ["expression"]
            })",
            R"({"type": "number"})",
            [this](const std::string& input_json) -> std::string {
                std::string expression = ExtractValue(input_json, "expression");
                int precision = ExtractInt(input_json, "precision", 2);
                
                // Simple calculation (in production, use a proper expression parser)
                double result = EvaluateExpression(expression);
                
                std::ostringstream oss;
                oss << std::fixed << std::setprecision(precision) << result;
                return "{\"result\": " + oss.str() + "}";
            },
            std::chrono::seconds(10),
            false,
            false,
            {}
        };
    }

    // Helper functions for simple JSON extraction
    std::string ExtractValue(const std::string& json, const std::string& key) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        
        pos = json.find("\"", pos);
        if (pos == std::string::npos) return "";
        
        size_t end = json.find("\"", pos + 1);
        if (end == std::string::npos) return "";
        
        return json.substr(pos + 1, end - pos - 1);
    }

    bool ExtractBool(const std::string& json, const std::string& key) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return false;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return false;
        
        // Skip whitespace
        pos++;
        while (pos < json.size() && std::isspace(json[pos])) pos++;
        
        if (pos + 4 <= json.size() && json.substr(pos, 4) == "true") return true;
        return false;
    }

    int ExtractInt(const std::string& json, const std::string& key, int default_val) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return default_val;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return default_val;
        
        // Skip whitespace
        pos++;
        while (pos < json.size() && std::isspace(json[pos])) pos++;
        
        // Extract number
        size_t end = pos;
        while (end < json.size() && (std::isdigit(json[end]) || json[end] == '-')) end++;
        
        if (end > pos) {
            try {
                return std::stoi(json.substr(pos, end - pos));
            } catch (...) {
                return default_val;
            }
        }
        return default_val;
    }

    double EvaluateExpression(const std::string& expr) {
        // Very simple evaluator - in production use a proper parser
        // This is just for demonstration
        double result = 0.0;
        double current = 0.0;
        char op = '+';
        
        std::istringstream iss(expr);
        std::string token;
        
        while (std::getline(iss, token, ' ')) {
            if (token.empty()) continue;
            
            if (token == "+" || token == "-" || token == "*" || token == "/") {
                op = token[0];
            } else {
                try {
                    current = std::stod(token);
                    switch (op) {
                        case '+': result += current; break;
                        case '-': result -= current; break;
                        case '*': result *= current; break;
                        case '/': result /= (current != 0 ? current : 1); break;
                    }
                } catch (...) {
                    // Ignore invalid tokens
                }
            }
        }
        
        return result;
    }
};

// Export the plugin
RAWRXD_DEFINE_PLUGIN(MyPlugin)
