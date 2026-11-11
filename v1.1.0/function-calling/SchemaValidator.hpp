// RawrXD Sovereign v1.1.0 - Function Calling Framework
// SchemaValidator.hpp - JSON schema validation for tool arguments

#pragma once

#include "ToolRegistry.hpp"
#include <regex>
#include <variant>
#include <optional>

namespace RawrXD {
namespace FunctionCalling {

// Schema types
enum class SchemaType {
    STRING,
    INTEGER,
    NUMBER,
    BOOLEAN,
    ARRAY,
    OBJECT,
    NULL_TYPE
};

// Schema property definition
struct SchemaProperty {
    std::string name;
    SchemaType type;
    std::string description;
    bool required;
    std::optional<json> default_value;
    std::optional<json> enum_values;
    std::optional<std::string> pattern;
    std::optional<int> min_length;
    std::optional<int> max_length;
    std::optional<double> minimum;
    std::optional<double> maximum;
    std::optional<int> min_items;
    std::optional<int> max_items;
    std::optional<SchemaProperty> items;  // For array types
    std::vector<SchemaProperty> properties;  // For object types
    
    SchemaProperty() : type(SchemaType::STRING), required(false) {}
    
    SchemaProperty(const std::string& n, SchemaType t, bool req = false)
        : name(n), type(t), required(req) {}
};

// Validation error
struct ValidationError {
    std::string path;
    std::string message;
    std::string code;
    json value;
    
    ValidationError() = default;
    ValidationError(const std::string& p, const std::string& m, 
                    const std::string& c, const json& v = nullptr)
        : path(p), message(m), code(c), value(v) {}
};

// Validation result
struct ValidationResult {
    bool valid;
    std::vector<ValidationError> errors;
    json sanitized_value;
    
    ValidationResult() : valid(true) {}
    
    static ValidationResult Success(const json& sanitized) {
        ValidationResult r;
        r.valid = true;
        r.sanitized_value = sanitized;
        return r;
    }
    
    static ValidationResult Failure(const std::vector<ValidationError>& errs) {
        ValidationResult r;
        r.valid = false;
        r.errors = errs;
        return r;
    }
    
    void AddError(const ValidationError& error) {
        valid = false;
        errors.push_back(error);
    }
    
    std::string GetErrorMessage() const {
        if (valid) return "";
        std::string msg;
        for (const auto& err : errors) {
            if (!msg.empty()) msg += "; ";
            msg += err.path + ": " + err.message;
        }
        return msg;
    }
};

// Schema definition for a tool
struct ToolSchema {
    std::string tool_name;
    std::string description;
    std::vector<SchemaProperty> parameters;
    std::vector<std::string> required_parameters;
    bool additional_properties;
    
    ToolSchema() : additional_properties(false) {}
    
    json ToJSON() const;
    static ToolSchema FromJSON(const json& j);
    static ToolSchema FromToolDefinition(const ToolDefinition& def);
};

// SchemaValidator class
class SchemaValidator {
public:
    SchemaValidator();
    ~SchemaValidator();

    // Schema registration
    void RegisterSchema(const ToolSchema& schema);
    void RegisterSchema(const ToolDefinition& def);
    bool UnregisterSchema(const std::string& tool_name);
    bool HasSchema(const std::string& tool_name) const;
    std::optional<ToolSchema> GetSchema(const std::string& tool_name) const;

    // Validation
    ValidationResult Validate(const std::string& tool_name, const json& arguments);
    ValidationResult Validate(const ToolSchema& schema, const json& arguments);
    
    // Type validation
    bool ValidateType(const json& value, SchemaType expected);
    SchemaType DetectType(const json& value) const;

    // Sanitization
    json SanitizeValue(const json& value, const SchemaProperty& prop);
    json SanitizeArguments(const json& arguments, const ToolSchema& schema);

    // Schema generation helpers
    static SchemaProperty MakeStringProperty(const std::string& name, 
                                              bool required = false,
                                              const std::string& pattern = "",
                                              int min_len = 0, 
                                              int max_len = 0);
    static SchemaProperty MakeIntegerProperty(const std::string& name,
                                               bool required = false,
                                               int min_val = 0,
                                               int max_val = 0);
    static SchemaProperty MakeNumberProperty(const std::string& name,
                                              bool required = false,
                                              double min_val = 0.0,
                                              double max_val = 0.0);
    static SchemaProperty MakeBooleanProperty(const std::string& name,
                                               bool required = false);
    static SchemaProperty MakeArrayProperty(const std::string& name,
                                             bool required = false,
                                             const SchemaProperty& items = SchemaProperty(),
                                             int min_items = 0,
                                             int max_items = 0);
    static SchemaProperty MakeObjectProperty(const std::string& name,
                                              bool required = false,
                                              const std::vector<SchemaProperty>& props = {},
                                              bool additional = false);

    // OpenAI compatibility
    json GenerateOpenAISchema(const std::string& tool_name) const;
    json GenerateOpenAIFunctionsList() const;

    // Validation statistics
    size_t GetTotalValidations() const;
    size_t GetSuccessfulValidations() const;
    size_t GetFailedValidations() const;
    void ResetStatistics();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    // Internal validation methods
    ValidationResult ValidateProperty(const json& value, 
                                       const SchemaProperty& prop,
                                       const std::string& path);
    ValidationResult ValidateString(const json& value,
                                       const SchemaProperty& prop,
                                       const std::string& path);
    ValidationResult ValidateNumber(const json& value,
                                       const SchemaProperty& prop,
                                       const std::string& path,
                                       bool is_integer);
    ValidationResult ValidateArray(const json& value,
                                      const SchemaProperty& prop,
                                      const std::string& path);
    ValidationResult ValidateObject(const json& value,
                                       const SchemaProperty& prop,
                                       const std::string& path);
};

// Common validation patterns
namespace ValidationPatterns {
    // File paths
    static const std::string SAFE_FILE_PATH = R"(^[a-zA-Z0-9_\-\.\/\\]+$)";
    static const std::string ABSOLUTE_PATH = R"(^([a-zA-Z]:)?[\\/].*$)";
    
    // Identifiers
    static const std::string IDENTIFIER = R"(^[a-zA-Z_][a-zA-Z0-9_]*$)";
    static const std::string NAMESPACE = R"(^[a-zA-Z_][a-zA-Z0-9_]*(::[a-zA-Z_][a-zA-Z0-9_]*)*$)";
    
    // URLs
    static const std::string HTTP_URL = R"(^https?://.+$)";
    static const std::string FILE_URL = R"(^file://.+$)";
    
    // Version strings
    static const std::string SEMVER = R"(^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$)";
    
    // Command validation
    static const std::string SAFE_COMMAND = R"(^[a-zA-Z0-9_\-\.\s\/\\]+$)";
}

// Predefined schemas for common types
namespace CommonSchemas {
    ToolSchema FileReadSchema();
    ToolSchema FileWriteSchema();
    ToolSchema ExecuteCommandSchema();
    ToolSchema CompileCodeSchema();
    ToolSchema SearchFilesSchema();
}

// Validation utilities
namespace ValidationUtils {
    bool IsValidFilePath(const std::string& path);
    bool IsValidIdentifier(const std::string& id);
    bool IsValidURL(const std::string& url);
    bool IsDangerousPattern(const std::string& value);
    std::string EscapeString(const std::string& input);
    std::string UnescapeString(const std::string& input);
}

} // namespace FunctionCalling
} // namespace RawrXD
