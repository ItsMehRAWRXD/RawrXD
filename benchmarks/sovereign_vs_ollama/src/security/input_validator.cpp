// input_validator.cpp
// Batch 13: Input Validation and Sanitization
//
// Validates and sanitizes all user inputs to prevent injection attacks
// Features: Schema validation, type checking, bounds checking, sanitization

#include <string>
#include <vector>
#include <map>
#include <regex>
#include <optional>
#include <functional>
#include <algorithm>
#include <cctype>

namespace Benchmark {
namespace Security {

// Validation result
struct ValidationResult {
    bool valid;
    std::string field;
    std::string error_message;
    std::string sanitized_value;
    
    static ValidationResult Success(const std::string& value = "") {
        return {true, "", "", value};
    }
    
    static ValidationResult Failure(const std::string& field, const std::string& message) {
        return {false, field, message, ""};
    }
};

// Validation rule types
enum class ValidationType {
    REQUIRED,
    STRING,
    INTEGER,
    FLOAT,
    BOOLEAN,
    EMAIL,
    URL,
    UUID,
    PATH,
    COMMAND,
    JSON,
    REGEX,
    LENGTH,
    RANGE,
    ENUM,
    CUSTOM
};

// Validation rule
struct ValidationRule {
    ValidationType type;
    std::string field_name;
    std::optional<std::string> pattern;
    std::optional<int> min_length;
    std::optional<int> max_length;
    std::optional<double> min_value;
    std::optional<double> max_value;
    std::vector<std::string> allowed_values;
    std::function<ValidationResult(const std::string&)> custom_validator;
    bool sanitize = true;
};

// Input validator
class InputValidator {
public:
    // Validate single value
    static ValidationResult Validate(const std::string& value,
                                      const ValidationRule& rule) {
        // Check required
        if (rule.type == ValidationType::REQUIRED && value.empty()) {
            return ValidationResult::Failure(rule.field_name, 
                "Field is required");
        }
        
        if (value.empty()) {
            return ValidationResult::Success(value);
        }
        
        std::string sanitized = value;
        
        // Apply type-specific validation
        switch (rule.type) {
            case ValidationType::STRING:
                return ValidateString(sanitized, rule);
            case ValidationType::INTEGER:
                return ValidateInteger(sanitized, rule);
            case ValidationType::FLOAT:
                return ValidateFloat(sanitized, rule);
            case ValidationType::EMAIL:
                return ValidateEmail(sanitized, rule);
            case ValidationType::URL:
                return ValidateURL(sanitized, rule);
            case ValidationType::UUID:
                return ValidateUUID(sanitized, rule);
            case ValidationType::PATH:
                return ValidatePath(sanitized, rule);
            case ValidationType::COMMAND:
                return ValidateCommand(sanitized, rule);
            case ValidationType::JSON:
                return ValidateJSON(sanitized, rule);
            case ValidationType::REGEX:
                return ValidateRegex(sanitized, rule);
            default:
                break;
        }
        
        // Apply length validation
        if (rule.min_length.has_value() && 
            static_cast<int>(sanitized.length()) < rule.min_length.value()) {
            return ValidationResult::Failure(rule.field_name,
                "Value too short (min " + std::to_string(rule.min_length.value()) + ")");
        }
        
        if (rule.max_length.has_value() && 
            static_cast<int>(sanitized.length()) > rule.max_length.value()) {
            return ValidationResult::Failure(rule.field_name,
                "Value too long (max " + std::to_string(rule.max_length.value()) + ")");
        }
        
        // Apply enum validation
        if (!rule.allowed_values.empty()) {
            auto it = std::find(rule.allowed_values.begin(), 
                               rule.allowed_values.end(), sanitized);
            if (it == rule.allowed_values.end()) {
                return ValidationResult::Failure(rule.field_name,
                    "Value not in allowed set");
            }
        }
        
        // Apply custom validator
        if (rule.custom_validator) {
            return rule.custom_validator(sanitized);
        }
        
        // Sanitize if requested
        if (rule.sanitize) {
            sanitized = Sanitize(sanitized);
        }
        
        auto result = ValidationResult::Success();
        result.sanitized_value = sanitized;
        return result;
    }
    
    // Validate multiple fields
    static std::vector<ValidationResult> ValidateBatch(
        const std::map<std::string, std::string>& fields,
        const std::vector<ValidationRule>& rules) {
        
        std::vector<ValidationResult> results;
        
        for (const auto& rule : rules) {
            auto it = fields.find(rule.field_name);
            std::string value = (it != fields.end()) ? it->second : "";
            
            results.push_back(Validate(value, rule));
        }
        
        return results;
    }
    
    // Check if all validations passed
    static bool AllValid(const std::vector<ValidationResult>& results) {
        for (const auto& result : results) {
            if (!result.valid) return false;
        }
        return true;
    }
    
    // Get first error message
    static std::optional<std::string> GetFirstError(
        const std::vector<ValidationResult>& results) {
        for (const auto& result : results) {
            if (!result.valid) {
                return result.field + ": " + result.error_message;
            }
        }
        return std::nullopt;
    }

private:
    static ValidationResult ValidateString(const std::string& value,
                                           const ValidationRule& rule) {
        // Check for null bytes
        if (value.find('\0') != std::string::npos) {
            return ValidationResult::Failure(rule.field_name,
                "String contains null bytes");
        }
        
        // Check for control characters (except common whitespace)
        for (char c : value) {
            if (std::iscntrl(c) && c != '\t' && c != '\n' && c != '\r') {
                return ValidationResult::Failure(rule.field_name,
                    "String contains invalid control characters");
            }
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidateInteger(const std::string& value,
                                           const ValidationRule& rule) {
        // Check format
        std::regex int_regex("^-?\\d+$");
        if (!std::regex_match(value, int_regex)) {
            return ValidationResult::Failure(rule.field_name,
                "Invalid integer format");
        }
        
        // Check range
        try {
            long long num = std::stoll(value);
            
            if (rule.min_value.has_value() && num < rule.min_value.value()) {
                return ValidationResult::Failure(rule.field_name,
                    "Value below minimum");
            }
            
            if (rule.max_value.has_value() && num > rule.max_value.value()) {
                return ValidationResult::Failure(rule.field_name,
                    "Value above maximum");
            }
        } catch (...) {
            return ValidationResult::Failure(rule.field_name,
                "Integer overflow");
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidateFloat(const std::string& value,
                                         const ValidationRule& rule) {
        std::regex float_regex("^-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?$");
        if (!std::regex_match(value, float_regex)) {
            return ValidationResult::Failure(rule.field_name,
                "Invalid float format");
        }
        
        try {
            double num = std::stod(value);
            
            if (rule.min_value.has_value() && num < rule.min_value.value()) {
                return ValidationResult::Failure(rule.field_name,
                    "Value below minimum");
            }
            
            if (rule.max_value.has_value() && num > rule.max_value.value()) {
                return ValidationResult::Failure(rule.field_name,
                    "Value above maximum");
            }
        } catch (...) {
            return ValidationResult::Failure(rule.field_name,
                "Float overflow");
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidateEmail(const std::string& value,
                                         const ValidationRule& rule) {
        // RFC 5322 simplified pattern
        std::regex email_regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        if (!std::regex_match(value, email_regex)) {
            return ValidationResult::Failure(rule.field_name,
                "Invalid email format");
        }
        
        // Check length
        if (value.length() > 254) {
            return ValidationResult::Failure(rule.field_name,
                "Email too long");
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidateURL(const std::string& value,
                                       const ValidationRule& rule) {
        // Basic URL validation
        std::regex url_regex("^(https?|ftp)://[\\w\\-]+(\\.[\\w\\-]+)+[\\w\\-._~:/?#[\\]@!$&'()*+,;=]*$");
        if (!std::regex_match(value, url_regex)) {
            return ValidationResult::Failure(rule.field_name,
                "Invalid URL format");
        }
        
        // Check for dangerous schemes
        std::vector<std::string> dangerous_schemes = {
            "javascript:", "data:", "vbscript:", "file:", "about:"
        };
        
        std::string lower = value;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        for (const auto& scheme : dangerous_schemes) {
            if (lower.find(scheme) == 0) {
                return ValidationResult::Failure(rule.field_name,
                    "Dangerous URL scheme detected");
            }
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidateUUID(const std::string& value,
                                        const ValidationRule& rule) {
        std::regex uuid_regex(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
        
        if (!std::regex_match(value, uuid_regex)) {
            return ValidationResult::Failure(rule.field_name,
                "Invalid UUID format");
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidatePath(const std::string& value,
                                        const ValidationRule& rule) {
        // Check for path traversal
        if (value.find("..") != std::string::npos ||
            value.find("~") != std::string::npos) {
            return ValidationResult::Failure(rule.field_name,
                "Path traversal detected");
        }
        
        // Check for null bytes
        if (value.find('\0') != std::string::npos) {
            return ValidationResult::Failure(rule.field_name,
                "Null byte in path");
        }
        
        // Normalize path
        std::string normalized = NormalizePath(value);
        
        auto result = ValidationResult::Success();
        result.sanitized_value = normalized;
        return result;
    }
    
    static ValidationResult ValidateCommand(const std::string& value,
                                           const ValidationRule& rule) {
        // Check for shell metacharacters
        std::string dangerous = ";|&$`<>\\\"'";
        for (char c : value) {
            if (dangerous.find(c) != std::string::npos) {
                return ValidationResult::Failure(rule.field_name,
                    "Command contains dangerous characters");
            }
        }
        
        // Check for newlines
        if (value.find('\n') != std::string::npos ||
            value.find('\r') != std::string::npos) {
            return ValidationResult::Failure(rule.field_name,
                "Command contains newlines");
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidateJSON(const std::string& value,
                                        const ValidationRule& rule) {
        // Basic JSON validation - check braces balance
        int brace_count = 0;
        bool in_string = false;
        bool escaped = false;
        
        for (char c : value) {
            if (escaped) {
                escaped = false;
                continue;
            }
            
            if (c == '\\') {
                escaped = true;
                continue;
            }
            
            if (c == '"' && !escaped) {
                in_string = !in_string;
                continue;
            }
            
            if (!in_string) {
                if (c == '{') brace_count++;
                else if (c == '}') brace_count--;
                
                if (brace_count < 0) {
                    return ValidationResult::Failure(rule.field_name,
                        "Invalid JSON: unbalanced braces");
                }
            }
        }
        
        if (brace_count != 0) {
            return ValidationResult::Failure(rule.field_name,
                "Invalid JSON: unbalanced braces");
        }
        
        return ValidationResult::Success(value);
    }
    
    static ValidationResult ValidateRegex(const std::string& value,
                                         const ValidationRule& rule) {
        if (!rule.pattern.has_value()) {
            return ValidationResult::Failure(rule.field_name,
                "No pattern specified");
        }
        
        try {
            std::regex re(rule.pattern.value());
            if (!std::regex_match(value, re)) {
                return ValidationResult::Failure(rule.field_name,
                    "Value does not match required pattern");
            }
        } catch (const std::regex_error& e) {
            return ValidationResult::Failure(rule.field_name,
                "Invalid regex pattern");
        }
        
        return ValidationResult::Success(value);
    }
    
    static std::string Sanitize(const std::string& value) {
        std::string result;
        result.reserve(value.length());
        
        for (char c : value) {
            // Escape HTML special characters
            switch (c) {
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '&': result += "&amp;"; break;
                case '"': result += "&quot;"; break;
                case '\'': result += "&#x27;"; break;
                default:
                    if (!std::iscntrl(c) || c == '\t' || c == '\n' || c == '\r') {
                        result += c;
                    }
                    break;
            }
        }
        
        return result;
    }
    
    static std::string NormalizePath(const std::string& path) {
        std::string result;
        std::vector<std::string> components;
        
        // Split by separator
        size_t start = 0;
        size_t end = path.find('/');
        
        while (end != std::string::npos) {
            std::string component = path.substr(start, end - start);
            if (!component.empty() && component != ".") {
                if (component == "..") {
                    if (!components.empty()) {
                        components.pop_back();
                    }
                } else {
                    components.push_back(component);
                }
            }
            start = end + 1;
            end = path.find('/', start);
        }
        
        // Add last component
        std::string last = path.substr(start);
        if (!last.empty() && last != ".") {
            if (last == "..") {
                if (!components.empty()) {
                    components.pop_back();
                }
            } else {
                components.push_back(last);
            }
        }
        
        // Reconstruct path
        for (size_t i = 0; i < components.size(); ++i) {
            if (i > 0) result += "/";
            result += components[i];
        }
        
        return result;
    }
};

// Predefined validation schemas
class ValidationSchemas {
public:
    static std::vector<ValidationRule> BenchmarkRequest() {
        return {
            {ValidationType::REQUIRED, "benchmark_id", {}, {}, {}, {}, {}, {}, false},
            {ValidationType::STRING, "model", {}, {1}, {256}, {}, {}, {}, true},
            {ValidationType::INTEGER, "max_tokens", {}, {}, {}, {1}, {8192}, {}, false},
            {ValidationType::FLOAT, "temperature", {}, {}, {}, {0.0}, {2.0}, {}, false},
            {ValidationType::INTEGER, "iterations", {}, {}, {}, {1}, {1000}, {}, false},
            {ValidationType::STRING, "backend", {}, {1}, {64}, {}, {}, 
             {"sovereign", "ollama", "openai", "anthropic", "local_gguf", "vllm"}, {}, true}
        };
    }
    
    static std::vector<ValidationRule> ComparisonRequest() {
        return {
            {ValidationType::REQUIRED, "baseline_id", {}, {}, {}, {}, {}, {}, false},
            {ValidationType::REQUIRED, "current_id", {}, {}, {}, {}, {}, {}, false},
            {ValidationType::STRING, "metric", {}, {}, {}, {}, {}, 
             {"tps", "latency", "ttft", "memory", "all"}, {}, true}
        };
    }
    
    static std::vector<ValidationRule> APIKeyRequest() {
        return {
            {ValidationType::REQUIRED, "api_key", {}, {32}, {256}, {}, {}, {}, false},
            {ValidationType::STRING, "backend", {}, {}, {}, {}, {}, 
             {"openai", "anthropic", "azure"}, {}, true}
        };
    }
};

} // namespace Security
} // namespace Benchmark
