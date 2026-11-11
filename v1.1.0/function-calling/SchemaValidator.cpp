// RawrXD Sovereign v1.1.0 - Function Calling Framework
// SchemaValidator.cpp - Implementation

#include "SchemaValidator.hpp"
#include <regex>
#include <sstream>

namespace RawrXD {
namespace FunctionCalling {

// SchemaValidator::Impl
class SchemaValidator::Impl {
public:
    std::map<std::string, ToolSchema> schemas_;
    mutable std::mutex mutex_;
    std::atomic<size_t> total_validations_{0};
    std::atomic<size_t> successful_validations_{0};
    std::atomic<size_t> failed_validations_{0};
};

SchemaValidator::SchemaValidator() : pImpl(std::make_unique<Impl>()) {}
SchemaValidator::~SchemaValidator() = default;

void SchemaValidator::RegisterSchema(const ToolSchema& schema) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->schemas_[schema.tool_name] = schema;
}

void SchemaValidator::RegisterSchema(const ToolDefinition& def) {
    RegisterSchema(ToolSchema::FromToolDefinition(def));
}

bool SchemaValidator::UnregisterSchema(const std::string& tool_name) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->schemas_.find(tool_name);
    if (it == pImpl->schemas_.end()) {
        return false;
    }
    pImpl->schemas_.erase(it);
    return true;
}

bool SchemaValidator::HasSchema(const std::string& tool_name) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->schemas_.find(tool_name) != pImpl->schemas_.end();
}

std::optional<ToolSchema> SchemaValidator::GetSchema(const std::string& tool_name) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->schemas_.find(tool_name);
    if (it == pImpl->schemas_.end()) {
        return std::nullopt;
    }
    return it->second;
}

ValidationResult SchemaValidator::Validate(const std::string& tool_name, const json& arguments) {
    auto schema = GetSchema(tool_name);
    if (!schema) {
        return ValidationResult::Failure({
            ValidationError("", "Schema not found for tool: " + tool_name, "SCHEMA_NOT_FOUND")
        });
    }
    return Validate(*schema, arguments);
}

ValidationResult SchemaValidator::Validate(const ToolSchema& schema, const json& arguments) {
    pImpl->total_validations_++;
    
    ValidationResult result;
    
    // Check if arguments is an object
    if (!arguments.is_object()) {
        result.AddError(ValidationError("", "Arguments must be a JSON object", "INVALID_TYPE", arguments));
        pImpl->failed_validations_++;
        return result;
    }
    
    // Validate required parameters
    for (const auto& param : schema.parameters) {
        if (param.required && !arguments.contains(param.name)) {
            result.AddError(ValidationError(
                param.name, 
                "Required parameter missing", 
                "REQUIRED_PARAMETER_MISSING"
            ));
        }
    }
    
    // Validate each property
    for (const auto& [key, value] : arguments.items()) {
        auto it = std::find_if(schema.parameters.begin(), schema.parameters.end(),
            [&key](const SchemaProperty& p) { return p.name == key; });
        
        if (it == schema.parameters.end()) {
            // Unknown parameter
            if (!schema.additional_properties) {
                result.AddError(ValidationError(
                    key,
                    "Unknown parameter: " + key,
                    "UNKNOWN_PARAMETER",
                    value
                ));
            }
        } else {
            // Validate the property
            auto prop_result = ValidateProperty(value, *it, key);
            if (!prop_result.valid) {
                for (const auto& err : prop_result.errors) {
                    result.AddError(err);
                }
            }
        }
    }
    
    if (result.valid) {
        pImpl->successful_validations_++;
        result.sanitized_value = SanitizeArguments(arguments, schema);
    } else {
        pImpl->failed_validations_++;
    }
    
    return result;
}

bool SchemaValidator::ValidateType(const json& value, SchemaType expected) {
    switch (expected) {
        case SchemaType::STRING:
            return value.is_string();
        case SchemaType::INTEGER:
            return value.is_number_integer();
        case SchemaType::NUMBER:
            return value.is_number();
        case SchemaType::BOOLEAN:
            return value.is_boolean();
        case SchemaType::ARRAY:
            return value.is_array();
        case SchemaType::OBJECT:
            return value.is_object();
        case SchemaType::NULL_TYPE:
            return value.is_null();
    }
    return false;
}

SchemaType SchemaValidator::DetectType(const json& value) const {
    if (value.is_null()) return SchemaType::NULL_TYPE;
    if (value.is_boolean()) return SchemaType::BOOLEAN;
    if (value.is_number_integer()) return SchemaType::INTEGER;
    if (value.is_number()) return SchemaType::NUMBER;
    if (value.is_string()) return SchemaType::STRING;
    if (value.is_array()) return SchemaType::ARRAY;
    if (value.is_object()) return SchemaType::OBJECT;
    return SchemaType::NULL_TYPE;
}

json SchemaValidator::SanitizeValue(const json& value, const SchemaProperty& prop) {
    // Apply sanitization based on type
    switch (prop.type) {
        case SchemaType::STRING:
            if (value.is_string()) {
                std::string str = value.get<std::string>();
                // Apply length limits
                if (prop.max_length.has_value() && str.length() > prop.max_length.value()) {
                    str = str.substr(0, prop.max_length.value());
                }
                // Apply pattern validation
                if (prop.pattern.has_value()) {
                    std::regex pattern(prop.pattern.value());
                    if (!std::regex_match(str, pattern)) {
                        // Return empty or default
                        return prop.default_value.value_or(json(""));
                    }
                }
                return str;
            }
            return prop.default_value.value_or(json(""));
            
        case SchemaType::INTEGER:
            if (value.is_number_integer()) {
                int64_t val = value.get<int64_t>();
                if (prop.minimum.has_value()) {
                    val = std::max(val, static_cast<int64_t>(prop.minimum.value()));
                }
                if (prop.maximum.has_value()) {
                    val = std::min(val, static_cast<int64_t>(prop.maximum.value()));
                }
                return val;
            }
            return prop.default_value.value_or(json(0));
            
        case SchemaType::NUMBER:
            if (value.is_number()) {
                double val = value.get<double>();
                if (prop.minimum.has_value()) {
                    val = std::max(val, prop.minimum.value());
                }
                if (prop.maximum.has_value()) {
                    val = std::min(val, prop.maximum.value());
                }
                return val;
            }
            return prop.default_value.value_or(json(0.0));
            
        case SchemaType::BOOLEAN:
            if (value.is_boolean()) {
                return value.get<bool>();
            }
            return prop.default_value.value_or(json(false));
            
        case SchemaType::ARRAY:
            if (value.is_array()) {
                json arr = json::array();
                for (const auto& item : value) {
                    if (prop.items.has_value()) {
                        arr.push_back(SanitizeValue(item, prop.items.value()));
                    } else {
                        arr.push_back(item);
                    }
                }
                // Apply item limits
                if (prop.max_items.has_value() && arr.size() > prop.max_items.value()) {
                    json limited = json::array();
                    for (size_t i = 0; i < prop.max_items.value() && i < arr.size(); ++i) {
                        limited.push_back(arr[i]);
                    }
                    arr = limited;
                }
                return arr;
            }
            return prop.default_value.value_or(json::array());
            
        case SchemaType::OBJECT:
            if (value.is_object()) {
                return value; // Objects are passed through
            }
            return prop.default_value.value_or(json::object());
            
        case SchemaType::NULL_TYPE:
            return nullptr;
    }
    
    return value;
}

json SchemaValidator::SanitizeArguments(const json& arguments, const ToolSchema& schema) {
    json sanitized = json::object();
    
    for (const auto& prop : schema.parameters) {
        if (arguments.contains(prop.name)) {
            sanitized[prop.name] = SanitizeValue(arguments[prop.name], prop);
        } else if (prop.default_value.has_value()) {
            sanitized[prop.name] = prop.default_value.value();
        }
    }
    
    // Include additional properties if allowed
    if (schema.additional_properties) {
        for (const auto& [key, value] : arguments.items()) {
            if (!sanitized.contains(key)) {
                sanitized[key] = value;
            }
        }
    }
    
    return sanitized;
}

SchemaProperty SchemaValidator::MakeStringProperty(const std::string& name, 
                                                    bool required,
                                                    const std::string& pattern,
                                                    int min_len, 
                                                    int max_len) {
    SchemaProperty prop(name, SchemaType::STRING, required);
    if (!pattern.empty()) prop.pattern = pattern;
    if (min_len > 0) prop.min_length = min_len;
    if (max_len > 0) prop.max_length = max_len;
    return prop;
}

SchemaProperty SchemaValidator::MakeIntegerProperty(const std::string& name,
                                                     bool required,
                                                     int min_val,
                                                     int max_val) {
    SchemaProperty prop(name, SchemaType::INTEGER, required);
    if (min_val != 0) prop.minimum = min_val;
    if (max_val != 0) prop.maximum = max_val;
    return prop;
}

SchemaProperty SchemaValidator::MakeNumberProperty(const std::string& name,
                                                    bool required,
                                                    double min_val,
                                                    double max_val) {
    SchemaProperty prop(name, SchemaType::NUMBER, required);
    if (min_val != 0.0) prop.minimum = min_val;
    if (max_val != 0.0) prop.maximum = max_val;
    return prop;
}

SchemaProperty SchemaValidator::MakeBooleanProperty(const std::string& name,
                                                     bool required) {
    return SchemaProperty(name, SchemaType::BOOLEAN, required);
}

SchemaProperty SchemaValidator::MakeArrayProperty(const std::string& name,
                                                   bool required,
                                                   const SchemaProperty& items,
                                                   int min_items,
                                                   int max_items) {
    SchemaProperty prop(name, SchemaType::ARRAY, required);
    prop.items = items;
    if (min_items > 0) prop.min_items = min_items;
    if (max_items > 0) prop.max_items = max_items;
    return prop;
}

SchemaProperty SchemaValidator::MakeObjectProperty(const std::string& name,
                                                    bool required,
                                                    const std::vector<SchemaProperty>& props,
                                                    bool additional) {
    SchemaProperty prop(name, SchemaType::OBJECT, required);
    prop.properties = props;
    // Note: additional_properties is a ToolSchema property, not SchemaProperty
    return prop;
}

json SchemaValidator::GenerateOpenAISchema(const std::string& tool_name) const {
    auto schema = GetSchema(tool_name);
    if (!schema) {
        return nullptr;
    }
    return schema->ToJSON();
}

json SchemaValidator::GenerateOpenAIFunctionsList() const {
    json functions = json::array();
    
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    for (const auto& [name, schema] : pImpl->schemas_) {
        json func;
        func["type"] = "function";
        func["function"] = schema.ToJSON();
        functions.push_back(func);
    }
    
    return functions;
}

size_t SchemaValidator::GetTotalValidations() const {
    return pImpl->total_validations_.load();
}

size_t SchemaValidator::GetSuccessfulValidations() const {
    return pImpl->successful_validations_.load();
}

size_t SchemaValidator::GetFailedValidations() const {
    return pImpl->failed_validations_.load();
}

void SchemaValidator::ResetStatistics() {
    pImpl->total_validations_ = 0;
    pImpl->successful_validations_ = 0;
    pImpl->failed_validations_ = 0;
}

// Internal validation methods
ValidationResult SchemaValidator::ValidateProperty(const json& value, 
                                                    const SchemaProperty& prop,
                                                    const std::string& path) {
    ValidationResult result;
    
    // Type validation
    if (!ValidateType(value, prop.type)) {
        result.AddError(ValidationError(
            path,
            "Expected type " + std::to_string(static_cast<int>(prop.type)) + 
            " but got " + std::to_string(static_cast<int>(DetectType(value))),
            "TYPE_MISMATCH",
            value
        ));
        return result;
    }
    
    // Type-specific validation
    switch (prop.type) {
        case SchemaType::STRING:
            return ValidateString(value, prop, path);
        case SchemaType::INTEGER:
        case SchemaType::NUMBER:
            return ValidateNumber(value, prop, path, prop.type == SchemaType::INTEGER);
        case SchemaType::ARRAY:
            return ValidateArray(value, prop, path);
        case SchemaType::OBJECT:
            return ValidateObject(value, prop, path);
        default:
            return result;
    }
}

ValidationResult SchemaValidator::ValidateString(const json& value,
                                                  const SchemaProperty& prop,
                                                  const std::string& path) {
    ValidationResult result;
    std::string str = value.get<std::string>();
    
    // Length validation
    if (prop.min_length.has_value() && str.length() < prop.min_length.value()) {
        result.AddError(ValidationError(
            path,
            "String too short (min " + std::to_string(prop.min_length.value()) + ")",
            "MIN_LENGTH_VIOLATION",
            value
        ));
    }
    
    if (prop.max_length.has_value() && str.length() > prop.max_length.value()) {
        result.AddError(ValidationError(
            path,
            "String too long (max " + std::to_string(prop.max_length.value()) + ")",
            "MAX_LENGTH_VIOLATION",
            value
        ));
    }
    
    // Pattern validation
    if (prop.pattern.has_value()) {
        std::regex pattern(prop.pattern.value());
        if (!std::regex_match(str, pattern)) {
            result.AddError(ValidationError(
                path,
                "String does not match pattern",
                "PATTERN_VIOLATION",
                value
            ));
        }
    }
    
    // Enum validation
    if (prop.enum_values.has_value()) {
        bool found = false;
        for (const auto& enum_val : prop.enum_values.value()) {
            if (enum_val.get<std::string>() == str) {
                found = true;
                break;
            }
        }
        if (!found) {
            result.AddError(ValidationError(
                path,
                "Value not in enum",
                "ENUM_VIOLATION",
                value
            ));
        }
    }
    
    return result;
}

ValidationResult SchemaValidator::ValidateNumber(const json& value,
                                                  const SchemaProperty& prop,
                                                  const std::string& path,
                                                  bool is_integer) {
    ValidationResult result;
    
    double num = value.get<double>();
    
    // Range validation
    if (prop.minimum.has_value() && num < prop.minimum.value()) {
        result.AddError(ValidationError(
            path,
            "Value below minimum (" + std::to_string(prop.minimum.value()) + ")",
            "MINIMUM_VIOLATION",
            value
        ));
    }
    
    if (prop.maximum.has_value() && num > prop.maximum.value()) {
        result.AddError(ValidationError(
            path,
            "Value above maximum (" + std::to_string(prop.maximum.value()) + ")",
            "MAXIMUM_VIOLATION",
            value
        ));
    }
    
    return result;
}

ValidationResult SchemaValidator::ValidateArray(const json& value,
                                                 const SchemaProperty& prop,
                                                 const std::string& path) {
    ValidationResult result;
    
    // Item count validation
    if (prop.min_items.has_value() && value.size() < prop.min_items.value()) {
        result.AddError(ValidationError(
            path,
            "Array too small (min " + std::to_string(prop.min_items.value()) + ")",
            "MIN_ITEMS_VIOLATION",
            value
        ));
    }
    
    if (prop.max_items.has_value() && value.size() > prop.max_items.value()) {
        result.AddError(ValidationError(
            path,
            "Array too large (max " + std::to_string(prop.max_items.value()) + ")",
            "MAX_ITEMS_VIOLATION",
            value
        ));
    }
    
    // Item validation
    if (prop.items.has_value()) {
        for (size_t i = 0; i < value.size(); ++i) {
            auto item_result = ValidateProperty(value[i], prop.items.value(), 
                                                path + "[" + std::to_string(i) + "]");
            if (!item_result.valid) {
                for (const auto& err : item_result.errors) {
                    result.AddError(err);
                }
            }
        }
    }
    
    return result;
}

ValidationResult SchemaValidator::ValidateObject(const json& value,
                                                  const SchemaProperty& prop,
                                                  const std::string& path) {
    ValidationResult result;
    
    // Validate nested properties
    for (const auto& nested_prop : prop.properties) {
        if (nested_prop.required && !value.contains(nested_prop.name)) {
            result.AddError(ValidationError(
                path + "." + nested_prop.name,
                "Required property missing",
                "REQUIRED_PROPERTY_MISSING"
            ));
        } else if (value.contains(nested_prop.name)) {
            auto nested_result = ValidateProperty(value[nested_prop.name], nested_prop,
                                                  path + "." + nested_prop.name);
            if (!nested_result.valid) {
                for (const auto& err : nested_result.errors) {
                    result.AddError(err);
                }
            }
        }
    }
    
    return result;
}

// ToolSchema implementation
json ToolSchema::ToJSON() const {
    json j;
    j["name"] = tool_name;
    j["description"] = description;
    
    json params;
    params["type"] = "object";
    json properties = json::object();
    json required = json::array();
    
    for (const auto& prop : parameters) {
        json prop_json;
        prop_json["type"] = [] (SchemaType t) {
            switch (t) {
                case SchemaType::STRING: return "string";
                case SchemaType::INTEGER: return "integer";
                case SchemaType::NUMBER: return "number";
                case SchemaType::BOOLEAN: return "boolean";
                case SchemaType::ARRAY: return "array";
                case SchemaType::OBJECT: return "object";
                case SchemaType::NULL_TYPE: return "null";
            }
            return "unknown";
        }(prop.type);
        
        if (!prop.description.empty()) {
            prop_json["description"] = prop.description;
        }
        
        if (prop.default_value.has_value()) {
            prop_json["default"] = prop.default_value.value();
        }
        
        if (prop.enum_values.has_value()) {
            prop_json["enum"] = prop.enum_values.value();
        }
        
        properties[prop.name] = prop_json;
        
        if (prop.required) {
            required.push_back(prop.name);
        }
    }
    
    params["properties"] = properties;
    if (!required.empty()) {
        params["required"] = required;
    }
    params["additionalProperties"] = additional_properties;
    
    j["parameters"] = params;
    return j;
}

ToolSchema ToolSchema::FromJSON(const json& j) {
    ToolSchema schema;
    schema.tool_name = j.value("name", "");
    schema.description = j.value("description", "");
    schema.additional_properties = j.value("additionalProperties", false);
    
    if (j.contains("parameters")) {
        const auto& params = j["parameters"];
        if (params.contains("properties")) {
            for (const auto& [key, val] : params["properties"].items()) {
                SchemaProperty prop;
                prop.name = key;
                
                std::string type_str = val.value("type", "string");
                if (type_str == "string") prop.type = SchemaType::STRING;
                else if (type_str == "integer") prop.type = SchemaType::INTEGER;
                else if (type_str == "number") prop.type = SchemaType::NUMBER;
                else if (type_str == "boolean") prop.type = SchemaType::BOOLEAN;
                else if (type_str == "array") prop.type = SchemaType::ARRAY;
                else if (type_str == "object") prop.type = SchemaType::OBJECT;
                else if (type_str == "null") prop.type = SchemaType::NULL_TYPE;
                
                prop.description = val.value("description", "");
                
                if (params.contains("required")) {
                    for (const auto& req : params["required"]) {
                        if (req.get<std::string>() == key) {
                            prop.required = true;
                            break;
                        }
                    }
                }
                
                schema.parameters.push_back(prop);
            }
        }
    }
    
    return schema;
}

ToolSchema ToolSchema::FromToolDefinition(const ToolDefinition& def) {
    ToolSchema schema;
    schema.tool_name = def.name;
    schema.description = def.description;
    schema.additional_properties = false;
    
    // Parse parameters from JSON schema
    if (def.parameters_schema.contains("properties")) {
        for (const auto& [key, val] : def.parameters_schema["properties"].items()) {
            SchemaProperty prop;
            prop.name = key;
            
            std::string type_str = val.value("type", "string");
            if (type_str == "string") prop.type = SchemaType::STRING;
            else if (type_str == "integer") prop.type = SchemaType::INTEGER;
            else if (type_str == "number") prop.type = SchemaType::NUMBER;
            else if (type_str == "boolean") prop.type = SchemaType::BOOLEAN;
            else if (type_str == "array") prop.type = SchemaType::ARRAY;
            else if (type_str == "object") prop.type = SchemaType::OBJECT;
            
            prop.description = val.value("description", "");
            
            if (def.parameters_schema.contains("required")) {
                for (const auto& req : def.parameters_schema["required"]) {
                    if (req.get<std::string>() == key) {
                        prop.required = true;
                        break;
                    }
                }
            }
            
            schema.parameters.push_back(prop);
        }
    }
    
    return schema;
}

// CommonSchemas implementation
namespace CommonSchemas {

ToolSchema FileReadSchema() {
    ToolSchema schema;
    schema.tool_name = "file_read";
    schema.description = "Read file contents";
    schema.parameters = {
        SchemaValidator::MakeStringProperty("path", true),
        SchemaValidator::MakeIntegerProperty("offset", false, 0),
        SchemaValidator::MakeIntegerProperty("limit", false, 0, 1000000)
    };
    return schema;
}

ToolSchema FileWriteSchema() {
    ToolSchema schema;
    schema.tool_name = "file_write";
    schema.description = "Write to file";
    schema.parameters = {
        SchemaValidator::MakeStringProperty("path", true),
        SchemaValidator::MakeStringProperty("content", true),
        SchemaValidator::MakeBooleanProperty("append", false)
    };
    return schema;
}

ToolSchema ExecuteCommandSchema() {
    ToolSchema schema;
    schema.tool_name = "execute_command";
    schema.description = "Execute system command";
    schema.parameters = {
        SchemaValidator::MakeStringProperty("command", true),
        SchemaValidator::MakeStringProperty("working_dir", false),
        SchemaValidator::MakeIntegerProperty("timeout", false, 0, 3600)
    };
    return schema;
}

ToolSchema CompileCodeSchema() {
    ToolSchema schema;
    schema.tool_name = "compile_code";
    schema.description = "Compile source code";
    schema.parameters = {
        SchemaValidator::MakeArrayProperty("source_files", true, 
            SchemaProperty("", SchemaType::STRING)),
        SchemaValidator::MakeStringProperty("output", false),
        SchemaValidator::MakeArrayProperty("flags", false,
            SchemaProperty("", SchemaType::STRING))
    };
    return schema;
}

ToolSchema SearchFilesSchema() {
    ToolSchema schema;
    schema.tool_name = "search_files";
    schema.description = "Search files";
    schema.parameters = {
        SchemaValidator::MakeStringProperty("pattern", true),
        SchemaValidator::MakeStringProperty("directory", false),
        SchemaValidator::MakeBooleanProperty("recursive", false)
    };
    return schema;
}

} // namespace CommonSchemas

// ValidationUtils implementation
namespace ValidationUtils {

bool IsValidFilePath(const std::string& path) {
    try {
        std::filesystem::path p(path);
        return !p.empty();
    } catch (...) {
        return false;
    }
}

bool IsValidIdentifier(const std::string& id) {
    if (id.empty()) return false;
    if (!std::isalpha(id[0]) && id[0] != '_') return false;
    for (char c : id) {
        if (!std::isalnum(c) && c != '_') return false;
    }
    return true;
}

bool IsValidURL(const std::string& url) {
    std::regex url_regex(R"(^https?://[\w\-\.]+(:\d+)?(/[\w\-\./?%&=]*)?$)");
    return std::regex_match(url, url_regex);
}

bool IsDangerousPattern(const std::string& value) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    std::vector<std::string> dangerous = {
        "<script", "javascript:", "onerror=", "onload=",
        "eval(", "exec(", "system(", "shell_exec",
        "${", "{{", "{%", "<%"
    };
    
    for (const auto& d : dangerous) {
        if (lower.find(d) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string EscapeString(const std::string& input) {
    std::string output;
    for (char c : input) {
        switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    output += c;
                } else {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    output += buf;
                }
        }
    }
    return output;
}

std::string UnescapeString(const std::string& input) {
    std::string output;
    for (size_t i = 0; i < input.length(); ++i) {
        if (input[i] == '\\' && i + 1 < input.length()) {
            switch (input[i + 1]) {
                case '"': output += '"'; ++i; break;
                case '\\': output += '\\'; ++i; break;
                case 'b': output += '\b'; ++i; break;
                case 'f': output += '\f'; ++i; break;
                case 'n': output += '\n'; ++i; break;
                case 'r': output += '\r'; ++i; break;
                case 't': output += '\t'; ++i; break;
                case 'u':
                    if (i + 5 < input.length()) {
                        std::string hex = input.substr(i + 2, 4);
                        char* end;
                        unsigned int code = std::strtoul(hex.c_str(), &end, 16);
                        if (*end == '\0') {
                            output += static_cast<char>(code);
                            i += 5;
                        } else {
                            output += input[i];
                        }
                    } else {
                        output += input[i];
                    }
                    break;
                default:
                    output += input[i];
            }
        } else {
            output += input[i];
        }
    }
    return output;
}

} // namespace ValidationUtils

} // namespace FunctionCalling
} // namespace RawrXD
