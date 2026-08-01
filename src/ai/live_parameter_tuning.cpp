// live_parameter_tuning.cpp - Implementation of live parameter tuning
// Part of the Copilot-like inference pipeline.

#include "live_parameter_tuning.h"
#include <sstream>
#include <nlohmann/json.hpp>

namespace RawrXD {

using json = nlohmann::json;

LiveParameterTuner::LiveParameterTuner(FinalProductionPipeline* pipeline)
    : pipeline_(pipeline)
{
}

LiveParameterTuner::~LiveParameterTuner() {
}

void LiveParameterTuner::RegisterParameter(const ParameterDef& def) {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    definitions_[def.name] = def;
    
    // Set default value based on type
    ParameterValue default_value;
    default_value.name = def.name;
    default_value.type = def.type;
    
    switch (def.type) {
        case ParameterType::FLOAT:
            default_value.float_value = def.range.min_float;
            break;
        case ParameterType::INT:
            default_value.int_value = def.range.min_int;
            break;
        case ParameterType::BOOL:
            default_value.bool_value = false;
            break;
        case ParameterType::STRING:
            default_value.string_value = "";
            break;
        case ParameterType::ENUM:
            if (!def.range.enum_values.empty()) {
                default_value.string_value = def.range.enum_values[0];
            }
            break;
    }
    
    defaults_[def.name] = default_value;
    values_[def.name] = default_value;
}

ParameterValue LiveParameterTuner::GetParameter(const std::string& name) const {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    auto it = values_.find(name);
    if (it != values_.end()) {
        return it->second;
    }
    
    return ParameterValue{};
}

bool LiveParameterTuner::SetParameter(const std::string& name, const ParameterValue& value) {
    if (!ValidateParameter(name, value)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    auto def_it = definitions_.find(name);
    if (def_it == definitions_.end()) {
        return false;
    }
    
    // Store old value
    auto old_value = values_[name];
    
    // Update value
    values_[name] = value;
    values_[name].changed_at = std::chrono::steady_clock::now();
    
    // Add to history
    history_[name].push_back(values_[name]);
    if (history_[name].size() > 100) {
        history_[name].erase(history_[name].begin());
    }
    
    // Apply if hot-swappable
    if (def_it->second.is_hot_swappable) {
        ApplyParameter(name, value);
    }
    
    // Notify callbacks
    auto cb_it = callbacks_.find(name);
    if (cb_it != callbacks_.end() && cb_it->second) {
        cb_it->second(name, value);
    }
    
    return true;
}

bool LiveParameterTuner::SetParameterString(const std::string& name, const std::string& value) {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    auto def_it = definitions_.find(name);
    if (def_it == definitions_.end()) {
        return false;
    }
    
    ParameterValue param_value;
    param_value.name = name;
    param_value.type = def_it->second.type;
    
    switch (def_it->second.type) {
        case ParameterType::FLOAT:
            param_value.float_value = std::stof(value);
            break;
        case ParameterType::INT:
            param_value.int_value = std::stoi(value);
            break;
        case ParameterType::BOOL:
            param_value.bool_value = (value == "true" || value == "1");
            break;
        case ParameterType::STRING:
        case ParameterType::ENUM:
            param_value.string_value = value;
            break;
    }
    
    return SetParameter(name, param_value);
}

std::vector<ParameterDef> LiveParameterTuner::GetAllParameters() const {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    std::vector<ParameterDef> params;
    params.reserve(definitions_.size());
    
    for (const auto& pair : definitions_) {
        params.push_back(pair.second);
    }
    
    return params;
}

std::vector<ParameterDef> LiveParameterTuner::GetParametersByCategory(const std::string& category) const {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    std::vector<ParameterDef> params;
    
    for (const auto& pair : definitions_) {
        if (pair.second.category == category) {
            params.push_back(pair.second);
        }
    }
    
    return params;
}

void LiveParameterTuner::RegisterCallback(const std::string& name, ParameterChangeCallback callback) {
    std::lock_guard<std::mutex> lock(params_mutex_);
    callbacks_[name] = callback;
}

void LiveParameterTuner::UnregisterCallback(const std::string& name) {
    std::lock_guard<std::mutex> lock(params_mutex_);
    callbacks_.erase(name);
}

std::vector<ParameterValue> LiveParameterTuner::GetChangeHistory(const std::string& name, int count) const {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    auto it = history_.find(name);
    if (it == history_.end()) {
        return {};
    }
    
    int start = std::max(0, static_cast<int>(it->second.size()) - count);
    return std::vector<ParameterValue>(
        it->second.begin() + start,
        it->second.end());
}

std::string LiveParameterTuner::ExportParametersJSON() const {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    std::ostringstream json;
    json << "{\n";
    
    bool first = true;
    for (const auto& pair : values_) {
        if (!first) json << ",\n";
        first = false;
        
        json << "  \"" << pair.first << "\": ";
        
        switch (pair.second.type) {
            case ParameterType::FLOAT:
                json << pair.second.float_value;
                break;
            case ParameterType::INT:
                json << pair.second.int_value;
                break;
            case ParameterType::BOOL:
                json << (pair.second.bool_value ? "true" : "false");
                break;
            case ParameterType::STRING:
            case ParameterType::ENUM:
                json << "\"" << pair.second.string_value << "\"";
                break;
        }
    }
    
    json << "\n}";
    
    return json.str();
}

bool LiveParameterTuner::ImportParametersJSON(const std::string& json_str) {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    try {
        json j = json::parse(json_str);
        
        for (auto& [key, value] : j.items()) {
            auto it = definitions_.find(key);
            if (it == definitions_.end()) {
                continue; // Skip unknown parameters
            }
            
            const auto& def = it->second;
            ParameterValue param_value;
            param_value.name = key;
            param_value.type = def.type;
            
            switch (def.type) {
                case ParameterType::FLOAT:
                    if (value.is_number()) {
                        param_value.float_value = value.get<double>();
                        // Clamp to range
                        param_value.float_value = std::max(def.range.min_float,
                            std::min(def.range.max_float, param_value.float_value));
                    }
                    break;
                case ParameterType::INT:
                    if (value.is_number_integer()) {
                        param_value.int_value = value.get<int>();
                        // Clamp to range
                        param_value.int_value = std::max(def.range.min_int,
                            std::min(def.range.max_int, param_value.int_value));
                    }
                    break;
                case ParameterType::BOOL:
                    if (value.is_boolean()) {
                        param_value.bool_value = value.get<bool>();
                    }
                    break;
                case ParameterType::STRING:
                    if (value.is_string()) {
                        param_value.string_value = value.get<std::string>();
                    }
                    break;
                case ParameterType::ENUM:
                    if (value.is_string()) {
                        std::string enum_val = value.get<std::string>();
                        // Validate enum value
                        bool valid = false;
                        for (const auto& allowed : def.range.enum_values) {
                            if (allowed == enum_val) {
                                valid = true;
                                break;
                            }
                        }
                        if (valid) {
                            param_value.string_value = enum_val;
                        }
                    }
                    break;
            }
            
            values_[key] = param_value;
        }
        
        return true;
    } catch (const json::exception& e) {
        // JSON parsing failed
        return false;
    }
}

bool LiveParameterTuner::ResetParameter(const std::string& name) {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    auto it = defaults_.find(name);
    if (it == defaults_.end()) {
        return false;
    }
    
    values_[name] = it->second;
    return true;
}

void LiveParameterTuner::ResetAllParameters() {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    for (const auto& pair : defaults_) {
        values_[pair.first] = pair.second;
    }
}

bool LiveParameterTuner::ValidateParameter(const std::string& name, const ParameterValue& value) const {
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    auto def_it = definitions_.find(name);
    if (def_it == definitions_.end()) {
        return false;
    }
    
    if (value.type != def_it->second.type) {
        return false;
    }
    
    switch (value.type) {
        case ParameterType::FLOAT:
            if (value.float_value < def_it->second.range.min_float ||
                value.float_value > def_it->second.range.max_float) {
                return false;
            }
            break;
        case ParameterType::INT:
            if (value.int_value < def_it->second.range.min_int ||
                value.int_value > def_it->second.range.max_int) {
                return false;
            }
            break;
        case ParameterType::ENUM:
            {
                bool valid = false;
                for (const auto& ev : def_it->second.range.enum_values) {
                    if (ev == value.string_value) {
                        valid = true;
                        break;
                    }
                }
                if (!valid) return false;
            }
            break;
        default:
            break;
    }
    
    return true;
}

bool LiveParameterTuner::ApplyParameter(const std::string& name, const ParameterValue& value) {
    // Parameter application updates the stored value
    // Components read parameters on their next update cycle
    std::lock_guard<std::mutex> lock(params_mutex_);
    
    auto it = definitions_.find(name);
    if (it == definitions_.end()) {
        return false; // Unknown parameter
    }
    
    // Validate type matches
    if (value.type != it->second.type) {
        return false; // Type mismatch
    }
    
    // Store the value
    values_[name] = value;
    
    // Notify pipeline of parameter change
    if (pipeline_) {
        pipeline_->OnParameterChanged(name, value);
    }
    
    return true;
}

} // namespace RawrXD
