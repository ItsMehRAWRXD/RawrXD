// json_instantiations.cpp - Explicit template instantiations for nlohmann::json
// This file provides the actual template instantiations to prevent linker errors

#include <nlohmann/json.hpp>
#include <map>
#include <string>
#include <vector>

namespace nlohmann {
    // Explicit template instantiations for common container types
    template std::map<std::string, json> json::get<std::map<std::string, json>>() const;
    template std::map<std::string, std::string> json::get<std::map<std::string, std::string>>() const;
    template std::vector<json> json::get<std::vector<json>>() const;
    template std::vector<std::string> json::get<std::vector<std::string>>() const;
} // namespace nlohmann
