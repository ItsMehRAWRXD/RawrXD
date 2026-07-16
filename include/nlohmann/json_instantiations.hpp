// json_instantiations.hpp - Explicit template instantiations for nlohmann::json
// Include this header in any translation unit that uses json::get<T>() with complex types

#pragma once

#include "json.hpp"
#include <map>
#include <string>
#include <vector>

namespace nlohmann {
    // Explicit template instantiations for common container types
    // These prevent linker errors when json::get<T>() is used across multiple translation units
    
    extern template std::map<std::string, json> json::get<std::map<std::string, json>>() const;
    extern template std::map<std::string, std::string> json::get<std::map<std::string, std::string>>() const;
    extern template std::vector<json> json::get<std::vector<json>>() const;
    extern template std::vector<std::string> json::get<std::vector<std::string>>() const;
} // namespace nlohmann
