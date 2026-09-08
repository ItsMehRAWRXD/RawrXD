#pragma once
#include "../runtime/session_persist.hpp"
#include <string>
namespace rawr::product {

inline bool saveSession(const ProductSession& s) { return SaveProductSession(s); }

inline bool loadSession(const std::string& id, ProductSession& s) {
    return LoadProductSession(id, s);
}

} // namespace rawr::product
