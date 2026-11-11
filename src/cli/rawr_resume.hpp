#pragma once
#include "rawr_session_store.hpp"
namespace rawr {
inline bool ResumeSession(const std::string& id, SessionState& s) {
    return LoadSession(id, s);
}
} // namespace rawr
