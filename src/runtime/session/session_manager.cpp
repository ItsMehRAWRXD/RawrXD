#include "session_manager.hpp"
#include <stdexcept>

namespace rawrxd {
namespace runtime {

SessionManager::SessionManager() : nextSessionId_(1) {}

SessionManager::~SessionManager() {
    // Clean up any remaining sessions
    sessions_.clear();
}

std::shared_ptr<InferenceSession> SessionManager::create(
    const std::string& modelName
) {
    // In a full implementation, we would look up the model in a model registry
    // For now, we'll create a placeholder session
    auto session = std::make_shared<InferenceSession>();
    session->id = getNextSessionId();
    session->active = true;
    // Note: In a real implementation, we would set the model, tokenizer, etc.
    // by looking up the model in a model registry and initializing the session.
    
    sessions_[session->id] = session;
    return session;
}

bool SessionManager::destroy(
    uint64_t session_id
) {
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        sessions_.erase(it);
        return true;
    }
    return false;
}

std::shared_ptr<InferenceSession> SessionManager::get(
    uint64_t session_id
) {
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        return it->second;
    }
    return nullptr;
}

uint64_t SessionManager::getNextSessionId() {
    return nextSessionId_++;
}

} // namespace runtime
} // namespace rawrxd
