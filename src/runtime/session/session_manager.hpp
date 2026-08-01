#pragma once

#include <string>
#include <cstdint>
#include <unordered_map>
#include <memory>
#include "inference_session.hpp"

// Forward declarations
namespace rawrxd {
    class Tokenizer;
    class KVCache;
    class RuntimeContext;
}

namespace rawrxd {
namespace runtime {

class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    // Create a new session for the given model name
    std::shared_ptr<InferenceSession> create(
        const std::string& modelName
    );

    // Destroy a session by ID
    bool destroy(
        uint64_t session_id
    );

    // Get a session by ID
    std::shared_ptr<InferenceSession> get(
        uint64_t session_id
    );

    // Get the next available session ID
    uint64_t getNextSessionId();

private:
    std::unordered_map<uint64_t, std::shared_ptr<InferenceSession>> sessions_;
    uint64_t nextSessionId_;
};

} // namespace runtime
} // namespace rawrxd