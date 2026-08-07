#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include "../model_registry/model_manifest.hpp"

// Forward declarations
namespace rawrxd {
    class Tokenizer;
    class KVCache;
    class RuntimeContext;
}

namespace rawrxd {
namespace runtime {

struct InferenceSession {
    uint64_t id;
    ModelManifest model;
    
    // Smart pointers to components for automatic memory management
    std::shared_ptr<Tokenizer> tokenizer;
    std::shared_ptr<KVCache> kv_cache;
    std::shared_ptr<RuntimeContext> runtime;
    
    uint64_t tokens_processed;
    bool active;

    // Constructor
    InferenceSession() : 
        id(0), 
        tokenizer(nullptr),
        kv_cache(nullptr),
        runtime(nullptr),
        tokens_processed(0), 
        active(false) {}

    // Destructor
    ~InferenceSession() = default;
};

} // namespace runtime
} // namespace rawrxd