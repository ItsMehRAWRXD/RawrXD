// PatchRegistry.hpp
// Central registry for patcher implementations
// Part of the Sovereign PatchRegistry abstraction layer

#ifndef PATCHREGISTRY_HPP
#define PATCHREGISTRY_HPP

#include "IPatcher.hpp"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <string>

namespace Sovereign {

/**
 * @class PatchRegistry
 * @brief Thread-safe registry for patcher backend management
 * 
 * Usage:
 *   PatchRegistry registry;
 *   registry.Register(std::make_shared<MockPatcher>());
 *   
 *   auto result = registry.Apply("mock", request);
 * 
 * The registry allows switching between implementations
 * without changing the validation harness code.
 */
class PatchRegistry {
    mutable std::mutex lock;
    std::unordered_map<std::string, std::shared_ptr<IPatcher>> patchers;

public:
    /**
     * @brief Register a patcher implementation
     * @param patcher The patcher to register
     */
    void Register(std::shared_ptr<IPatcher> patcher) {
        std::lock_guard<std::mutex> g(lock);
        patchers[patcher->Name()] = patcher;
    }

    /**
     * @brief Resolve a patcher by name
     * @param name Patcher identifier (e.g., "mock", "hot")
     * @return Shared pointer to patcher, or nullptr if not found
     */
    std::shared_ptr<IPatcher> Resolve(const std::string& name) const {
        std::lock_guard<std::mutex> g(lock);
        auto it = patchers.find(name);
        if (it == patchers.end()) {
            return nullptr;
        }
        return it->second;
    }

    /**
     * @brief Apply a patch using the specified backend
     * @param backend Name of the patcher to use
     * @param request Patch specification
     * @return Result of the operation
     */
    PatchResult Apply(const std::string& backend, const PatchRequest& request) const {
        auto p = Resolve(backend);
        if (!p) {
            return {
                false,
                request.address,
                "PATCHER_NOT_FOUND: " + backend
            };
        }
        return p->Apply(request);
    }

    /**
     * @brief Rollback a patch using the specified backend
     * @param backend Name of the patcher to use
     * @param request Patch specification
     * @return Result of the operation
     */
    PatchResult Rollback(const std::string& backend, const PatchRequest& request) const {
        auto p = Resolve(backend);
        if (!p) {
            return {
                false,
                request.address,
                "PATCHER_NOT_FOUND: " + backend
            };
        }
        return p->Rollback(request);
    }

    /**
     * @brief Check if a patcher is registered
     * @param name Patcher identifier
     * @return true if registered
     */
    bool HasPatcher(const std::string& name) const {
        std::lock_guard<std::mutex> g(lock);
        return patchers.find(name) != patchers.end();
    }

    /**
     * @brief Get list of registered patcher names
     * @return Vector of registered names
     */
    std::vector<std::string> GetRegisteredNames() const {
        std::lock_guard<std::mutex> g(lock);
        std::vector<std::string> names;
        names.reserve(patchers.size());
        for (const auto& pair : patchers) {
            names.push_back(pair.first);
        }
        return names;
    }

    /**
     * @brief Clear all registered patchers
     */
    void Clear() {
        std::lock_guard<std::mutex> g(lock);
        patchers.clear();
    }
};

} // namespace Sovereign

#endif // PATCHREGISTRY_HPP
