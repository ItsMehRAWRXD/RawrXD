// ============================================================================
// engine_iface.cpp — Engine Registry Implementation
// ============================================================================
#include "engine_iface.h"
#include <map>
#include <mutex>
#include <vector>
#include <algorithm>

namespace {
    std::mutex g_registryMutex;
    std::map<std::string, Engine*> g_engines;
    std::vector<std::string> g_engineOrder; // Registration order
}

Engine* EngineRegistry::get(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    auto it = g_engines.find(name);
    if (it != g_engines.end()) {
        return it->second;
    }
    return nullptr;
}

void EngineRegistry::register_engine(Engine* e) {
    if (!e) return;
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    // Remove from order if already exists (re-registration)
    auto orderIt = std::find(g_engineOrder.begin(), g_engineOrder.end(), e->name());
    if (orderIt != g_engineOrder.end()) {
        g_engineOrder.erase(orderIt);
    }
    
    g_engines[e->name()] = e;
    g_engineOrder.push_back(e->name());
}

void EngineRegistry::unregister_engine(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    auto it = g_engines.find(name);
    if (it != g_engines.end()) {
        g_engines.erase(it);
    }
    
    auto orderIt = std::find(g_engineOrder.begin(), g_engineOrder.end(), name);
    if (orderIt != g_engineOrder.end()) {
        g_engineOrder.erase(orderIt);
    }
}

std::vector<std::string> EngineRegistry::list_engines() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    return g_engineOrder;
}

size_t EngineRegistry::count() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    return g_engines.size();
}

void EngineRegistry::clear() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    g_engines.clear();
    g_engineOrder.clear();
}

bool EngineRegistry::has_engine(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    return g_engines.find(name) != g_engines.end();
}

Engine* EngineRegistry::get_default() {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    if (g_engineOrder.empty()) {
        return nullptr;
    }
    return g_engines[g_engineOrder.front()];
}

Engine* EngineRegistry::get_by_capability(const std::string& capability) {
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    for (const auto& name : g_engineOrder) {
        Engine* e = g_engines[name];
        if (e && e->has_capability(capability)) {
            return e;
        }
    }
    
    return nullptr;
}
