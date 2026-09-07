#pragma once
#include "../abi/runtime_abi.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>
namespace rawr::product {

struct CacheEntry {
    uint32_t key = 0;
    uint64_t gen = 0;
    std::string prompt;
    uint32_t hits = 0;
};

struct ContextCache {
    std::unordered_map<uint32_t, CacheEntry> map;
    uint32_t hits = 0;
    uint32_t misses = 0;

    static uint32_t makeKey(const std::string& path, const std::string& prefix,
                            uint32_t line) {
        std::string blob = path + "\n" + std::to_string(line) + "\n" + prefix;
        return RawrFnv1a32(blob.data(), (uint32_t)blob.size());
    }

    bool get(uint32_t key, uint64_t gen, std::string& out) {
        auto it = map.find(key);
        if (it == map.end() || it->second.gen != gen) {
            misses++;
            return false;
        }
        hits++;
        it->second.hits++;
        out = it->second.prompt;
        return true;
    }

    void put(uint32_t key, uint64_t gen, const std::string& prompt) {
        CacheEntry e{};
        e.key = key;
        e.gen = gen;
        e.prompt = prompt;
        map[key] = e;
    }

    void invalidateGen(uint64_t gen) {
        for (auto it = map.begin(); it != map.end();) {
            if (it->second.gen != gen) it = map.erase(it);
            else ++it;
        }
    }
};

} // namespace rawr::product
