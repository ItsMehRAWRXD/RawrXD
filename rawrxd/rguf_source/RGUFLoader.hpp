// RGUFLoader.hpp -- RGUF model loader header
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include "RGUFFormat.hpp"

namespace rguf {

struct LoadedBlock {
    Block meta;
    std::vector<uint8_t> bytes;
};

class Model {
public:
    bool open(const std::string& path, std::string& err);
    void set_key(const uint8_t key[32]) noexcept;
    std::shared_ptr<LoadedBlock> acquire(uint64_t tensor, uint64_t block, std::string& err);
    bool apply_patch(const std::string& path, std::string& err);

private:
    std::string path_;
    std::vector<Block> blocks_;
    std::unordered_map<uint64_t, size_t> index_;
    std::vector<std::shared_ptr<LoadedBlock>> active_;
    std::mutex mu_;
    uint8_t key_[32] = {};
    bool has_key_ = false;
};

} // namespace rguf
