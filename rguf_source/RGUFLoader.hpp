#pragma once
#include "RGUFFormat.hpp"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <string>
namespace rguf {
struct LoadedBlock { Block meta; std::vector<uint8_t> bytes; };
class Model { std::string path_; std::vector<Block> blocks_; std::unordered_map<uint64_t,size_t> index_; mutable std::mutex mu_; std::vector<std::shared_ptr<LoadedBlock>> active_; uint8_t key_[32]{}; bool has_key_=false; public:
 bool open(const std::string&,std::string&); void set_key(const uint8_t key[32]) noexcept; std::shared_ptr<LoadedBlock> acquire(uint64_t tensor,uint64_t block,std::string&); bool apply_patch(const std::string&,std::string&); size_t block_count()const{return blocks_.size();}
};
}
