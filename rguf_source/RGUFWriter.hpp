#pragma once
#include "RGUFFormat.hpp"
#include <string>
#include <vector>
namespace rguf {
class Writer { std::string path_; std::vector<Tensor> tensors_; std::vector<Block> blocks_; uint8_t key_[32]{}; bool encrypt_=false; public:
 bool pack(const std::string& gguf,const std::string& out,bool encrypt,const uint8_t key[32],std::string& err);
 bool make_patch(const std::string& rguf,const std::string& patch,uint64_t tensor,uint64_t block,const uint8_t* data,size_t n,std::string& err);
};
}
