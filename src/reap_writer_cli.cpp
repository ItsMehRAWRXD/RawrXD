#include "deep2/GGUFLoader.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
namespace fs=std::filesystem;
static std::string readAll(const fs::path& p){std::ifstream f(p,std::ios::binary);return std::string((std::istreambuf_iterator<char>(f)),{});}
int main(int argc,char**argv){
  if(argc!=4){std::cerr<<"usage: rawr-reap-writer <first-shard.gguf> <mask.json> <output-dir>\n";return 2;}
  const fs::path src=fs::absolute(argv[1]), mask=fs::absolute(argv[2]), out=fs::absolute(argv[3]);
  if(!fs::exists(src)||!fs::exists(mask)){std::cerr<<"REAP_WRITER_INPUT_MISSING\n";return 4;}
  Deep2::GGUFLoader l; if(!l.load(src.string())){std::cerr<<"REAP_WRITER_SOURCE_INVALID: "<<l.error()<<"\n";return 4;}
  const std::string m=readAll(mask);
  // A writer must never infer a mask. Require explicit completion and a hash.
  if(m.find("\"complete\":true")==std::string::npos || m.find("mask_sha256") == std::string::npos || m.find("\"selected\"")==std::string::npos){
    std::cout<<"{\"status\":\"BLOCKED\",\"reason\":\"INCOMPLETE_SELECTION_MANIFEST\",\"output_written\":false}\n";return 4;
  }
  // Structural validation is intentionally performed before any write. The
  // actual projection-slice writer remains gated until CPU parity and router
  // remap receipts exist; never emit a structurally unproven checkpoint.
  std::cout<<"{\"status\":\"BLOCKED\",\"reason\":\"WRITER_PARITY_GATE_REQUIRED\",\"source_shards_valid\":true,\"output_written\":false}\n";
  (void)out; return 4;
}
