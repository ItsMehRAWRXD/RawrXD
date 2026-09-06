#include "IOCPGGUFLoader.hpp"
#include <cstdio>
#include <string>
int main() {
  Deep2::IOCPGGUFLoader loader;
  Deep2::IOCPGGUFLoader::Config cfg;
  cfg.useIOCP = true;
  cfg.noBuffering = false;
  cfg.verbose = true;
  const char* path = "F:/~dev/tinyllama_fresh.gguf";
  try {
    if (!loader.Open(path, cfg)) { printf("OPEN_FAIL\n"); return 1; }
    printf("OPEN_OK\n");
    Deep2::ModelMetadata meta;
    std::vector<Deep2::TensorInfo> tensors;
    uint64_t off = 0;
    if (!loader.ParseHeader(meta, tensors, off)) { printf("PARSE_FAIL\n"); return 2; }
    printf("PARSE_OK tensors=%zu layers=%u off=%llu\n", tensors.size(), meta.numLayers, (unsigned long long)off);
    return 0;
  } catch (const std::exception& e) {
    printf("CXX_EX=%s\n", e.what());
    return 3;
  } catch (...) {
    printf("CXX_EX_UNKNOWN\n");
    return 4;
  }
}
