#include "../src/deep2/MoEWeightsLoader.hpp"
#include <cassert>
#include <cstdint>
#include <vector>
// Safe ownership regression: invalid requests must fail without exposing
// dangling buffers. Full GGUF byte parity requires a fixture/model test.
int main() {
 Deep2::MoEWeightsLoader loader;
 std::vector<uint8_t> owned{1,2,3};
 assert(!loader.LoadExpertOwned(-1,0,owned));
 assert(owned.empty());
 assert(!loader.LoadExpertOwned(0,-1,owned));
 assert(!loader.LoadExpertOwned(0,0,owned)); // unopened file
 return 0;
}
