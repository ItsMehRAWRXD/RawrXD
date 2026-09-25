#include "core/HexMagResidencyAuthority.hpp"
#include <iostream>
#include <string>
#include <unordered_map>

using namespace RawrXD::HexMag;
namespace {
struct Entry { bool resident{}; std::uint64_t bytes{}; };
struct Harness { std::unordered_map<std::string, Entry> items; };
bool prefetch(void* u, std::string_view key, std::uint64_t bytes) {
    auto& h = *static_cast<Harness*>(u); h.items[std::string(key)] = {true, bytes}; return true;
}
bool evict(void* u, std::string_view key) {
    auto& h = *static_cast<Harness*>(u); auto it=h.items.find(std::string(key)); if(it==h.items.end()) return false; it->second.resident=false; return true;
}
bool reload(void* u, std::string_view key, std::uint64_t* out) {
    auto& h = *static_cast<Harness*>(u); auto it=h.items.find(std::string(key)); if(it==h.items.end()) return false; it->second.resident=true; *out=it->second.bytes; return true;
}
bool resident(void* u, std::string_view key) {
    auto& h = *static_cast<Harness*>(u); auto it=h.items.find(std::string(key)); return it!=h.items.end() && it->second.resident;
}
}
int main() {
    Harness h;
    ResidencyAuthority a({&h,&prefetch,&evict,&reload,&resident});
    if (!a.prefetch("expert.0", 4096)) return 1;
    if (!a.prefetch("expert.1", 4096)) return 2;
    if (!a.touch("expert.1")) return 3;
    if (a.trimToBudget(4096, {"expert.1"}) != 1) return 4;
    if (!a.reload("expert.0")) return 5;
    if (!a.receipt().pass()) return 6;
    std::cout << a.receipt().text();
    return 0;
}
