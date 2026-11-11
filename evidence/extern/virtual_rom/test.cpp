#include "virtual_rom.hpp"
#include <cassert>
#include <iostream>
#include <array>
int main() {
    constexpr uint64_t logical=1ULL<<40; // 1 TiB logical address space
    auto exact=[](uint64_t offset,uint8_t* dst,size_t n)->bool {
        for(size_t i=0;i<n;++i) dst[i]=uint8_t(((offset+i)*1315423911ULL)>>17);
        return true;
    };
    rawrxd::VirtualROM rom(logical,4096,8192,exact);
    std::array<uint8_t,10000> data{};
    rom.read(4090,data.data(),data.size());
    for(size_t i=0;i<data.size();++i) assert(data[i]==uint8_t(((4090+i)*1315423911ULL)>>17));
    assert(rom.resident_bytes()<=8192);
    assert(rom.stats().evictions>0);
    rom.read(4090,data.data(),32);
    assert(rom.resident_bytes()<=8192);
    bool bounds=false;
    try { rom.read(logical-3,data.data(),4); } catch(const std::out_of_range&) {bounds=true;}
    assert(bounds);
    std::cout << "VIRTUAL_ROM_PASS logical=" << rom.size() << " resident=" << rom.resident_bytes() << " evictions=" << rom.stats().evictions << "\n";
}
