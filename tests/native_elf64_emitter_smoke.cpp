#include "../src/native_link/elf64_emitter.hpp"
#include <cassert>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
int main(int argc,char** argv) {
    const std::string path=argc>1?argv[1]:"rawrxd_elf64_smoke";
    // mov eax,60; mov edi,42; syscall => exit(42) on Linux x86-64
    const std::vector<uint8_t> code={0xb8,60,0,0,0,0xbf,42,0,0,0,0x0f,0x05};
    std::string error;
    assert(rawrxd::native_link::emit_elf64_x86_64(path,code,&error));
    std::ifstream f(path,std::ios::binary);
    assert(f.good());
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)),{});
    assert(b.size()==4096+code.size());
    assert(b[0]==0x7f && b[1]=='E' && b[2]=='L' && b[3]=='F');
    assert(b[4]==2 && b[5]==1 && b[6]==1);
    assert(b[16]==2 && b[18]==62 && b[56]==1);
    assert(b[4096]==0xb8 && b[4096+10]==0x0f && b[4096+11]==0x05);
    assert(!rawrxd::native_link::emit_elf64_x86_64(path,{},&error));
    return 0;
}
