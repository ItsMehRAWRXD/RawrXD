// RawrXD native ELF64 Linux/x86-64 executable emitter.
// No libc, Qt, external linker, or third-party headers required.
// Limited to a position-independent-free ET_EXEC with one RX PT_LOAD segment.
// This is a bootstrap emitter, NOT a general ELF relocatable-object linker.
#pragma once
#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace rawrxd::native_link {
inline void put16(std::vector<uint8_t>& b, size_t p, uint16_t v) {
    for (unsigned i=0;i<2;++i) b[p+i]=uint8_t(v>>(8*i));
}
inline void put32(std::vector<uint8_t>& b, size_t p, uint32_t v) {
    for (unsigned i=0;i<4;++i) b[p+i]=uint8_t(v>>(8*i));
}
inline void put64(std::vector<uint8_t>& b, size_t p, uint64_t v) {
    for (unsigned i=0;i<8;++i) b[p+i]=uint8_t(v>>(8*i));
}
// Linux x86-64: caller supplies already-encoded machine instructions.
// The entry point is the first instruction. Maximum image size is 16 MiB.
inline bool emit_elf64_x86_64(const std::string& path,
                             const std::vector<uint8_t>& code,
                             std::string* error=nullptr) {
    auto fail=[&](const char* why) { if(error) *error=why; return false; };
    constexpr size_t header=64, phdr=56, code_offset=0x1000;
    constexpr uint64_t base=0x400000;
    if (code.empty()) return fail("empty code");
    if (code.size()>16u*1024u*1024u) return fail("image exceeds 16 MiB limit");
    std::vector<uint8_t> out(code_offset+code.size(),0);
    out[0]=0x7f; out[1]='E'; out[2]='L'; out[3]='F';
    out[4]=2; out[5]=1; out[6]=1; // ELFCLASS64, LSB, current
    put16(out,16,2); // ET_EXEC
    put16(out,18,62); // EM_X86_64
    put32(out,20,1);
    put64(out,24,base+code_offset); // e_entry
    put64(out,32,header); // e_phoff
    put16(out,52,header); put16(out,54,phdr); put16(out,56,1);
    put32(out,header+0,1); // PT_LOAD
    put32(out,header+4,5); // PF_R | PF_X
    put64(out,header+8,0); // p_offset
    put64(out,header+16,base); // p_vaddr
    put64(out,header+24,base); // p_paddr
    put64(out,header+32,out.size()); // p_filesz
    put64(out,header+40,out.size()); // p_memsz
    put64(out,header+48,0x1000); // p_align
    for(size_t i=0;i<code.size();++i) out[code_offset+i]=code[i];
    std::ofstream file(path,std::ios::binary|std::ios::trunc);
    if(!file) return fail("cannot open output");
    file.write(reinterpret_cast<const char*>(out.data()),
               static_cast<std::streamsize>(out.size()));
    if(!file) return fail("cannot write output");
    return true;
}
} // namespace rawrxd::native_link
