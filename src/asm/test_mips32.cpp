#include "d:\rawrxd\src\reverse_engineering\RawrCodex_Multi_v2.hpp"
#include <stdio>
#include <string>

extern "C" DecodeStatus ReferenceDecoder_Decode(ArchType arch, const uint8_t* bytes, size_t byteCount, uint64_t va, DecodedInstruction* output);

int main() {
    printf("Testing MIPS32 NOP decode...\n");
    
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    // MIPS32 NOP instruction: 0x00000000
    uint8_t nop[] = {0x00, 0x00, 0x00, 0x00};
    
    printf("Calling ReferenceDecoder_Decode...\n");
    DecodeStatus status = ReferenceDecoder_Decode(
        ArchType::MIPS_32,
        nop,
        4,
        0x1000,
        &instr
    );
    
    printf("Decode returned status: %d\n", static_cast<int>(status));
    printf("Instruction length: %u\n", instr.raw.length);
    printf("Instruction class: %u\n", instr.semantic.instrClass);
    printf("Mnemonic: %u\n", instr.semantic.mnemonic);
    
    return 0;
}