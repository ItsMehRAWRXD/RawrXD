#include "d:\rawrxd\src\reverse_engineering\RawrCodex_Multi_v2.hpp"
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern "C" DecodeStatus ReferenceDecoder_Decode(ArchType arch, const uint8_t* bytes, size_t byteCount, uint64_t va, DecodedInstruction* output);

int main() {
    printf("=== MIPS32 Decoder Standalone Test ===\n\n");
    
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    
    // MIPS32 NOP instruction: 0x00000000
    uint8_t nop[] = {0x00, 0x00, 0x00, 0x00};
    
    printf("Testing MIPS32 NOP instruction...\n");
    printf("Instruction bytes: %02X %02X %02X %02X\n", nop[0], nop[1], nop[2], nop[3]);
    printf("Virtual address: 0x1000\n");
    printf("Output structure size: %zu bytes\n", sizeof(instr));
    printf("\n");
    
    printf("Calling ReferenceDecoder_Decode...\n");
    fflush(stdout);
    
    __try {
        DecodeStatus status = ReferenceDecoder_Decode(
            ArchType::MIPS_32,
            nop,
            4,
            0x1000,
            &instr
        );
        
        printf("Decode completed successfully!\n");
        printf("Return status: %d\n", (int)status);
        printf("Instruction length: %u\n", instr.raw.length);
        printf("Instruction class: %u\n", instr.semantic.instrClass);
        printf("Mnemonic: %u\n", instr.semantic.mnemonic);
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("CRASH: Exception 0x%08X occurred during MIPS32 decode\n", GetExceptionCode());
        return 1;
    }
    
    return 0;
}