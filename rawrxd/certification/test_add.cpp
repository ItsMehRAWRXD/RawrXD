#include <cstdio>
#include <cstdint>
#include <vector>
#include "compiler_backend/rawr_backend_types.hpp"
#include "compiler_backend/InstructionEncoderX64.hpp"
#include "sovereign/puppeteer/JITAssembler.hpp"
using namespace RawrXD::Backend;

int main() {
    // Test ADD
    JITAssembler jit;
    InstructionIR mov;
    mov.mnemonic = Mnemonic::MOV;
    mov.operands.push_back(Operand::fromReg(Register::EAX));
    mov.operands.push_back(Operand::fromReg(Register::ECX));
    jit.emit(mov);
    
    InstructionIR add;
    add.mnemonic = Mnemonic::ADD;
    add.operands.push_back(Operand::fromReg(Register::EAX));
    add.operands.push_back(Operand::fromReg(Register::EDX));
    jit.emit(add);
    
    InstructionIR ret;
    ret.mnemonic = Mnemonic::RET;
    jit.emit(ret);
    
    auto fn = jit.finalize();
    printf("entryAddr=%p\n", (void*)fn.entryAddr);
    
    // Dump bytes
    for (size_t i = 0; i < fn.size; i++) {
        printf("%02X ", fn.code[i]);
    }
    printf("\n");
    
    if (fn.entryAddr) {
        int result = fn.call<int>(7, 5);
        printf("Result: %d\n", result);
    }
    return 0;
}
