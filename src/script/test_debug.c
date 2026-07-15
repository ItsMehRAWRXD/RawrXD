// Debug test for RawrXD-Script
#include <stdio.h>
#include <stdint.h>

extern int JsInterpreter_Run(uint8_t* bytecode, size_t bytecode_size, 
                             uint64_t* constants, uint64_t* result);
extern uint64_t JsInterpreter_GetRegister(int idx);

#define OP_LOAD_FALSE   0x09
#define OP_RETURN       0x50

int main() {
    printf("Debug Test: OP_LOAD_FALSE\n");
    
    // Just load false and return it
    uint8_t bytecode[] = {
        OP_LOAD_FALSE, 0,    // r0 = false
        OP_RETURN, 0         // return r0
    };
    uint64_t constants[] = {};
    uint64_t result;
    
    int status = JsInterpreter_Run(bytecode, sizeof(bytecode), constants, &result);
    
    printf("Status: %d\n", status);
    printf("Result: 0x%016llX\n", (unsigned long long)result);
    printf("Expected JS_FALSE: 0x7FF2000000000000\n");
    
    if (result == 0x7FF2000000000000ULL) {
        printf("✅ OP_LOAD_FALSE works!\n");
        return 0;
    } else {
        printf("❌ OP_LOAD_FALSE failed!\n");
        return 1;
    }
}
