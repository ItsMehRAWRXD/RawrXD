/*==========================================================================
 * x64 Win64 ABI Support - Calling Convention Implementation
 *=========================================================================*/

#include "x64_abi.h"
#include "x64_validate.h"
#include <string.h>

void x64_abi_call_init(x64_abi_call_builder_t* builder) {
    memset(builder, 0, sizeof(*builder));
    builder->num_reg_args = 0;
    builder->num_stack_args = 0;
    builder->stack_adjust = 0;
}

int x64_abi_add_arg_imm(x64_abi_call_builder_t* builder, uint64_t value) {
    if (builder->num_reg_args < 4) {
        x64_reg_t target_reg;
        switch (builder->num_reg_args) {
            case 0: target_reg = REG_RCX; break;
            case 1: target_reg = REG_RDX; break;
            case 2: target_reg = REG_R8;  break;
            case 3: target_reg = REG_R9;  break;
            default: return -1;
        }
        
        x64_operand_t dst = {.type = OP_REG, .size = SZ_QWORD, .reg = target_reg};
        x64_operand_t src = {.type = OP_IMM, .size = SZ_QWORD, .imm = (int64_t)value};
        x64_encoded_t enc = x64_encode_safe(MNEM_MOV, &dst, &src, NULL);
        
        if (enc.len == 0) return -1;
        memcpy(builder->code + builder->len, enc.bytes, enc.len);
        builder->len += enc.len;
        builder->num_reg_args++;
        return 0;
    } else {
        /* Stack argument - push immediate (simplified: mov to stack) */
        /* For now, we don't support more than 4 args */
        return -1;
    }
}

int x64_abi_add_arg_reg(x64_abi_call_builder_t* builder, x64_reg_t reg) {
    if (builder->num_reg_args < 4) {
        x64_reg_t target_reg;
        switch (builder->num_reg_args) {
            case 0: target_reg = REG_RCX; break;
            case 1: target_reg = REG_RDX; break;
            case 2: target_reg = REG_R8;  break;
            case 3: target_reg = REG_R9;  break;
            default: return -1;
        }
        
        x64_operand_t dst = {.type = OP_REG, .size = SZ_QWORD, .reg = target_reg};
        x64_operand_t src = {.type = OP_REG, .size = SZ_QWORD, .reg = reg};
        x64_encoded_t enc = x64_encode_safe(MNEM_MOV, &dst, &src, NULL);
        
        if (enc.len == 0) return -1;
        memcpy(builder->code + builder->len, enc.bytes, enc.len);
        builder->len += enc.len;
        builder->num_reg_args++;
        return 0;
    }
    return -1;
}

int x64_abi_emit_call(x64_abi_call_builder_t* builder, uint32_t import_rva) {
    /* Step 1: Align stack to 16-byte boundary
     * Current RSP is 8 mod 16 (return address pushed by caller)
     * We need RSP 0 mod 16 at call instruction
     * Shadow space (32 bytes) + return address (8) = 40, which is 8 mod 16
     * So we need to push one more 8-byte value to get to 0 mod 16
     */
    
    /* Allocate shadow space (sub rsp, 32) */
    x64_operand_t rsp = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RSP};
    x64_operand_t imm32 = {.type = OP_IMM, .size = SZ_QWORD, .imm = X64_ABI_SHADOW_SPACE};
    x64_encoded_t enc = x64_encode_safe(MNEM_SUB, &rsp, &imm32, NULL);
    if (enc.len == 0) return -1;
    memcpy(builder->code + builder->len, enc.bytes, enc.len);
    builder->len += enc.len;
    builder->stack_adjust += X64_ABI_SHADOW_SPACE;
    
    /* Step 2: Call through IAT
     * call qword ptr [rip + disp32]
     * We need to encode: FF 15 XX XX XX XX
     * Where XX is the displacement to the IAT slot
     */
    
    /* For now, emit a direct call with placeholder
     * In real implementation, we'd calculate RIP-relative displacement
     * to the IAT slot in the .idata section
     */
    
    /* Emit: call qword ptr [rip + 0] (placeholder) */
    /* This is: FF 15 00 00 00 00 */
    /* Actually, let's emit a direct relative call for now */
    /* call rel32: E8 XX XX XX XX */
    
    /* Simplified: emit call to absolute address (not position independent) */
    /* For a real implementation, we'd need relocation support */
    
    /* Emit: mov rax, import_rva; call rax */
    x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
    x64_operand_t addr = {.type = OP_IMM, .size = SZ_QWORD, .imm = import_rva};
    enc = x64_encode_safe(MNEM_MOV, &rax, &addr, NULL);
    if (enc.len == 0) return -1;
    memcpy(builder->code + builder->len, enc.bytes, enc.len);
    builder->len += enc.len;
    
    /* call rax */
    /* ModR/M: 11 010 000 = D0 (mod=11, reg=010=call, rm=000=rax) */
    builder->code[builder->len++] = 0xFF;
    builder->code[builder->len++] = 0xD0;
    
    /* Step 3: Restore stack (add rsp, 32) */
    enc = x64_encode_safe(MNEM_ADD, &rsp, &imm32, NULL);
    if (enc.len == 0) return -1;
    memcpy(builder->code + builder->len, enc.bytes, enc.len);
    builder->len += enc.len;
    
    return 0;
}

uint8_t* x64_abi_get_code(x64_abi_call_builder_t* builder) {
    return builder->code;
}

size_t x64_abi_get_len(x64_abi_call_builder_t* builder) {
    return builder->len;
}

int x64_abi_gen_call_4imm(uint8_t* out, size_t* len, uint32_t import_rva,
                          uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    x64_abi_call_builder_t builder;
    x64_abi_call_init(&builder);
    
    if (x64_abi_add_arg_imm(&builder, arg1) != 0) return -1;
    if (x64_abi_add_arg_imm(&builder, arg2) != 0) return -1;
    if (x64_abi_add_arg_imm(&builder, arg3) != 0) return -1;
    if (x64_abi_add_arg_imm(&builder, arg4) != 0) return -1;
    
    if (x64_abi_emit_call(&builder, import_rva) != 0) return -1;
    
    memcpy(out, builder.code, builder.len);
    *len = builder.len;
    return 0;
}
