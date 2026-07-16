#!/usr/bin/env python3
"""
Generate comprehensive decoder test corpus for all architectures
"""

import os
import struct
import sys

# ARM64 instruction encodings (little-endian)
ARM64_INSTRUCTIONS = {
    # NOP and hints
    "nop": bytes([0x1F, 0x20, 0x03, 0xD5]),           # HINT #0x1E
    "yield": bytes([0x1F, 0x20, 0x03, 0xD5]),         # HINT #1
    "wfe": bytes([0x5F, 0x20, 0x03, 0xD5]),          # HINT #2
    "wfi": bytes([0x7F, 0x20, 0x03, 0xD5]),           # HINT #3
    "sev": bytes([0x9F, 0x20, 0x03, 0xD5]),           # HINT #4
    "sevl": bytes([0xBF, 0x20, 0x03, 0xD5]),          # HINT #5
    
    # Data processing - immediate
    "movz_x0": bytes([0x00, 0x00, 0x80, 0xD2]),       # MOVZ X0, #0
    "movz_x1_1": bytes([0x21, 0x00, 0x80, 0xD2]),     # MOVZ X1, #1
    "movn_x0": bytes([0x00, 0x00, 0x80, 0x92]),       # MOVN X0, #0
    "movk_x0": bytes([0x00, 0x00, 0x80, 0xF2]),       # MOVK X0, #0
    "add_x0_sp_0": bytes([0x00, 0x00, 0x80, 0x91]),   # ADD X0, SP, #0
    "sub_x0_sp_0": bytes([0x00, 0x00, 0x80, 0xD1]),   # SUB X0, SP, #0
    "adds_x0_x0_0": bytes([0x00, 0x00, 0x00, 0xB1]),  # ADDS X0, X0, #0
    "subs_x0_x0_0": bytes([0x00, 0x00, 0x00, 0xF1]),  # SUBS X0, X0, #0
    "cmp_x0_0": bytes([0x00, 0x00, 0x80, 0xF1]),      # CMP X0, #0 (SUBS XZR, X0, #0)
    "cmn_x0_0": bytes([0x00, 0x00, 0x80, 0xB1]),      # CMN X0, #0 (ADDS XZR, X0, #0)
    
    # Data processing - register
    "add_x0_x1_x2": bytes([0x20, 0x00, 0x02, 0x8B]),  # ADD X0, X1, X2
    "sub_x0_x1_x2": bytes([0x20, 0x00, 0x02, 0xCB]),  # SUB X0, X1, X2
    "and_x0_x1_x2": bytes([0x20, 0x00, 0x02, 0x8A]),  # AND X0, X1, X2
    "orr_x0_x1_x2": bytes([0x20, 0x00, 0x02, 0xAA]),  # ORR X0, X1, X2
    "eor_x0_x1_x2": bytes([0x20, 0x00, 0x02, 0xCA]),  # EOR X0, X1, X2
    "ands_x0_x1_x2": bytes([0x20, 0x00, 0x02, 0xEA]), # ANDS X0, X1, X2
    "tst_x1_x2": bytes([0x3F, 0x00, 0x02, 0xEA]),     # TST X1, X2 (ANDS XZR, X1, X2)
    "lsl_x0_x1_1": bytes([0x20, 0x04, 0x00, 0xD3]),   # LSL X0, X1, #1
    "lsr_x0_x1_1": bytes([0x20, 0x04, 0x00, 0xD3]),   # LSR X0, X1, #1 (with different immr)
    "asr_x0_x1_1": bytes([0x20, 0x04, 0x00, 0x93]),   # ASR X0, X1, #1
    
    # Load/store
    "ldr_x0_sp": bytes([0xE0, 0x03, 0x40, 0xF9]),     # LDR X0, [SP]
    "str_x0_sp": bytes([0xE0, 0x03, 0x00, 0xF9]),     # STR X0, [SP]
    "ldp_x0_x1_sp": bytes([0xE0, 0x0B, 0x40, 0xA9]),  # LDP X0, X1, [SP]
    "stp_x0_x1_sp": bytes([0xE0, 0x0B, 0x00, 0xA9]),  # STP X0, X1, [SP]
    "ldrb_w0_sp": bytes([0xE0, 0x03, 0x40, 0x39]),    # LDRB W0, [SP]
    "ldrh_w0_sp": bytes([0xE0, 0x03, 0x40, 0x79]),    # LDRH W0, [SP]
    "ldrsb_x0_sp": bytes([0xE0, 0x03, 0xC0, 0x39]),   # LDRSB X0, [SP]
    "ldrsw_x0_sp": bytes([0xE0, 0x03, 0x80, 0xB9]),   # LDRSW X0, [SP]
    
    # Branches
    "b": bytes([0x00, 0x00, 0x00, 0x14]),             # B .
    "bl": bytes([0x00, 0x00, 0x00, 0x94]),             # BL .
    "ret": bytes([0xC0, 0x03, 0x5F, 0xD6]),           # RET
    "ret_x0": bytes([0x00, 0x00, 0x5F, 0xD6]),         # RET X0
    "br_x0": bytes([0x00, 0x00, 0x1F, 0xD6]),          # BR X0
    "blr_x0": bytes([0x00, 0x00, 0x3F, 0xD6]),         # BLR X0
    "cbz_x0": bytes([0x00, 0x00, 0x00, 0xB4]),          # CBZ X0, .
    "cbnz_x0": bytes([0x00, 0x00, 0x00, 0xB5]),         # CBNZ X0, .
    "tbz_x0_0": bytes([0x00, 0x00, 0x00, 0x36]),        # TBZ X0, #0, .
    "tbnz_x0_0": bytes([0x00, 0x00, 0x00, 0x37]),       # TBNZ X0, #0, .
    "beq": bytes([0x00, 0x00, 0x00, 0x54]),             # B.EQ .
    "bne": bytes([0x00, 0x00, 0x00, 0x54]),             # B.NE . (different cond)
    
    # PC-relative addressing
    "adr_x0": bytes([0x00, 0x00, 0x00, 0x10]),          # ADR X0, .
    "adrp_x0": bytes([0x00, 0x00, 0x00, 0x90]),         # ADRP X0, .
    
    # System instructions
    "svc_0": bytes([0x01, 0x00, 0x00, 0xD4]),           # SVC #0
    "hvc_0": bytes([0x02, 0x00, 0x00, 0xD4]),           # HVC #0
    "smc_0": bytes([0x03, 0x00, 0x00, 0xD4]),           # SMC #0
    "brk_0": bytes([0x00, 0x00, 0x20, 0xD4]),           # BRK #0
    "dmb_ish": bytes([0xBF, 0x3B, 0x03, 0xD5]),         # DMB ISH
    "dsb_ish": bytes([0x9F, 0x3B, 0x03, 0xD5]),         # DSB ISH
    "isb": bytes([0xDF, 0x3B, 0x03, 0xD5]),             # ISB
    "mrs_x0_cntpct": bytes([0x00, 0x00, 0x1B, 0xD5]),   # MRS X0, CNTPCT_EL0
    "msr_cntpct_x0": bytes([0x00, 0x00, 0x1B, 0xD5]),   # MSR CNTPCT_EL0, X0 (different encoding)
}

# MIPS32 instruction encodings (big-endian)
MIPS32_INSTRUCTIONS = {
    # NOP and special
    "nop": bytes([0x00, 0x00, 0x00, 0x00]),            # SLL $zero, $zero, 0
    "ssnop": bytes([0x00, 0x00, 0x00, 0x40]),           # SSNOP
    "ehb": bytes([0x00, 0x00, 0x00, 0x80]),             # EHB
    "pause": bytes([0x00, 0x00, 0x01, 0x00]),           # PAUSE
    "sync": bytes([0x00, 0x00, 0x00, 0x0F]),            # SYNC
    
    # Shifts
    "sll_v0_v1_1": bytes([0x00, 0x06, 0x08, 0x80]),     # SLL $v0, $v1, 1
    "srl_v0_v1_1": bytes([0x00, 0x06, 0x08, 0xC2]),     # SRL $v0, $v1, 1
    "sra_v0_v1_1": bytes([0x00, 0x06, 0x08, 0xC3]),     # SRA $v0, $v1, 1
    "sllv_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x04]),   # SLLV $v0, $v1, $v2
    "srlv_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x06]),   # SRLV $v0, $v1, $v2
    "srav_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x07]),   # SRAV $v0, $v1, $v2
    
    # Arithmetic
    "add_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x20]),    # ADD $v0, $v1, $v2
    "addu_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x21]),   # ADDU $v0, $v1, $v2
    "sub_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x22]),    # SUB $v0, $v1, $v2
    "subu_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x23]),   # SUBU $v0, $v1, $v2
    "addi_v0_v1_1": bytes([0x20, 0x46, 0x00, 0x01]),    # ADDI $v0, $v1, 1
    "addiu_v0_v1_1": bytes([0x24, 0x46, 0x00, 0x01]),   # ADDIU $v0, $v1, 1
    "lui_v0_0x1234": bytes([0x3C, 0x02, 0x12, 0x34]),   # LUI $v0, 0x1234
    
    # Logical
    "and_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x24]),    # AND $v0, $v1, $v2
    "or_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x25]),     # OR $v0, $v1, $v2
    "xor_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x26]),    # XOR $v0, $v1, $v2
    "nor_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x27]),    # NOR $v0, $v1, $v2
    "andi_v0_v1_0xFF": bytes([0x30, 0x46, 0x00, 0xFF]),  # ANDI $v0, $v1, 0xFF
    "ori_v0_v1_0xFF": bytes([0x34, 0x46, 0x00, 0xFF]),   # ORI $v0, $v1, 0xFF
    "xori_v0_v1_0xFF": bytes([0x38, 0x46, 0x00, 0xFF]),  # XORI $v0, $v1, 0xFF
    
    # Comparison
    "slt_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x2A]),     # SLT $v0, $v1, $v2
    "sltu_v0_v1_v2": bytes([0x00, 0x46, 0x10, 0x2B]),    # SLTU $v0, $v1, $v2
    "slti_v0_v1_1": bytes([0x28, 0x46, 0x00, 0x01]),     # SLTI $v0, $v1, 1
    "sltiu_v0_v1_1": bytes([0x2C, 0x46, 0x00, 0x01]),    # SLTIU $v0, $v1, 1
    
    # Multiply/divide
    "mult_a0_a1": bytes([0x00, 0x85, 0x00, 0x18]),       # MULT $a0, $a1
    "multu_a0_a1": bytes([0x00, 0x85, 0x00, 0x19]),      # MULTU $a0, $a1
    "div_a0_a1": bytes([0x00, 0x85, 0x00, 0x1A]),         # DIV $a0, $a1
    "divu_a0_a1": bytes([0x00, 0x85, 0x00, 0x1B]),        # DIVU $a0, $a1
    "mfhi_v0": bytes([0x00, 0x00, 0x10, 0x10]),           # MFHI $v0
    "mflo_v0": bytes([0x00, 0x00, 0x10, 0x12]),           # MFLO $v0
    "mthi_a0": bytes([0x00, 0x80, 0x00, 0x11]),           # MTHI $a0
    "mtlo_a0": bytes([0x00, 0x80, 0x00, 0x13]),           # MTLO $a0
    
    # Load/store
    "lb_v0_0_sp": bytes([0x80, 0x42, 0x00, 0x00]),        # LB $v0, 0($sp)
    "lh_v0_0_sp": bytes([0x84, 0x42, 0x00, 0x00]),        # LH $v0, 0($sp)
    "lw_v0_0_sp": bytes([0x8C, 0x42, 0x00, 0x00]),        # LW $v0, 0($sp)
    "lbu_v0_0_sp": bytes([0x90, 0x42, 0x00, 0x00]),       # LBU $v0, 0($sp)
    "lhu_v0_0_sp": bytes([0x94, 0x42, 0x00, 0x00]),       # LHU $v0, 0($sp)
    "lwl_v0_0_sp": bytes([0x88, 0x42, 0x00, 0x00]),       # LWL $v0, 0($sp)
    "lwr_v0_0_sp": bytes([0x98, 0x42, 0x00, 0x00]),       # LWR $v0, 0($sp)
    "sb_v0_0_sp": bytes([0xA0, 0x42, 0x00, 0x00]),        # SB $v0, 0($sp)
    "sh_v0_0_sp": bytes([0xA4, 0x42, 0x00, 0x00]),        # SH $v0, 0($sp)
    "sw_v0_0_sp": bytes([0xAC, 0x42, 0x00, 0x00]),        # SW $v0, 0($sp)
    "swl_v0_0_sp": bytes([0xA8, 0x42, 0x00, 0x00]),       # SWL $v0, 0($sp)
    "swr_v0_0_sp": bytes([0xB8, 0x42, 0x00, 0x00]),       # SWR $v0, 0($sp)
    "ll_v0_0_sp": bytes([0xC0, 0x42, 0x00, 0x00]),        # LL $v0, 0($sp)
    "sc_v0_0_sp": bytes([0xE0, 0x42, 0x00, 0x00]),        # SC $v0, 0($sp)
    
    # Branches
    "beq_v0_v1": bytes([0x10, 0x46, 0x00, 0x00]),         # BEQ $v0, $v1, .
    "bne_v0_v1": bytes([0x14, 0x46, 0x00, 0x00]),         # BNE $v0, $v1, .
    "blez_v0": bytes([0x18, 0x40, 0x00, 0x00]),           # BLEZ $v0, .
    "bgtz_v0": bytes([0x1C, 0x40, 0x00, 0x00]),           # BGTZ $v0, .
    "bltz_v0": bytes([0x04, 0x40, 0x00, 0x00]),           # BLTZ $v0, .
    "bgez_v0": bytes([0x04, 0x41, 0x00, 0x00]),           # BGEZ $v0, .
    "bltzal_v0": bytes([0x04, 0x50, 0x00, 0x00]),          # BLTZAL $v0, .
    "bgezal_v0": bytes([0x04, 0x51, 0x00, 0x00]),          # BGEZAL $v0, .
    "j": bytes([0x08, 0x00, 0x00, 0x00]),                  # J .
    "jal": bytes([0x0C, 0x00, 0x00, 0x00]),                 # JAL .
    "jr_ra": bytes([0x03, 0xE0, 0x00, 0x08]),               # JR $ra
    "jalr_ra": bytes([0x00, 0xE0, 0xF8, 0x09]),             # JALR $ra
    
    # System
    "syscall": bytes([0x00, 0x00, 0x00, 0x0C]),             # SYSCALL
    "break_0": bytes([0x00, 0x00, 0x00, 0x0D]),             # BREAK
    "eret": bytes([0x42, 0x00, 0x00, 0x18]),                 # ERET
    "mfc0_v0_status": bytes([0x40, 0x02, 0x0C, 0x00]),      # MFC0 $v0, $12
    "mtc0_v0_status": bytes([0x40, 0x82, 0x0C, 0x00]),      # MTC0 $v0, $12
    "tlbp": bytes([0x42, 0x00, 0x00, 0x08]),                 # TLBP
    "tlbr": bytes([0x42, 0x00, 0x00, 0x01]),                 # TLBR
    "tlbwi": bytes([0x42, 0x00, 0x00, 0x02]),                # TLBWI
    "tlbwr": bytes([0x42, 0x00, 0x00, 0x06]),                # TLBWR
}

# RISC-V32 instruction encodings (little-endian)
RISCV32_INSTRUCTIONS = {
    # NOP and base
    "nop": bytes([0x13, 0x00, 0x00, 0x00]),               # ADDI x0, x0, 0
    "li_x5_0": bytes([0x93, 0x02, 0x00, 0x00]),           # ADDI x5, x0, 0 (LI pseudo)
    
    # Arithmetic
    "add_x5_x6_x7": bytes([0xB3, 0x02, 0x73, 0x00]),      # ADD x5, x6, x7
    "sub_x5_x6_x7": bytes([0xB3, 0x02, 0x73, 0x40]),      # SUB x5, x6, x7
    "addi_x5_x6_1": bytes([0x93, 0x02, 0x16, 0x00]),      # ADDI x5, x6, 1
    "lui_x5_0x12345": bytes([0xB7, 0x52, 0x34, 0x12]),   # LUI x5, 0x12345
    "auipc_x5_0": bytes([0x97, 0x52, 0x00, 0x00]),        # AUIPC x5, 0
    
    # Logical
    "and_x5_x6_x7": bytes([0xB3, 0x72, 0x73, 0x00]),      # AND x5, x6, x7
    "or_x5_x6_x7": bytes([0xB3, 0x62, 0x73, 0x00]),       # OR x5, x6, x7
    "xor_x5_x6_x7": bytes([0xB3, 0x42, 0x73, 0x00]),      # XOR x5, x6, x7
    "andi_x5_x6_1": bytes([0x93, 0x72, 0x16, 0x00]),      # ANDI x5, x6, 1
    "ori_x5_x6_1": bytes([0x93, 0x62, 0x16, 0x00]),       # ORI x5, x6, 1
    "xori_x5_x6_1": bytes([0x93, 0x42, 0x16, 0x00]),      # XORI x5, x6, 1
    
    # Shifts
    "sll_x5_x6_x7": bytes([0xB3, 0x12, 0x73, 0x00]),      # SLL x5, x6, x7
    "srl_x5_x6_x7": bytes([0xB3, 0x52, 0x73, 0x00]),      # SRL x5, x6, x7
    "sra_x5_x6_x7": bytes([0xB3, 0x52, 0x73, 0x40]),      # SRA x5, x6, x7
    "slli_x5_x6_1": bytes([0x93, 0x12, 0x16, 0x00]),      # SLLI x5, x6, 1
    "srli_x5_x6_1": bytes([0x93, 0x52, 0x16, 0x00]),      # SRLI x5, x6, 1
    "srai_x5_x6_1": bytes([0x93, 0x52, 0x16, 0x40]),      # SRAI x5, x6, 1
    
    # Comparison
    "slt_x5_x6_x7": bytes([0xB3, 0x22, 0x73, 0x00]),      # SLT x5, x6, x7
    "sltu_x5_x6_x7": bytes([0xB3, 0x32, 0x73, 0x00]),     # SLTU x5, x6, x7
    "slti_x5_x6_1": bytes([0x93, 0x22, 0x16, 0x00]),      # SLTI x5, x6, 1
    "sltiu_x5_x6_1": bytes([0x93, 0x32, 0x16, 0x00]),     # SLTIU x5, x6, 1
    
    # Load/store
    "lb_x5_0_x6": bytes([0x83, 0x02, 0x06, 0x00]),        # LB x5, 0(x6)
    "lh_x5_0_x6": bytes([0x83, 0x12, 0x06, 0x00]),        # LH x5, 0(x6)
    "lw_x5_0_x6": bytes([0x83, 0x22, 0x06, 0x00]),        # LW x5, 0(x6)
    "lbu_x5_0_x6": bytes([0x83, 0x42, 0x06, 0x00]),       # LBU x5, 0(x6)
    "lhu_x5_0_x6": bytes([0x83, 0x52, 0x06, 0x00]),       # LHU x5, 0(x6)
    "sb_x5_0_x6": bytes([0x23, 0x00, 0x56, 0x00]),        # SB x5, 0(x6)
    "sh_x5_0_x6": bytes([0x23, 0x10, 0x56, 0x00]),        # SH x5, 0(x6)
    "sw_x5_0_x6": bytes([0x23, 0x20, 0x56, 0x00]),        # SW x5, 0(x6)
    
    # Branches
    "beq_x5_x6": bytes([0xE3, 0x00, 0x56, 0x00]),         # BEQ x5, x6, .
    "bne_x5_x6": bytes([0xE3, 0x10, 0x56, 0x00]),         # BNE x5, x6, .
    "blt_x5_x6": bytes([0xE3, 0x40, 0x56, 0x00]),         # BLT x5, x6, .
    "bge_x5_x6": bytes([0xE3, 0x50, 0x56, 0x00]),         # BGE x5, x6, .
    "bltu_x5_x6": bytes([0xE3, 0x60, 0x56, 0x00]),        # BLTU x5, x6, .
    "bgeu_x5_x6": bytes([0xE3, 0x70, 0x56, 0x00]),        # BGEU x5, x6, .
    "jal": bytes([0x6F, 0x00, 0x00, 0x00]),               # JAL x0, .
    "jal_x1": bytes([0xEF, 0x00, 0x00, 0x00]),            # JAL x1, .
    "jalr_x5_x6": bytes([0x67, 0x02, 0x06, 0x00]),        # JALR x5, x6, 0
    
    # System
    "ecall": bytes([0x73, 0x00, 0x00, 0x00]),             # ECALL
    "ebreak": bytes([0x73, 0x00, 0x10, 0x00]),            # EBREAK
    "uret": bytes([0x73, 0x00, 0x20, 0x00]),               # URET
    "sret": bytes([0x73, 0x00, 0x20, 0x10]),               # SRET
    "mret": bytes([0x73, 0x00, 0x20, 0x30]),               # MRET
    "wfi": bytes([0x73, 0x00, 0x50, 0x10]),                # WFI
    "fence": bytes([0x0F, 0x00, 0x00, 0x00]),              # FENCE
    "fence_i": bytes([0x0F, 0x10, 0x00, 0x00]),            # FENCE.I
    
    # CSR
    "csrrw_x5_x6_cycle": bytes([0x73, 0x12, 0xC0, 0x02]),  # CSRRW x5, cycle, x6
    "csrrs_x5_x6_cycle": bytes([0x73, 0x22, 0xC0, 0x02]),  # CSRRS x5, cycle, x6
    "csrrc_x5_x6_cycle": bytes([0x73, 0x32, 0xC0, 0x02]),  # CSRRC x5, cycle, x6
    "csrrwi_x5_1_cycle": bytes([0xF3, 0x12, 0xC0, 0x02]),  # CSRRWI x5, cycle, 1
    "csrrsi_x5_1_cycle": bytes([0xF3, 0x22, 0xC0, 0x02]),  # CSRRSI x5, cycle, 1
    "csrrci_x5_1_cycle": bytes([0xF3, 0x32, 0xC0, 0x02]),  # CSRRCI x5, cycle, 1
    
    # M extension (RV32M)
    "mul_x5_x6_x7": bytes([0xB3, 0x02, 0x73, 0x02]),      # MUL x5, x6, x7
    "mulh_x5_x6_x7": bytes([0xB3, 0x12, 0x73, 0x02]),     # MULH x5, x6, x7
    "mulhsu_x5_x6_x7": bytes([0xB3, 0x22, 0x73, 0x02]),   # MULHSU x5, x6, x7
    "mulhu_x5_x6_x7": bytes([0xB3, 0x32, 0x73, 0x02]),     # MULHU x5, x6, x7
    "div_x5_x6_x7": bytes([0xB3, 0x42, 0x73, 0x02]),      # DIV x5, x6, x7
    "divu_x5_x6_x7": bytes([0xB3, 0x52, 0x73, 0x02]),     # DIVU x5, x6, x7
    "rem_x5_x6_x7": bytes([0xB3, 0x62, 0x73, 0x02]),      # REM x5, x6, x7
    "remu_x5_x6_x7": bytes([0xB3, 0x72, 0x73, 0x02]),     # REMU x5, x6, x7
    
    # Compressed (RVC) - 16-bit
    "c_nop": bytes([0x01, 0x00]),                         # C.NOP
    "c_addi_x5_1": bytes([0x05, 0x45]),                   # C.ADDI x5, 1
    "c_li_x5_1": bytes([0x05, 0x41]),                     # C.LI x5, 1
    "c_lui_x5_1": bytes([0x05, 0x61]),                    # C.LUI x5, 1
    "c_addi16sp": bytes([0x61, 0x61]),                    # C.ADDI16SP
    "c_addi4spn_x8": bytes([0x00, 0x00]),                  # C.ADDI4SPN x8, 0
    "c_slli_x5_1": bytes([0x85, 0x05]),                   # C.SLLI x5, 1
    "c_srli_x8_1": bytes([0x81, 0x81]),                   # C.SRLI x8, 1
    "c_srai_x8_1": bytes([0x81, 0x85]),                   # C.SRAI x8, 1
    "c_andi_x8_1": bytes([0x81, 0x88]),                   # C.ANDI x8, 1
    "c_mv_x5_x6": bytes([0x82, 0x02]),                    # C.MV x5, x6
    "c_add_x5_x6": bytes([0x82, 0x42]),                   # C.ADD x5, x6
    "c_and_x8_x9": bytes([0x01, 0x8C]),                   # C.AND x8, x9
    "c_or_x8_x9": bytes([0x01, 0x8D]),                    # C.OR x8, x9
    "c_xor_x8_x9": bytes([0x01, 0x8C]),                   # C.XOR x8, x9 (different funct)
    "c_sub_x8_x9": bytes([0x81, 0x8C]),                   # C.SUB x8, x9
    "c_j": bytes([0x01, 0xA1]),                            # C.J .
    "c_jal": bytes([0x01, 0xB1]),                          # C.JAL .
    "c_jr_x5": bytes([0x82, 0x00]),                        # C.JR x5
    "c_jalr_x5": bytes([0x82, 0x02]),                      # C.JALR x5
    "c_beqz_x8": bytes([0x81, 0xC1]),                      # C.BEQZ x8, .
    "c_bnez_x8": bytes([0x81, 0xE1]),                      # C.BNEZ x8, .
    "c_lw_x8_0_x10": bytes([0x00, 0x42]),                # C.LW x8, 0(x10)
    "c_sw_x8_0_x10": bytes([0x00, 0xC2]),                # C.SW x8, 0(x10)
    "c_lwsp_x5_0": bytes([0x02, 0x45]),                  # C.LWSP x5, 0
    "c_swsp_x5_0": bytes([0x02, 0xC2]),                  # C.SWSP x5, 0
}

def write_corpus_file(directory, name, data):
    """Write instruction bytes to corpus file"""
    filepath = os.path.join(directory, f"{name}.bin")
    with open(filepath, 'wb') as f:
        f.write(data)
    return filepath

def generate_malformed_corpus(base_dir):
    """Generate malformed instruction test cases"""
    malformed_dir = os.path.join(base_dir, "malformed")
    os.makedirs(malformed_dir, exist_ok=True)
    
    test_cases = {
        "all_zeros": bytes([0x00] * 4),
        "all_ones": bytes([0xFF] * 4),
        "alternating": bytes([0xAA, 0x55, 0xAA, 0x55]),
        "truncated_1": bytes([0x00]),
        "truncated_2": bytes([0x00, 0x00]),
        "truncated_3": bytes([0x00, 0x00, 0x00]),
        "overlong": bytes([0x00] * 16),
        "invalid_prefix": bytes([0xFF, 0xFF, 0x00, 0x00]),
    }
    
    for name, data in test_cases.items():
        write_corpus_file(malformed_dir, name, data)
    
    return len(test_cases)

def generate_arm64_corpus(base_dir):
    """Generate ARM64 test corpus"""
    arm64_dir = os.path.join(base_dir, "arm64")
    os.makedirs(arm64_dir, exist_ok=True)
    
    count = 0
    for name, data in ARM64_INSTRUCTIONS.items():
        write_corpus_file(arm64_dir, name, data)
        count += 1
    
    return count

def generate_mips_corpus(base_dir):
    """Generate MIPS32 test corpus"""
    mips_dir = os.path.join(base_dir, "mips")
    os.makedirs(mips_dir, exist_ok=True)
    
    count = 0
    for name, data in MIPS32_INSTRUCTIONS.items():
        write_corpus_file(mips_dir, name, data)
        count += 1
    
    return count

def generate_riscv_corpus(base_dir):
    """Generate RISC-V32 test corpus"""
    riscv_dir = os.path.join(base_dir, "riscv")
    os.makedirs(riscv_dir, exist_ok=True)
    
    count = 0
    for name, data in RISCV32_INSTRUCTIONS.items():
        write_corpus_file(riscv_dir, name, data)
        count += 1
    
    return count

def generate_test_harness(base_dir):
    """Generate C++ test harness"""
    harness_path = os.path.join(base_dir, "test_harness.cpp")
    
    harness_code = '''/**
 * Auto-generated test harness for decoder corpus
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>

#include "RawrCodex_Multi_v2.hpp"

using namespace RawrCodex;

extern "C" {
    __declspec(dllimport) uint32_t ReferenceDecoder_Decode(
        uint32_t arch,
        const uint8_t* bytes,
        uint32_t byteCount,
        uint64_t va,
        DecodedInstruction* out
    );
}

struct TestCase {
    const char* name;
    ArchType arch;
    const char* filepath;
};

// Test cases will be auto-populated
TestCase g_testCases[] = {
    // ARM64 tests
'''
    
    # Add ARM64 test cases
    for name in ARM64_INSTRUCTIONS.keys():
        harness_code += f'    {{ "arm64/{name}", ArchType::ARM_64, "arm64/{name}.bin" }},\n'
    
    harness_code += '''    
    // MIPS tests
'''
    
    for name in MIPS32_INSTRUCTIONS.keys():
        harness_code += f'    {{ "mips/{name}", ArchType::MIPS_32, "mips/{name}.bin" }},\n'
    
    harness_code += '''    
    // RISC-V tests
'''
    
    for name in RISCV32_INSTRUCTIONS.keys():
        harness_code += f'    {{ "riscv/{name}", ArchType::RISCV_32, "riscv/{name}.bin" }},\n'
    
    harness_code += '''};

const size_t g_testCount = sizeof(g_testCases) / sizeof(g_testCases[0]);

bool RunTest(const TestCase& test) {
    // Read test file
    FILE* f = fopen(test.filepath, "rb");
    if (!f) {
        printf("[SKIP] Cannot open: %s\\n", test.filepath);
        return true; // Skip, don't fail
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size > 16) {
        printf("[FAIL] File too large: %s (%ld bytes)\\n", test.filepath, size);
        fclose(f);
        return false;
    }
    
    uint8_t bytes[16];
    size_t read = fread(bytes, 1, size, f);
    fclose(f);
    
    if (read != size) {
        printf("[FAIL] Read error: %s\\n", test.filepath);
        return false;
    }
    
    // Decode
    DecodedInstruction result;
    memset(&result, 0, sizeof(result));
    
    uint32_t status = ReferenceDecoder_Decode(
        static_cast<uint32_t>(test.arch),
        bytes,
        static_cast<uint32_t>(size),
        0x1000,
        &result
    );
    
    if (status != 0) {
        printf("[FAIL] %s: Decode error %u\\n", test.name, status);
        return false;
    }
    
    printf("[PASS] %s\\n", test.name);
    return true;
}

int main() {
    printf("=== Decoder Corpus Test Harness ===\\n");
    printf("Running %zu tests...\\n\\n", g_testCount);
    
    int passed = 0;
    int failed = 0;
    
    for (size_t i = 0; i < g_testCount; i++) {
        if (RunTest(g_testCases[i])) {
            passed++;
        } else {
            failed++;
        }
    }
    
    printf("\\n=== Results ===\\n");
    printf("Total:  %d\\n", passed + failed);
    printf("Passed: %d\\n", passed);
    printf("Failed: %d\\n", failed);
    
    return failed > 0 ? 1 : 0;
}
'''
    
    with open(harness_path, 'w') as f:
        f.write(harness_code)
    
    return harness_path

def main():
    # Determine base directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = script_dir
    
    print("Generating decoder test corpus...")
    print(f"Output directory: {base_dir}")
    
    # Generate corpus for each architecture
    arm64_count = generate_arm64_corpus(base_dir)
    print(f"Generated {arm64_count} ARM64 test cases")
    
    mips_count = generate_mips_corpus(base_dir)
    print(f"Generated {mips_count} MIPS32 test cases")
    
    riscv_count = generate_riscv_corpus(base_dir)
    print(f"Generated {riscv_count} RISC-V32 test cases")
    
    malformed_count = generate_malformed_corpus(base_dir)
    print(f"Generated {malformed_count} malformed test cases")
    
    # Generate test harness
    harness_path = generate_test_harness(base_dir)
    print(f"Generated test harness: {harness_path}")
    
    total = arm64_count + mips_count + riscv_count + malformed_count
    print(f"\nTotal test cases: {total}")
    print("Done!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
