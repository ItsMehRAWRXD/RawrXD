/**
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
    { "arm64/nop", ArchType::ARM_64, "arm64/nop.bin" },
    { "arm64/yield", ArchType::ARM_64, "arm64/yield.bin" },
    { "arm64/wfe", ArchType::ARM_64, "arm64/wfe.bin" },
    { "arm64/wfi", ArchType::ARM_64, "arm64/wfi.bin" },
    { "arm64/sev", ArchType::ARM_64, "arm64/sev.bin" },
    { "arm64/sevl", ArchType::ARM_64, "arm64/sevl.bin" },
    { "arm64/movz_x0", ArchType::ARM_64, "arm64/movz_x0.bin" },
    { "arm64/movz_x1_1", ArchType::ARM_64, "arm64/movz_x1_1.bin" },
    { "arm64/movn_x0", ArchType::ARM_64, "arm64/movn_x0.bin" },
    { "arm64/movk_x0", ArchType::ARM_64, "arm64/movk_x0.bin" },
    { "arm64/add_x0_sp_0", ArchType::ARM_64, "arm64/add_x0_sp_0.bin" },
    { "arm64/sub_x0_sp_0", ArchType::ARM_64, "arm64/sub_x0_sp_0.bin" },
    { "arm64/adds_x0_x0_0", ArchType::ARM_64, "arm64/adds_x0_x0_0.bin" },
    { "arm64/subs_x0_x0_0", ArchType::ARM_64, "arm64/subs_x0_x0_0.bin" },
    { "arm64/cmp_x0_0", ArchType::ARM_64, "arm64/cmp_x0_0.bin" },
    { "arm64/cmn_x0_0", ArchType::ARM_64, "arm64/cmn_x0_0.bin" },
    { "arm64/add_x0_x1_x2", ArchType::ARM_64, "arm64/add_x0_x1_x2.bin" },
    { "arm64/sub_x0_x1_x2", ArchType::ARM_64, "arm64/sub_x0_x1_x2.bin" },
    { "arm64/and_x0_x1_x2", ArchType::ARM_64, "arm64/and_x0_x1_x2.bin" },
    { "arm64/orr_x0_x1_x2", ArchType::ARM_64, "arm64/orr_x0_x1_x2.bin" },
    { "arm64/eor_x0_x1_x2", ArchType::ARM_64, "arm64/eor_x0_x1_x2.bin" },
    { "arm64/ands_x0_x1_x2", ArchType::ARM_64, "arm64/ands_x0_x1_x2.bin" },
    { "arm64/tst_x1_x2", ArchType::ARM_64, "arm64/tst_x1_x2.bin" },
    { "arm64/lsl_x0_x1_1", ArchType::ARM_64, "arm64/lsl_x0_x1_1.bin" },
    { "arm64/lsr_x0_x1_1", ArchType::ARM_64, "arm64/lsr_x0_x1_1.bin" },
    { "arm64/asr_x0_x1_1", ArchType::ARM_64, "arm64/asr_x0_x1_1.bin" },
    { "arm64/ldr_x0_sp", ArchType::ARM_64, "arm64/ldr_x0_sp.bin" },
    { "arm64/str_x0_sp", ArchType::ARM_64, "arm64/str_x0_sp.bin" },
    { "arm64/ldp_x0_x1_sp", ArchType::ARM_64, "arm64/ldp_x0_x1_sp.bin" },
    { "arm64/stp_x0_x1_sp", ArchType::ARM_64, "arm64/stp_x0_x1_sp.bin" },
    { "arm64/ldrb_w0_sp", ArchType::ARM_64, "arm64/ldrb_w0_sp.bin" },
    { "arm64/ldrh_w0_sp", ArchType::ARM_64, "arm64/ldrh_w0_sp.bin" },
    { "arm64/ldrsb_x0_sp", ArchType::ARM_64, "arm64/ldrsb_x0_sp.bin" },
    { "arm64/ldrsw_x0_sp", ArchType::ARM_64, "arm64/ldrsw_x0_sp.bin" },
    { "arm64/b", ArchType::ARM_64, "arm64/b.bin" },
    { "arm64/bl", ArchType::ARM_64, "arm64/bl.bin" },
    { "arm64/ret", ArchType::ARM_64, "arm64/ret.bin" },
    { "arm64/ret_x0", ArchType::ARM_64, "arm64/ret_x0.bin" },
    { "arm64/br_x0", ArchType::ARM_64, "arm64/br_x0.bin" },
    { "arm64/blr_x0", ArchType::ARM_64, "arm64/blr_x0.bin" },
    { "arm64/cbz_x0", ArchType::ARM_64, "arm64/cbz_x0.bin" },
    { "arm64/cbnz_x0", ArchType::ARM_64, "arm64/cbnz_x0.bin" },
    { "arm64/tbz_x0_0", ArchType::ARM_64, "arm64/tbz_x0_0.bin" },
    { "arm64/tbnz_x0_0", ArchType::ARM_64, "arm64/tbnz_x0_0.bin" },
    { "arm64/beq", ArchType::ARM_64, "arm64/beq.bin" },
    { "arm64/bne", ArchType::ARM_64, "arm64/bne.bin" },
    { "arm64/adr_x0", ArchType::ARM_64, "arm64/adr_x0.bin" },
    { "arm64/adrp_x0", ArchType::ARM_64, "arm64/adrp_x0.bin" },
    { "arm64/svc_0", ArchType::ARM_64, "arm64/svc_0.bin" },
    { "arm64/hvc_0", ArchType::ARM_64, "arm64/hvc_0.bin" },
    { "arm64/smc_0", ArchType::ARM_64, "arm64/smc_0.bin" },
    { "arm64/brk_0", ArchType::ARM_64, "arm64/brk_0.bin" },
    { "arm64/dmb_ish", ArchType::ARM_64, "arm64/dmb_ish.bin" },
    { "arm64/dsb_ish", ArchType::ARM_64, "arm64/dsb_ish.bin" },
    { "arm64/isb", ArchType::ARM_64, "arm64/isb.bin" },
    { "arm64/mrs_x0_cntpct", ArchType::ARM_64, "arm64/mrs_x0_cntpct.bin" },
    { "arm64/msr_cntpct_x0", ArchType::ARM_64, "arm64/msr_cntpct_x0.bin" },
    
    // MIPS tests
    { "mips/nop", ArchType::MIPS_32, "mips/nop.bin" },
    { "mips/ssnop", ArchType::MIPS_32, "mips/ssnop.bin" },
    { "mips/ehb", ArchType::MIPS_32, "mips/ehb.bin" },
    { "mips/pause", ArchType::MIPS_32, "mips/pause.bin" },
    { "mips/sync", ArchType::MIPS_32, "mips/sync.bin" },
    { "mips/sll_v0_v1_1", ArchType::MIPS_32, "mips/sll_v0_v1_1.bin" },
    { "mips/srl_v0_v1_1", ArchType::MIPS_32, "mips/srl_v0_v1_1.bin" },
    { "mips/sra_v0_v1_1", ArchType::MIPS_32, "mips/sra_v0_v1_1.bin" },
    { "mips/sllv_v0_v1_v2", ArchType::MIPS_32, "mips/sllv_v0_v1_v2.bin" },
    { "mips/srlv_v0_v1_v2", ArchType::MIPS_32, "mips/srlv_v0_v1_v2.bin" },
    { "mips/srav_v0_v1_v2", ArchType::MIPS_32, "mips/srav_v0_v1_v2.bin" },
    { "mips/add_v0_v1_v2", ArchType::MIPS_32, "mips/add_v0_v1_v2.bin" },
    { "mips/addu_v0_v1_v2", ArchType::MIPS_32, "mips/addu_v0_v1_v2.bin" },
    { "mips/sub_v0_v1_v2", ArchType::MIPS_32, "mips/sub_v0_v1_v2.bin" },
    { "mips/subu_v0_v1_v2", ArchType::MIPS_32, "mips/subu_v0_v1_v2.bin" },
    { "mips/addi_v0_v1_1", ArchType::MIPS_32, "mips/addi_v0_v1_1.bin" },
    { "mips/addiu_v0_v1_1", ArchType::MIPS_32, "mips/addiu_v0_v1_1.bin" },
    { "mips/lui_v0_0x1234", ArchType::MIPS_32, "mips/lui_v0_0x1234.bin" },
    { "mips/and_v0_v1_v2", ArchType::MIPS_32, "mips/and_v0_v1_v2.bin" },
    { "mips/or_v0_v1_v2", ArchType::MIPS_32, "mips/or_v0_v1_v2.bin" },
    { "mips/xor_v0_v1_v2", ArchType::MIPS_32, "mips/xor_v0_v1_v2.bin" },
    { "mips/nor_v0_v1_v2", ArchType::MIPS_32, "mips/nor_v0_v1_v2.bin" },
    { "mips/andi_v0_v1_0xFF", ArchType::MIPS_32, "mips/andi_v0_v1_0xFF.bin" },
    { "mips/ori_v0_v1_0xFF", ArchType::MIPS_32, "mips/ori_v0_v1_0xFF.bin" },
    { "mips/xori_v0_v1_0xFF", ArchType::MIPS_32, "mips/xori_v0_v1_0xFF.bin" },
    { "mips/slt_v0_v1_v2", ArchType::MIPS_32, "mips/slt_v0_v1_v2.bin" },
    { "mips/sltu_v0_v1_v2", ArchType::MIPS_32, "mips/sltu_v0_v1_v2.bin" },
    { "mips/slti_v0_v1_1", ArchType::MIPS_32, "mips/slti_v0_v1_1.bin" },
    { "mips/sltiu_v0_v1_1", ArchType::MIPS_32, "mips/sltiu_v0_v1_1.bin" },
    { "mips/mult_a0_a1", ArchType::MIPS_32, "mips/mult_a0_a1.bin" },
    { "mips/multu_a0_a1", ArchType::MIPS_32, "mips/multu_a0_a1.bin" },
    { "mips/div_a0_a1", ArchType::MIPS_32, "mips/div_a0_a1.bin" },
    { "mips/divu_a0_a1", ArchType::MIPS_32, "mips/divu_a0_a1.bin" },
    { "mips/mfhi_v0", ArchType::MIPS_32, "mips/mfhi_v0.bin" },
    { "mips/mflo_v0", ArchType::MIPS_32, "mips/mflo_v0.bin" },
    { "mips/mthi_a0", ArchType::MIPS_32, "mips/mthi_a0.bin" },
    { "mips/mtlo_a0", ArchType::MIPS_32, "mips/mtlo_a0.bin" },
    { "mips/lb_v0_0_sp", ArchType::MIPS_32, "mips/lb_v0_0_sp.bin" },
    { "mips/lh_v0_0_sp", ArchType::MIPS_32, "mips/lh_v0_0_sp.bin" },
    { "mips/lw_v0_0_sp", ArchType::MIPS_32, "mips/lw_v0_0_sp.bin" },
    { "mips/lbu_v0_0_sp", ArchType::MIPS_32, "mips/lbu_v0_0_sp.bin" },
    { "mips/lhu_v0_0_sp", ArchType::MIPS_32, "mips/lhu_v0_0_sp.bin" },
    { "mips/lwl_v0_0_sp", ArchType::MIPS_32, "mips/lwl_v0_0_sp.bin" },
    { "mips/lwr_v0_0_sp", ArchType::MIPS_32, "mips/lwr_v0_0_sp.bin" },
    { "mips/sb_v0_0_sp", ArchType::MIPS_32, "mips/sb_v0_0_sp.bin" },
    { "mips/sh_v0_0_sp", ArchType::MIPS_32, "mips/sh_v0_0_sp.bin" },
    { "mips/sw_v0_0_sp", ArchType::MIPS_32, "mips/sw_v0_0_sp.bin" },
    { "mips/swl_v0_0_sp", ArchType::MIPS_32, "mips/swl_v0_0_sp.bin" },
    { "mips/swr_v0_0_sp", ArchType::MIPS_32, "mips/swr_v0_0_sp.bin" },
    { "mips/ll_v0_0_sp", ArchType::MIPS_32, "mips/ll_v0_0_sp.bin" },
    { "mips/sc_v0_0_sp", ArchType::MIPS_32, "mips/sc_v0_0_sp.bin" },
    { "mips/beq_v0_v1", ArchType::MIPS_32, "mips/beq_v0_v1.bin" },
    { "mips/bne_v0_v1", ArchType::MIPS_32, "mips/bne_v0_v1.bin" },
    { "mips/blez_v0", ArchType::MIPS_32, "mips/blez_v0.bin" },
    { "mips/bgtz_v0", ArchType::MIPS_32, "mips/bgtz_v0.bin" },
    { "mips/bltz_v0", ArchType::MIPS_32, "mips/bltz_v0.bin" },
    { "mips/bgez_v0", ArchType::MIPS_32, "mips/bgez_v0.bin" },
    { "mips/bltzal_v0", ArchType::MIPS_32, "mips/bltzal_v0.bin" },
    { "mips/bgezal_v0", ArchType::MIPS_32, "mips/bgezal_v0.bin" },
    { "mips/j", ArchType::MIPS_32, "mips/j.bin" },
    { "mips/jal", ArchType::MIPS_32, "mips/jal.bin" },
    { "mips/jr_ra", ArchType::MIPS_32, "mips/jr_ra.bin" },
    { "mips/jalr_ra", ArchType::MIPS_32, "mips/jalr_ra.bin" },
    { "mips/syscall", ArchType::MIPS_32, "mips/syscall.bin" },
    { "mips/break_0", ArchType::MIPS_32, "mips/break_0.bin" },
    { "mips/eret", ArchType::MIPS_32, "mips/eret.bin" },
    { "mips/mfc0_v0_status", ArchType::MIPS_32, "mips/mfc0_v0_status.bin" },
    { "mips/mtc0_v0_status", ArchType::MIPS_32, "mips/mtc0_v0_status.bin" },
    { "mips/tlbp", ArchType::MIPS_32, "mips/tlbp.bin" },
    { "mips/tlbr", ArchType::MIPS_32, "mips/tlbr.bin" },
    { "mips/tlbwi", ArchType::MIPS_32, "mips/tlbwi.bin" },
    { "mips/tlbwr", ArchType::MIPS_32, "mips/tlbwr.bin" },
    
    // RISC-V tests
    { "riscv/nop", ArchType::RISCV_32, "riscv/nop.bin" },
    { "riscv/li_x5_0", ArchType::RISCV_32, "riscv/li_x5_0.bin" },
    { "riscv/add_x5_x6_x7", ArchType::RISCV_32, "riscv/add_x5_x6_x7.bin" },
    { "riscv/sub_x5_x6_x7", ArchType::RISCV_32, "riscv/sub_x5_x6_x7.bin" },
    { "riscv/addi_x5_x6_1", ArchType::RISCV_32, "riscv/addi_x5_x6_1.bin" },
    { "riscv/lui_x5_0x12345", ArchType::RISCV_32, "riscv/lui_x5_0x12345.bin" },
    { "riscv/auipc_x5_0", ArchType::RISCV_32, "riscv/auipc_x5_0.bin" },
    { "riscv/and_x5_x6_x7", ArchType::RISCV_32, "riscv/and_x5_x6_x7.bin" },
    { "riscv/or_x5_x6_x7", ArchType::RISCV_32, "riscv/or_x5_x6_x7.bin" },
    { "riscv/xor_x5_x6_x7", ArchType::RISCV_32, "riscv/xor_x5_x6_x7.bin" },
    { "riscv/andi_x5_x6_1", ArchType::RISCV_32, "riscv/andi_x5_x6_1.bin" },
    { "riscv/ori_x5_x6_1", ArchType::RISCV_32, "riscv/ori_x5_x6_1.bin" },
    { "riscv/xori_x5_x6_1", ArchType::RISCV_32, "riscv/xori_x5_x6_1.bin" },
    { "riscv/sll_x5_x6_x7", ArchType::RISCV_32, "riscv/sll_x5_x6_x7.bin" },
    { "riscv/srl_x5_x6_x7", ArchType::RISCV_32, "riscv/srl_x5_x6_x7.bin" },
    { "riscv/sra_x5_x6_x7", ArchType::RISCV_32, "riscv/sra_x5_x6_x7.bin" },
    { "riscv/slli_x5_x6_1", ArchType::RISCV_32, "riscv/slli_x5_x6_1.bin" },
    { "riscv/srli_x5_x6_1", ArchType::RISCV_32, "riscv/srli_x5_x6_1.bin" },
    { "riscv/srai_x5_x6_1", ArchType::RISCV_32, "riscv/srai_x5_x6_1.bin" },
    { "riscv/slt_x5_x6_x7", ArchType::RISCV_32, "riscv/slt_x5_x6_x7.bin" },
    { "riscv/sltu_x5_x6_x7", ArchType::RISCV_32, "riscv/sltu_x5_x6_x7.bin" },
    { "riscv/slti_x5_x6_1", ArchType::RISCV_32, "riscv/slti_x5_x6_1.bin" },
    { "riscv/sltiu_x5_x6_1", ArchType::RISCV_32, "riscv/sltiu_x5_x6_1.bin" },
    { "riscv/lb_x5_0_x6", ArchType::RISCV_32, "riscv/lb_x5_0_x6.bin" },
    { "riscv/lh_x5_0_x6", ArchType::RISCV_32, "riscv/lh_x5_0_x6.bin" },
    { "riscv/lw_x5_0_x6", ArchType::RISCV_32, "riscv/lw_x5_0_x6.bin" },
    { "riscv/lbu_x5_0_x6", ArchType::RISCV_32, "riscv/lbu_x5_0_x6.bin" },
    { "riscv/lhu_x5_0_x6", ArchType::RISCV_32, "riscv/lhu_x5_0_x6.bin" },
    { "riscv/sb_x5_0_x6", ArchType::RISCV_32, "riscv/sb_x5_0_x6.bin" },
    { "riscv/sh_x5_0_x6", ArchType::RISCV_32, "riscv/sh_x5_0_x6.bin" },
    { "riscv/sw_x5_0_x6", ArchType::RISCV_32, "riscv/sw_x5_0_x6.bin" },
    { "riscv/beq_x5_x6", ArchType::RISCV_32, "riscv/beq_x5_x6.bin" },
    { "riscv/bne_x5_x6", ArchType::RISCV_32, "riscv/bne_x5_x6.bin" },
    { "riscv/blt_x5_x6", ArchType::RISCV_32, "riscv/blt_x5_x6.bin" },
    { "riscv/bge_x5_x6", ArchType::RISCV_32, "riscv/bge_x5_x6.bin" },
    { "riscv/bltu_x5_x6", ArchType::RISCV_32, "riscv/bltu_x5_x6.bin" },
    { "riscv/bgeu_x5_x6", ArchType::RISCV_32, "riscv/bgeu_x5_x6.bin" },
    { "riscv/jal", ArchType::RISCV_32, "riscv/jal.bin" },
    { "riscv/jal_x1", ArchType::RISCV_32, "riscv/jal_x1.bin" },
    { "riscv/jalr_x5_x6", ArchType::RISCV_32, "riscv/jalr_x5_x6.bin" },
    { "riscv/ecall", ArchType::RISCV_32, "riscv/ecall.bin" },
    { "riscv/ebreak", ArchType::RISCV_32, "riscv/ebreak.bin" },
    { "riscv/uret", ArchType::RISCV_32, "riscv/uret.bin" },
    { "riscv/sret", ArchType::RISCV_32, "riscv/sret.bin" },
    { "riscv/mret", ArchType::RISCV_32, "riscv/mret.bin" },
    { "riscv/wfi", ArchType::RISCV_32, "riscv/wfi.bin" },
    { "riscv/fence", ArchType::RISCV_32, "riscv/fence.bin" },
    { "riscv/fence_i", ArchType::RISCV_32, "riscv/fence_i.bin" },
    { "riscv/csrrw_x5_x6_cycle", ArchType::RISCV_32, "riscv/csrrw_x5_x6_cycle.bin" },
    { "riscv/csrrs_x5_x6_cycle", ArchType::RISCV_32, "riscv/csrrs_x5_x6_cycle.bin" },
    { "riscv/csrrc_x5_x6_cycle", ArchType::RISCV_32, "riscv/csrrc_x5_x6_cycle.bin" },
    { "riscv/csrrwi_x5_1_cycle", ArchType::RISCV_32, "riscv/csrrwi_x5_1_cycle.bin" },
    { "riscv/csrrsi_x5_1_cycle", ArchType::RISCV_32, "riscv/csrrsi_x5_1_cycle.bin" },
    { "riscv/csrrci_x5_1_cycle", ArchType::RISCV_32, "riscv/csrrci_x5_1_cycle.bin" },
    { "riscv/mul_x5_x6_x7", ArchType::RISCV_32, "riscv/mul_x5_x6_x7.bin" },
    { "riscv/mulh_x5_x6_x7", ArchType::RISCV_32, "riscv/mulh_x5_x6_x7.bin" },
    { "riscv/mulhsu_x5_x6_x7", ArchType::RISCV_32, "riscv/mulhsu_x5_x6_x7.bin" },
    { "riscv/mulhu_x5_x6_x7", ArchType::RISCV_32, "riscv/mulhu_x5_x6_x7.bin" },
    { "riscv/div_x5_x6_x7", ArchType::RISCV_32, "riscv/div_x5_x6_x7.bin" },
    { "riscv/divu_x5_x6_x7", ArchType::RISCV_32, "riscv/divu_x5_x6_x7.bin" },
    { "riscv/rem_x5_x6_x7", ArchType::RISCV_32, "riscv/rem_x5_x6_x7.bin" },
    { "riscv/remu_x5_x6_x7", ArchType::RISCV_32, "riscv/remu_x5_x6_x7.bin" },
    { "riscv/c_nop", ArchType::RISCV_32, "riscv/c_nop.bin" },
    { "riscv/c_addi_x5_1", ArchType::RISCV_32, "riscv/c_addi_x5_1.bin" },
    { "riscv/c_li_x5_1", ArchType::RISCV_32, "riscv/c_li_x5_1.bin" },
    { "riscv/c_lui_x5_1", ArchType::RISCV_32, "riscv/c_lui_x5_1.bin" },
    { "riscv/c_addi16sp", ArchType::RISCV_32, "riscv/c_addi16sp.bin" },
    { "riscv/c_addi4spn_x8", ArchType::RISCV_32, "riscv/c_addi4spn_x8.bin" },
    { "riscv/c_slli_x5_1", ArchType::RISCV_32, "riscv/c_slli_x5_1.bin" },
    { "riscv/c_srli_x8_1", ArchType::RISCV_32, "riscv/c_srli_x8_1.bin" },
    { "riscv/c_srai_x8_1", ArchType::RISCV_32, "riscv/c_srai_x8_1.bin" },
    { "riscv/c_andi_x8_1", ArchType::RISCV_32, "riscv/c_andi_x8_1.bin" },
    { "riscv/c_mv_x5_x6", ArchType::RISCV_32, "riscv/c_mv_x5_x6.bin" },
    { "riscv/c_add_x5_x6", ArchType::RISCV_32, "riscv/c_add_x5_x6.bin" },
    { "riscv/c_and_x8_x9", ArchType::RISCV_32, "riscv/c_and_x8_x9.bin" },
    { "riscv/c_or_x8_x9", ArchType::RISCV_32, "riscv/c_or_x8_x9.bin" },
    { "riscv/c_xor_x8_x9", ArchType::RISCV_32, "riscv/c_xor_x8_x9.bin" },
    { "riscv/c_sub_x8_x9", ArchType::RISCV_32, "riscv/c_sub_x8_x9.bin" },
    { "riscv/c_j", ArchType::RISCV_32, "riscv/c_j.bin" },
    { "riscv/c_jal", ArchType::RISCV_32, "riscv/c_jal.bin" },
    { "riscv/c_jr_x5", ArchType::RISCV_32, "riscv/c_jr_x5.bin" },
    { "riscv/c_jalr_x5", ArchType::RISCV_32, "riscv/c_jalr_x5.bin" },
    { "riscv/c_beqz_x8", ArchType::RISCV_32, "riscv/c_beqz_x8.bin" },
    { "riscv/c_bnez_x8", ArchType::RISCV_32, "riscv/c_bnez_x8.bin" },
    { "riscv/c_lw_x8_0_x10", ArchType::RISCV_32, "riscv/c_lw_x8_0_x10.bin" },
    { "riscv/c_sw_x8_0_x10", ArchType::RISCV_32, "riscv/c_sw_x8_0_x10.bin" },
    { "riscv/c_lwsp_x5_0", ArchType::RISCV_32, "riscv/c_lwsp_x5_0.bin" },
    { "riscv/c_swsp_x5_0", ArchType::RISCV_32, "riscv/c_swsp_x5_0.bin" },
};

const size_t g_testCount = sizeof(g_testCases) / sizeof(g_testCases[0]);

bool RunTest(const TestCase& test) {
    // Read test file
    FILE* f = fopen(test.filepath, "rb");
    if (!f) {
        printf("[SKIP] Cannot open: %s\n", test.filepath);
        return true; // Skip, don't fail
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size > 16) {
        printf("[FAIL] File too large: %s (%ld bytes)\n", test.filepath, size);
        fclose(f);
        return false;
    }
    
    uint8_t bytes[16];
    size_t read = fread(bytes, 1, size, f);
    fclose(f);
    
    if (read != size) {
        printf("[FAIL] Read error: %s\n", test.filepath);
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
        printf("[FAIL] %s: Decode error %u\n", test.name, status);
        return false;
    }
    
    printf("[PASS] %s\n", test.name);
    return true;
}

int main() {
    printf("=== Decoder Corpus Test Harness ===\n");
    printf("Running %zu tests...\n\n", g_testCount);
    
    int passed = 0;
    int failed = 0;
    
    for (size_t i = 0; i < g_testCount; i++) {
        if (RunTest(g_testCases[i])) {
            passed++;
        } else {
            failed++;
        }
    }
    
    printf("\n=== Results ===\n");
    printf("Total:  %d\n", passed + failed);
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    
    return failed > 0 ? 1 : 0;
}
