// ============================================================================
// optimizer/sme2_spmv_scheduler.hpp - Pipelined Register Scheduler for SpMV
// 3-stage software pipeline: prefetch, dequantize, outer-product accumulate
// ============================================================================

#include <cstdint>
#include <vector>
#include <string>

#ifndef SME2_SPMV_SCHEDULER_H
#define SME2_SPMV_SCHEDULER_H

enum class InstructionClass {
    LOAD_PACKED_INDEX,  // LD1B
    LOAD_ACTIVATION,    // LD1W VG4
    DEQUANTIZE_LUTI,    // LUTI4 / LUTI2 VG4
    OUTER_PRODUCT_MATH  // FMOPA VG4
};

struct ScheduledInstruction {
    uint32_t         cycle_stage;
    InstructionClass type;
    uint32_t         dst_reg;
    uint32_t         src_reg;
    uint32_t         imm_offset;
    std::string      disasm;
};

class SME2SpMVScheduler {
private:
    static constexpr uint32_t LATENCY_LD1B  = 4;
    static constexpr uint32_t LATENCY_LUTI4 = 3;
    static constexpr uint32_t LATENCY_FMOPA = 2;

public:
    // Generate 3-stage software pipelined IR schedule for SpMV
    static std::vector<ScheduledInstruction> SchedulePipelinedLoop(
        QuantPrecision precision,
        uint32_t unroll_factor = 1)
    {
        std::vector<ScheduledInstruction> schedule;

        for (uint32_t u = 0; u < unroll_factor; ++u) {
            uint32_t z_base = u * 16; // Register base for unrolled iteration

            // Stage 0: Memory Prefetch (Iteration K+1)
            schedule.push_back({
                0, InstructionClass::LOAD_PACKED_INDEX,
                z_base + 0, 0, 0,
                "LD1B { Z" + std::to_string(z_base) + ".B }, P0/Z, [X1, X_OFF]"
            });
            schedule.push_back({
                0, InstructionClass::LOAD_ACTIVATION,
                z_base + 8, 0, 0,
                "LD1W { Z" + std::to_string(z_base + 8) + ".S - Z" +
                std::to_string(z_base + 11) + ".S }, P0/Z, [X2, X_OFF]"
            });

            // Stage 1: Hardware Dequantization (Iteration K)
            if (precision == QuantPrecision::INT4) {
                schedule.push_back({
                    1, InstructionClass::DEQUANTIZE_LUTI,
                    z_base + 4, z_base + 0, 0,
                    "LUTI4 { Z" + std::to_string(z_base + 4) +
                    ".S - Z" + std::to_string(z_base + 7) +
                    ".S }, ZT0, Z" + std::to_string(z_base) + ".B, #0"
                });
                schedule.push_back({
                    1, InstructionClass::DEQUANTIZE_LUTI,
                    z_base + 12, z_base + 0, 1,
                    "LUTI4 { Z" + std::to_string(z_base + 12) +
                    ".S - Z" + std::to_string(z_base + 15) +
                    ".S }, ZT0, Z" + std::to_string(z_base) + ".B, #1"
                });
            } else {
                schedule.push_back({
                    1, InstructionClass::DEQUANTIZE_LUTI,
                    z_base + 4, z_base + 0, 0,
                    "LUTI2 { Z" + std::to_string(z_base + 4) +
                    ".S - Z" + std::to_string(z_base + 7) +
                    ".S }, ZT0, Z" + std::to_string(z_base) + ".B, #0"
                });
            }

            // Stage 2: Outer Product Compute (Iteration K-1)
            schedule.push_back({
                2, InstructionClass::OUTER_PRODUCT_MATH,
                0, z_base + 4, 0,
                "FMOPA ZA0.S, P0/M, P0/M, Z" +
                std::to_string(z_base + 4) + ".S-Z" +
                std::to_string(z_base + 7) + ".S, Z" +
                std::to_string(z_base + 8) + ".S-Z" +
                std::to_string(z_base + 11) + ".S"
            });

            if (precision == QuantPrecision::INT4) {
                schedule.push_back({
                    2, InstructionClass::OUTER_PRODUCT_MATH,
                    1, z_base + 12, 0,
                    "FMOPA ZA1.S, P0/M, P0/M, Z" +
                    std::to_string(z_base + 12) + ".S-Z" +
                    std::to_string(z_base + 15) + ".S, Z" +
                    std::to_string(z_base + 8) + ".S-Z" +
                    std::to_string(z_base + 11) + ".S"
                });
            }
        }

        return schedule;
    }
};

#endif // SME2_SPMV_SCHEDULER_H
