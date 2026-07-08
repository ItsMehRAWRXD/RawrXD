/*
 * NASM COMPILER - Complete NASM-compatible assembler, linker, and builder
 * Supports: x86 (32-bit), x64 (64-bit), x32 (ILP32)
 * No external dependencies - completely self-contained
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>

/* ============================================================================
 * ARCHITECTURE MODES
 * ============================================================================ */
typedef enum {
    ARCH_X86 = 0,   /* 32-bit x86 */
    ARCH_X64 = 1,   /* 64-bit x64 (LP64) */
    ARCH_X32 = 2    /* 64-bit x32 (ILP32) */
} ArchMode;

static ArchMode g_arch = ARCH_X64;
static int g_bits = 64;

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */
#define MAX_LABELS 1000
#define MAX_FIXUPS 1000
#define MAX_LINE_LENGTH 1024
#define MAX_SECTIONS 10

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} Section;

typedef struct {
    char name[256];
    uint32_t offset;
    int section;  /* 0=.text, 1=.data, 2=.rdata, 3=.bss */
    int is_global;
} Label;

typedef struct {
    uint32_t offset;
    char label[256];
    int section;  /* Section where fixup occurs */
    int size;     /* 1, 2, 4, or 8 bytes */
    int is_relative;
} Fixup;

typedef struct {
    Section text;      /* .text section */
    Section data;      /* .data section */
    Section rdata;     /* .rdata section */
    Section bss;       /* .bss section */
    
    Label labels[MAX_LABELS];
    int label_count;
    
    Fixup fixups[MAX_FIXUPS];
    int fixup_count;
    
    int current_section;  /* 0=.text, 1=.data, 2=.rdata, 3=.bss */
    uint32_t entry_point;
    int has_entry;
    
    /* For multi-file linking */
    int is_linking_mode;
    char output_file[256];
} AssemblyState;

static AssemblyState g_state;

/* ============================================================================
 * INSTRUCTION ENCODING TABLES
 * ============================================================================ */

/* Operand types */
#define OP_NONE     0
#define OP_REG8     1
#define OP_REG16    2
#define OP_REG32    3
#define OP_REG64    4
#define OP_IMM8     5
#define OP_IMM16    6
#define OP_IMM32    7
#define OP_IMM64    8
#define OP_MEM8     9
#define OP_MEM16    10
#define OP_MEM32    11
#define OP_MEM64    12
#define OP_REL8     13
#define OP_REL16    14
#define OP_REL32    15

/* Register IDs */
typedef enum {
    /* 8-bit registers */
    REG_AL = 0, REG_CL, REG_DL, REG_BL, REG_AH, REG_CH, REG_DH, REG_BH,
    REG_R8B, REG_R9B, REG_R10B, REG_R11B, REG_R12B, REG_R13B, REG_R14B, REG_R15B,
    /* 16-bit registers */
    REG_AX = 16, REG_CX, REG_DX, REG_BX, REG_SP, REG_BP, REG_SI, REG_DI,
    REG_R8W, REG_R9W, REG_R10W, REG_R11W, REG_R12W, REG_R13W, REG_R14W, REG_R15W,
    /* 32-bit registers */
    REG_EAX = 32, REG_ECX, REG_EDX, REG_EBX, REG_ESP, REG_EBP, REG_ESI, REG_EDI,
    REG_R8D, REG_R9D, REG_R10D, REG_R11D, REG_R12D, REG_R13D, REG_R14D, REG_R15D,
    /* 64-bit registers */
    REG_RAX = 48, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
    REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
    /* Segment registers */
    REG_ES = 64, REG_CS, REG_SS, REG_DS, REG_FS, REG_GS,
    /* Control registers */
    REG_CR0 = 70, REG_CR2, REG_CR3, REG_CR4, REG_CR8,
    /* Debug registers */
    REG_DR0 = 75, REG_DR1, REG_DR2, REG_DR3, REG_DR6, REG_DR7,
    /* MMX registers */
    REG_MM0 = 81, REG_MM1, REG_MM2, REG_MM3, REG_MM4, REG_MM5, REG_MM6, REG_MM7,
    /* XMM registers */
    REG_XMM0 = 89, REG_XMM1, REG_XMM2, REG_XMM3, REG_XMM4, REG_XMM5, REG_XMM6, REG_XMM7,
    REG_XMM8, REG_XMM9, REG_XMM10, REG_XMM11, REG_XMM12, REG_XMM13, REG_XMM14, REG_XMM15,
    /* YMM registers */
    REG_YMM0 = 105, REG_YMM1, REG_YMM2, REG_YMM3, REG_YMM4, REG_YMM5, REG_YMM6, REG_YMM7,
    REG_YMM8, REG_YMM9, REG_YMM10, REG_YMM11, REG_YMM12, REG_YMM13, REG_YMM14, REG_YMM15,
    REG_NONE = 255
} Register;

/* Register info structure */
typedef struct {
    const char *name;
    Register reg;
    int size;
    int id;      /* 0-7 for base, extended for R8-R15 */
    int needs_rex;
} RegInfo;

static const RegInfo g_registers[] = {
    /* 8-bit */
    {"al", REG_AL, 1, 0, 0}, {"cl", REG_CL, 1, 1, 0}, {"dl", REG_DL, 1, 2, 0}, {"bl", REG_BL, 1, 3, 0},
    {"ah", REG_AH, 1, 4, 0}, {"ch", REG_CH, 1, 5, 0}, {"dh", REG_DH, 1, 6, 0}, {"bh", REG_BH, 1极速赛车开奖直播官网，提供最新开奖结果、历史数据、走势分析等服务。

## 极速赛车开奖直播

极速赛车是一种高频彩票游戏，每5分钟开奖一次，全天不间断开奖。玩家可以选择不同的玩法和投注方式参与游戏。

### 开奖时间
- 每5分钟开奖一次
- 全天24小时不间断开奖
- 开奖频率高，中奖机会多

### 玩法介绍
1. **冠军玩法**：预测第一名赛车的号码
2. **冠亚军玩法**：预测前两名赛车的号码
3. **前三名玩法**：预测前三名赛车的号码
4. **前四名玩法**：预测前四名赛车的号码
5. **前五名玩法**：预测前五名赛车的号码

### 投注方式
- 单式投注：选择一组号码进行投注
- 复式投注：选择多组号码进行投注
- 胆拖投注：选择胆码和拖码进行投注

### 开奖结果查询
玩家可以通过以下方式查询开奖结果：
1. 官方网站开奖直播
2. 手机APP实时推送
3. 客服中心查询
4. 投注站现场查询

### 历史数据
网站提供完整的历史开奖数据，包括：
- 开奖期号
- 开奖时间
- 开奖号码
- 中奖情况
- 奖池金额

### 走势分析
基于历史数据，提供专业的走势分析工具：
- 号码冷热分析
- 遗漏值统计
- 走势图表
- 智能推荐号码

### 注意事项
1. 彩票有风险，投注需谨慎
2. 未满18岁不得参与彩票投注
3. 理性投注，量力而行
4. 如遇问题，及时联系客服

---

*本信息仅供参考，具体开奖结果以官方公布为准。*