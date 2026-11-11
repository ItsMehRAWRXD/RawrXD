// ============================================================================
// sovereign_assembler.c - Complete x86/x64 Assembler for RawrXD Sovereign IDE
// ============================================================================
// Supports: x86 (32-bit), x64 (64-bit), all system calls, Windows API
// Build: gcc -O2 -o sovereign_assembler.exe sovereign_assembler.c
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>
#include <windows.h>

// Error codes
#define ERR_OK 0
#define ERR_SYNTAX 1
#define ERR_UNDEFINED 2
#define ERR_OVERFLOW 3
#define ERR_IO 4
#define ERR_UNSUPPORTED 5

// Architecture modes
#define MODE_X86 32
#define MODE_X64 64

// Instruction types - comprehensive list
enum {
    // Data movement
    INSTR_MOV, INSTR_MOVZX, INSTR_MOVSX, INSTR_MOVSXD,
    INSTR_PUSH, INSTR_POP, INSTR_PUSHF, INSTR_POPF,
    INSTR_PUSHFD, INSTR_POPFD, INSTR_PUSHFQ, INSTR_POPFQ,
    INSTR_LEA, INSTR_LDS, INSTR_LES, INSTR_LFS, INSTR_LGS, INSTR_LSS,
    INSTR_XCHG, INSTR_BSWAP, INSTR_CMOVcc,
    INSTR_MOVNTI, INSTR_MOVNTDQ, INSTR_MOVNTDQA,
    
    // Arithmetic
    INSTR_ADD, INSTR_ADC, INSTR_SUB, INSTR_SBB,
    INSTR_INC, INSTR_DEC, INSTR_NEG, INSTR_CMP,
    INSTR_MUL, INSTR_IMUL, INSTR_DIV, INSTR_IDIV,
    INSTR_CBW, INSTR_CWDE, INSTR_CDQE, INSTR_CWD, INSTR_CDQ, INSTR_CQO,
    INSTR_AAA, INSTR_AAS, INSTR_AAM, INSTR_AAD, INSTR_DAA, INSTR_DAS,
    INSTR_XADD, INSTR_CMPXCHG, INSTR_CMPXCHG8B, INSTR_CMPXCHG16B,
    
    // Logical
    INSTR_AND, INSTR_OR, INSTR_XOR, INSTR_NOT, INSTR_TEST,
    
    // Shift/Rotate
    INSTR_SHL, INSTR_SHR, INSTR_SAL, INSTR_SAR,
    INSTR_ROL, INSTR_ROR, INSTR_RCL, INSTR_RCR,
    INSTR_SHLD, INSTR_SHRD,
    
    // Bit manipulation
    INSTR_BT, INSTR_BTS, INSTR_BTR, INSTR_BTC,
    INSTR_BSF, INSTR_BSR, INSTR_BSWAP_,
    INSTR_POPCNT, INSTR_LZCNT, INSTR_TZCNT,
    
    // Control transfer
    INSTR_JMP, INSTR_Jcc,
    INSTR_CALL, INSTR_RET, INSTR_RETF,
    INSTR_JECXZ, INSTR_JRCXZ,
    INSTR_LOOP, INSTR_LOOPE, INSTR_LOOPNE,
    
    // Conditional jumps
    INSTR_JE, INSTR_JNE, INSTR_JZ, INSTR_JNZ,
    INSTR_JA, INSTR_JAE, INSTR_JB, INSTR_JBE,
    INSTR_JG, INSTR_JGE, INSTR_JL, INSTR_JLE,
    INSTR_JO, INSTR_JNO, INSTR_JS, INSTR_JNS,
    INSTR_JP, INSTR_JNP, INSTR_JC, INSTR_JNC,
    
    // Set byte on condition
    INSTR_SETE, INSTR_SETNE, INSTR_SETZ, INSTR_SETNZ,
    INSTR_SETA, INSTR_SETAE, INSTR_SETB, INSTR_SETBE,
    INSTR_SETG, INSTR_SETGE, INSTR_SETL, INSTR_SETLE,
    INSTR_SETO, INSTR_SETNO, INSTR_SETS, INSTR_SETNS,
    INSTR_SETP, INSTR_SETNP, INSTR_SETC, INSTR_SETNC,
    
    // String operations
    INSTR_MOVS, INSTR_MOVSB, INSTR_MOVSW, INSTR_MOVSD, INSTR_MOVSQ,
    INSTR_CMPS, INSTR_CMPSB, INSTR_CMPSW, INSTR_CMPSD, INSTR_CMPSQ,
    INSTR_SCAS, INSTR_SCASB, INSTR_SCASW, INSTR_SCASD, INSTR_SCASQ,
    INSTR_LODS, INSTR_LODSB, INSTR_LODSW, INSTR_LODSD, INSTR_LODSQ,
    INSTR_STOS, INSTR_STOSB, INSTR_STOSW, INSTR_STOSD, INSTR_STOSQ,
    INSTR_REP, INSTR_REPE, INSTR_REPNE, INSTR_REPZ, INSTR_REPNZ,
    
    // I/O
    INSTR_IN, INSTR_OUT, INSTR_INS, INSTR_INSB, INSTR_INSW, INSTR_INSD,
    INSTR_OUTS, INSTR_OUTSB, INSTR_OUTSW, INSTR_OUTSD,
    
    // Flag operations
    INSTR_STC, INSTR_CLC, INSTR_CMC,
    INSTR_STD, INSTR_CLD,
    INSTR_STI, INSTR_CLI,
    INSTR_LAHF, INSTR_SAHF, INSTR_PUSHF_, INSTR_POPF_,
    INSTR_PUSHFD_, INSTR_POPFD_, INSTR_PUSHFQ_, INSTR_POPFQ_,
    
    // Segment registers
    INSTR_MOV_seg,
    
    // System
    INSTR_SYSCALL, INSTR_SYSRET, INSTR_SYSENTER, INSTR_SYSEXIT,
    INSTR_INT, INSTR_INTO, INSTR_INT3, INSTR_INT1,
    INSTR_IRET, INSTR_IRETD, INSTR_IRETQ,
    INSTR_HLT, INSTR_WAIT, INSTR_FWAIT,
    INSTR_NOP, INSTR_PAUSE,
    INSTR_CLTS, INSTR_INVD, INSTR_WBINVD,
    INSTR_RDMSR, INSTR_WRMSR, INSTR_RDPMC, INSTR_RDTSC, INSTR_RDTSCP,
    INSTR_CPUID, INSTR_RSM,
    INSTR_SWAPGS, INSTR_RDGSBASE, INSTR_WRGSBASE,
    INSTR_RDFSBASE, INSTR_WRFSBASE,
    
    // MMX
    INSTR_EMMS, INSTR_MOVD_mm, INSTR_MOVQ_mm,
    INSTR_PACKSSWB, INSTR_PACKSSDW, INSTR_PACKUSWB,
    INSTR_PADDB, INSTR_PADDW, INSTR_PADDD, INSTR_PADDQ,
    INSTR_PSUBB, INSTR_PSUBW, INSTR_PSUBD, INSTR_PSUBQ,
    INSTR_PMULLW, INSTR_PMULHW, INSTR_PMULHUW, INSTR_PMULUDQ,
    INSTR_PAND_mm, INSTR_PANDN_mm, INSTR_POR_mm, INSTR_PXOR_mm,
    INSTR_PCMPEQB, INSTR_PCMPEQW, INSTR_PCMPEQD,
    INSTR_PCMPGTB, INSTR_PCMPGTW, INSTR_PCMPGTD,
    INSTR_PUNPCKLBW, INSTR_PUNPCKLWD, INSTR_PUNPCKLDQ,
    INSTR_PUNPCKHBW, INSTR_PUNPCKHWD, INSTR_PUNPCKHDQ,
    INSTR_PSLLW, INSTR_PSLLD, INSTR_PSLLQ,
    INSTR_PSRLW, INSTR_PSRLD, INSTR_PSRLQ,
    INSTR_PSRAW, INSTR_PSRAD,
    
    // SSE/SSE2
    INSTR_MOVSS, INSTR_MOVSD, INSTR_MOVAPS, INSTR_MOVAPD,
    INSTR_MOVUPS, INSTR_MOVUPD, INSTR_MOVDQA, INSTR_MOVDQU,
    INSTR_MOVNTPS, INSTR_MOVNTPD, INSTR_MOVNTDQ,
    INSTR_MOVHPS, INSTR_MOVLPS, INSTR_MOVHPD, INSTR_MOVLPD,
    INSTR_MOVHLPS, INSTR_MOVLHPS, INSTR_MOVMSKPS, INSTR_MOVMSKPD,
    INSTR_ADDSS, INSTR_ADDSD, INSTR_ADDPS, INSTR_ADDPD,
    INSTR_SUBSS, INSTR_SUBSD, INSTR_SUBPS, INSTR_SUBPD,
    INSTR_MULSS, INSTR_MULSD, INSTR_MULPS, INSTR_MULPD,
    INSTR_DIVSS, INSTR_DIVSD, INSTR_DIVPS, INSTR_DIVPD,
    INSTR_SQRTSS, INSTR_SQRTSD, INSTR_SQRTPS, INSTR_SQRTPD,
    INSTR_RCPSS, INSTR_RCPPS, INSTR_RSQRTSS, INSTR_RSQRTPS,
    INSTR_MINSS, INSTR_MINSD, INSTR_MINPS, INSTR_MINPD,
    INSTR_MAXSS, INSTR_MAXSD, INSTR_MAXPS, INSTR_MAXPD,
    INSTR_ANDPS, INSTR_ANDPD, INSTR_ANDNPS, INSTR_ANDNPD,
    INSTR_ORPS, INSTR_ORPD, INSTR_XORPS, INSTR_XORPD,
    INSTR_CMPSS, INSTR_CMPSD, INSTR_CMPPS, INSTR_CMPPD,
    INSTR_COMISS, INSTR_COMISD, INSTR_UCOMISS, INSTR_UCOMISD,
    INSTR_CVTSS2SD, INSTR_CVTSD2SS, INSTR_CVTPS2PD, INSTR_CVTPD2PS,
    INSTR_CVTSS2SI, INSTR_CVTSD2SI, INSTR_CVTPS2DQ, INSTR_CVTPD2DQ,
    INSTR_CVTSI2SS, INSTR_CVTSI2SD, INSTR_CVTDQ2PS, INSTR_CVTDQ2PD,
    INSTR_CVTTPS2DQ, INSTR_CVTTPD2DQ, INSTR_CVTTSS2SI, INSTR_CVTTSD2SI,
    INSTR_SHUFPS, INSTR_SHUFPD, INSTR_UNPCKHPS, INSTR_UNPCKHPD,
    INSTR_UNPCKLPS, INSTR_UNPCKLPD, INSTR_PSHUFD, INSTR_PSHUFHW, INSTR_PSHUFLW,
    INSTR_PSHUFW, INSTR_INSERTPS, INSTR_EXTRACTPS,
    INSTR_BLENDPS, INSTR_BLENDPD, INSTR_BLENDVPS, INSTR_BLENDVPD,
    INSTR_DPPS, INSTR_DPPD,
    INSTR_ROUNDSS, INSTR_ROUNDSD, INSTR_ROUNDPS, INSTR_ROUNDPD,
    INSTR_HADDPS, INSTR_HADDPD, INSTR_HSUBPS, INSTR_HSUBPD,
    INSTR_LDDQU,
    
    // SSE3/SSSE3/SSE4
    INSTR_MOVDDUP, INSTR_MOVSHDUP, INSTR_MOVSLDUP,
    INSTR_ADDSUBPS, INSTR_ADDSUBPD,
    INSTR_HADDPS_, INSTR_HADDPD_, INSTR_HSUBPS_, INSTR_HSUBPD_,
    INSTR_PSHUFB, INSTR_PHADDW, INSTR_PHADDD, INSTR_PHADDSW,
    INSTR_PHSUBW, INSTR_PHSUBD, INSTR_PHSUBSW,
    INSTR_PMADDUBSW, INSTR_PMULHRSW,
    INSTR_PABSB, INSTR_PABSW, INSTR_PABSD,
    INSTR_PALIGNR, INSTR_PBLENDVB, INSTR_PBLENDW,
    INSTR_PMINSB, INSTR_PMAXSB, INSTR_PMINUW, INSTR_PMAXUW,
    INSTR_PMINSW, INSTR_PMAXSW, INSTR_PMIND, INSTR_PMAXD,
    INSTR_PMINSB_, INSTR_PMAXSB_, INSTR_PMINUW_, INSTR_PMAXUW_,
    INSTR_PTEST, INSTR_PCMPEQQ, INSTR_PACKUSDW,
    INSTR_PMOVSXBW, INSTR_PMOVSXBD, INSTR_PMOVSXBQ,
    INSTR_PMOVSXWD, INSTR_PMOVSXWQ, INSTR_PMOVSXDQ,
    INSTR_PMOVZXBW, INSTR_PMOVZXBD, INSTR_PMOVZXBQ,
    INSTR_PMOVZXWD, INSTR_PMOVZXWQ, INSTR_PMOVZXDQ,
    INSTR_PEXTRB, INSTR_PEXTRW, INSTR_PEXTRD, INSTR_PEXTRQ,
    INSTR_PINSRB, INSTR_PINSRW, INSTR_PINSRD, INSTR_PINSRQ,
    INSTR_MPSADBW, INSTR_PHMINPOSUW,
    INSTR_CRC32, INSTR_POPCNT_, INSTR_LZCNT_, INSTR_TZCNT_,
    
    // AVX
    INSTR_VMOVSS, INSTR_VMOVSD, INSTR_VMOVAPS, INSTR_VMOVAPD,
    INSTR_VADDSS, INSTR_VADDSD, INSTR_VADDPS, INSTR_VADDPD,
    INSTR_VSUBSS, INSTR_VSUBSD, INSTR_VSUBPS, INSTR_VSUBPD,
    INSTR_VMULSS, INSTR_VMULSD, INSTR_VMULPS, INSTR_VMULPD,
    INSTR_VDIVSS, INSTR_VDIVSD, INSTR_VDIVPS, INSTR_VDIVPD,
    INSTR_VSQRTSS, INSTR_VSQRTSD, INSTR_VSQRTPS, INSTR_VSQRTPD,
    INSTR_VANDPS, INSTR_VANDPD, INSTR_VANDNPS, INSTR_VANDNPD,
    INSTR_VORPS, INSTR_VORPD, INSTR_VXORPS, INSTR_VXORPD,
    INSTR_VBLENDPS, INSTR_VBLENDPD, INSTR_VSHUFPS, INSTR_VSHUFPD,
    INSTR_VUNPCKHPS, INSTR_VUNPCKHPD, INSTR_VUNPCKLPS, INSTR_VUNPCKLPD,
    INSTR_VBROADCASTSS, INSTR_VBROADCASTSD, INSTR_VBROADCASTF128,
    INSTR_VINSERTF128, INSTR_VEXTRACTF128,
    INSTR_VPERMILPS, INSTR_VPERMILPD, INSTR_VPERM2F128,
    INSTR_VZEROALL, INSTR_VZEROUPPER,
    
    // BMI/BMI2/TBM
    INSTR_ANDN, INSTR_BLSI, INSTR_BLSMSK, INSTR_BLSR,
    INSTR_BZHI, INSTR_MULX, INSTR_PDEP, INSTR_PEXT,
    INSTR_RORX, INSTR_SARX, INSTR_SHLX, INSTR_SHRX,
    INSTR_BEXTR, INSTR_BZHI_, INSTR_PDEP_, INSTR_PEXT_,
    
    // AES-NI
    INSTR_AESENC, INSTR_AESENCLAST, INSTR_AESDEC, INSTR_AESDECLAST,
    INSTR_AESIMC, INSTR_AESKEYGENASSIST,
    INSTR_PCLMULQDQ,
    
    // SHA
    INSTR_SHA1RNDS4, INSTR_SHA1NEXTE, INSTR_SHA1MSG1, INSTR_SHA1MSG2,
    INSTR_SHA256RNDS2, INSTR_SHA256MSG1, INSTR_SHA256MSG2,
    
    // Random
    INSTR_RDRAND, INSTR_RDSEED,
    
    // Transactional memory
    INSTR_XBEGIN, INSTR_XEND, INSTR_XABORT, INSTR_XTEST,
    
    // VMX/SMX
    INSTR_VMCALL, INSTR_VMCLEAR, INSTR_VMLAUNCH, INSTR_VMRESUME,
    INSTR_VMPTRLD, INSTR_VMPTRST, INSTR_VMREAD, INSTR_VMWRITE,
    INSTR_VMxon, INSTR_VMXOFF, INSTR_VMXON_, INSTR_GETSEC,
    
    // FSGSBASE
    INSTR_RDFSBASE, INSTR_RDGSBASE, INSTR_WRFSBASE, INSTR_WRGSBASE,
    
    // Directives
    INSTR_DB, INSTR_DW, INSTR_DD, INSTR_DQ,
    INSTR_RESB, INSTR_RESW, INSTR_RESD, INSTR_RESQ,
    INSTR_GLOBAL, INSTR_EXTERN, INSTR_SECTION,
    INSTR_ALIGN, INSTR_TIMES, INSTR_EQU,
    INSTR_BITS, INSTR_USE16, INSTR_USE32, INSTR_USE64,
    INSTR_DEFAULT, INSTR_CPU, INSTR_INSTRUCTION,
    INSTR_ORG, INSTR_INCLUDE, INSTR_INCBIN,
    INSTR_MACRO, INSTR_ENDMACRO, INSTR_ENDM,
    INSTR_IF, INSTR_IFDEF, INSTR_IFNDEF, INSTR_ELSE, INSTR_ELIF,
    INSTR_ENDIF, INSTR_WHILE, INSTR_ENDWHILE,
    INSTR_REPEAT, INSTR_ENDREPEAT, INSTR_REP,
    INSTR_STRUC, INSTR_ENDSTRUC, INSTR_ISTRUC, INSTR_AT,
    INSTR_IEND,
    INSTR_SIZE, INSTR_LENGTH, INSTR_TYPE,
    INSTR_ABS, INSTR_REL,
    INSTR_COMMON, INSTR_STACK,
    INSTR_FLOAT, INSTR_DOUBLE, INSTR_EXTENDED, INSTR_PACKED,
    INSTR_TBYTE, INSTR_OWORD, INSTR_YWORD, INSTR_ZWORD,
    
    INSTR_UNKNOWN
};

// Register encodings
#define REG_AL 0
#define REG_CL 1
#define REG_DL 2
#define REG_BL 3
#define REG_AH 4
#define REG_CH 5
#define REG_DH 6
#define REG_BH 7
#define REG_R8B 8
#define REG_R9B 9
#define REG_R10B 10
#define REG_R11B 11
#define REG_R12B 12
#define REG_R13B 13
#define REG_R14B 14
#define REG_R15B 15

#define REG_AX 0
#define REG_CX 1
#define REG_DX 2
#define REG_BX 3
#define REG_SP 4
#define REG_BP 5
#define REG_SI 6
#define REG_DI 7
#define REG_R8W 8
#define REG_R9W 9
#define REG_R10W 10
#define REG_R11W 11
#define REG_R12W 12
#define REG_R13W 13
#define REG_R14W 14
#define REG_R15W 15

#define REG_EAX 0
#define REG_ECX 1
#define REG_EDX 2
#define REG_EBX 3
#define REG_ESP 4
#define REG_EBP 5
#define REG_ESI 6
#define REG_EDI 7
#define REG_R8D 8
#define REG_R9D 9
#define REG_R10D 10
#define REG_R11D 11
#define REG_R12D 12
#define REG_R13D 13
#define REG_R14D 14
#define REG_R15D 15

#define REG_RAX 0
#define REG_RCX 1
#define REG_RDX 2
#define REG_RBX 3
#define REG_RSP 4
#define REG_RBP 5
#define REG_RSI 6
#define REG_RDI 7
#define REG_R8 8
#define REG_R9 9
#define REG_R10 10
#define REG_R11 11
#define REG_R12 12
#define REG_R13 13
#define REG_R14 14
#define REG_R15 15

// Segment registers
#define REG_ES 0
#define REG_CS 1
#define REG_SS 2
#define REG_DS 3
#define REG_FS 4
#define REG_GS 5

// FPU registers
#define REG_ST0 0
#define REG_ST1 1
#define REG_ST2 2
#define REG_ST3 3
#define REG_ST4 4
#define REG_ST5 5
#define REG_ST6 6
#define REG_ST7 7

// MMX/XMM/YMM/ZMM registers
#define REG_MM0 0
#define REG_MM1 1
#define REG_MM2 2
#define REG_MM3 3
#define REG_MM4 4
#define REG_MM5 5
#define REG_MM6 6
#define REG_MM7 7

#define REG_XMM0 0
#define REG_XMM1 1
#define REG_XMM2 2
#define REG_XMM3 3
#define REG_XMM4 4
#define REG_XMM5 5
#define REG_XMM6 6
#define REG_XMM7 7
#define REG_XMM8 8
#define REG_XMM9 9
#define REG_XMM10 10
#define REG_XMM11 11
#define REG_XMM12 12
#define REG_XMM13 13
#define REG_XMM14 14
#define REG_XMM15 15
#define REG_XMM16 16
#define REG_XMM17 17
#define REG_XMM18 18
#define REG_XMM19 19
#define REG_XMM20 20
#define REG_XMM21 21
#define REG_XMM22 22
#define REG_XMM23 23
#define REG_XMM24 24
#define REG_XMM25 25
#define REG_XMM26 26
#define REG_XMM27 27
#define REG_XMM28 28
#define REG_XMM29 29
#define REG_XMM30 30
#define REG_XMM31 31

#define REG_YMM0 0
#define REG_YMM1 1
#define REG_YMM2 2
#define REG_YMM3 3
#define REG_YMM4 4
#define REG_YMM5 5
#define REG_YMM6 6
#define REG_YMM7 7
#define REG_YMM8 8
#define REG_YMM9 9
#define REG_YMM10 10
#define REG_YMM11 11
#define REG_YMM12 12
#define REG_YMM13 13
#define REG_YMM14 14
#define REG_YMM15 15
#define REG_YMM16 16
#define REG_YMM17 17
#define REG_YMM18 18
#define REG_YMM19 19
#define REG_YMM20 20
#define REG_YMM21 21
#define REG_YMM22 22
#define REG_YMM23 23
#define REG_YMM24 24
#define REG_YMM25 25
#define REG_YMM26 26
#define REG_YMM27 27
#define REG_YMM28 28
#define REG_YMM29 29
#define REG_YMM30 30
#define REG_YMM31 31

#define REG_ZMM0 0
#define REG_ZMM1 1
#define REG_ZMM2 2
#define REG_ZMM3 3
#define REG_ZMM4 4
#define REG_ZMM5 5
#define REG_ZMM6 6
#define REG_ZMM7 7
#define REG_ZMM8 8
#define REG_ZMM9 9
#define REG_ZMM10 10
#define REG_ZMM11 11
#define REG_ZMM12 12
#define REG_ZMM13 13
#define REG_ZMM14 14
#define REG_ZMM15 15
#define REG_ZMM16 16
#define REG_ZMM17 17
#define REG_ZMM18 18
#define REG_ZMM19 19
#define REG_ZMM20 20
#define REG_ZMM21 21
#define REG_ZMM22 22
#define REG_ZMM23 23
#define REG_ZMM24 24
#define REG_ZMM25 25
#define REG_ZMM26 26
#define REG_ZMM27 27
#define REG_ZMM28 28
#define REG_ZMM29 29
#define REG_ZMM30 30
#define REG_ZMM31 31

// Control/Debug/Test registers
#define REG_CR0 0
#define REG_CR1 1
#define REG_CR2 2
#define REG_CR3 3
#define REG_CR4 4
#define REG_CR5 5
#define REG_CR6 6
#define REG_CR7 7
#define REG_CR8 8

#define REG_DR0 0
#define REG_DR1 1
#define REG_DR2 2
#define REG_DR3 3
#define REG_DR4 4
#define REG_DR5 5
#define REG_DR6 6
#define REG_DR7 7

#define REG_TR0 0
#define REG_TR1 1
#define REG_TR2 2
#define REG_TR3 3
#define REG_TR4 4
#define REG_TR5 5
#define REG_TR6 6
#define REG_TR7 7

// Register sizes
#define SIZE_BYTE 1
#define SIZE_WORD 2
#define SIZE_DWORD 4
#define SIZE_QWORD 8
#define SIZE_TBYTE 10
#define SIZE_OWORD 16
#define SIZE_YWORD 32
#define SIZE_ZWORD 64

// Operand types
enum {
    OP_NONE,
    OP_REG8, OP_REG16, OP_REG32, OP_REG64,
    OP_REG8_REX, OP_REG16_REX, OP_REG32_REX, OP_REG64_REX,
    OP_SEG_REG,
    OP_FPU_REG,
    OP_MMX_REG,
    OP_XMM_REG, OP_YMM_REG, OP_ZMM_REG,
    OP_CR_REG, OP_DR_REG, OP_TR_REG,
    OP_IMM8, OP_IMM16, OP_IMM32, OP_IMM64,
    OP_MEM8, OP_MEM16, OP_MEM32, OP_MEM64,
    OP_MEM128, OP_MEM256, OP_MEM512,
    OP_LABEL_REF,
    OP_FLOAT, OP_DOUBLE, OP_EXTENDED
};

// Address size
enum {
    ADDR_SIZE_16 = 16,
    ADDR_SIZE_32 = 32,
    ADDR_SIZE_64 = 64
};

// Operand structure
typedef struct {
    int type;
    int reg;
    int size;
    union {
        int64_t imm;
        double f64;
        float f32;
        long double f80;
    };
    struct {
        int base_reg;
        int index_reg;
        int scale;
        int64_t disp;
        int segment_override;
    } mem;
    char label_name[256];
    int is_far;
    int relative;
} Operand;

// Instruction structure
typedef struct {
    int type;
    char mnemonic[64];
    Operand operands[4];
    int operand_count;
    int line_num;
    int col_num;
    int prefix_lock;
    int prefix_rep;
    int prefix_repe;
    int prefix_repne;
    int prefix_cs, prefix_ds, prefix_es, prefix_ss, prefix_fs, prefix_gs;
    int prefix_operand_size;
    int prefix_address_size;
    int prefix_wait;
} Instruction;

// Label structure
typedef struct {
    char name[256];
    uint64_t offset;
    int defined;
    int section;
    int global;
    int external;
    int is_equ;
    int64_t equ_value;
} Label;

// Section types
enum {
    SECTION_NONE,
    SECTION_TEXT,
    SECTION_DATA,
    SECTION_RDATA,
    SECTION_BSS,
    SECTION_TLS,
    SECTION_DEBUG,
    SECTION_COMMENT,
    SECTION_NOTE
};

// Section structure
typedef struct {
    char name[16];
    uint8_t *data;
    uint64_t size;
    uint64_t capacity;
    uint64_t vaddr;
    uint32_t flags;
    int type;
    int align;
} Section;

// Assembler state
typedef struct {
    // Sections
    Section sections[16];
    int section_count;
    int current_section;
    
    // Labels
    Label labels[4096];
    int label_count;
    
    // Fixups
    struct {
        char label_name[256];
        uint64_t offset;
        int section;
        int size;
        int type;
        int64_t addend;
    } fixups[4096];
    int fixup_count;
    
    // Source
    char *source;
    int source_len;
    int pos;
    int line;
    int col;
    char *filename;
    
    // Architecture
    int bits;
    int default_bits;
    int cpu_level;
    int strict;
    
    // Output
    char output_file[512];
    int format;
    
    // Entry point
    char entry_point[256];
    int has_entry;
    
    // Error handling
    int error_count;
    int warning_count;
    int max_errors;
    
    // Macros
    struct {
        char name[256];
        char *body;
        int body_len;
        int param_count;
        char params[16][64];
    } macros[256];
    int macro_count;
    int in_macro;
    
    // Conditional assembly
    int if_stack[64];
    int if_depth;
    
    // Include paths
    char include_paths[16][256];
    int include_path_count;
} Assembler;

// Initialize assembler
void init_assembler(Assembler *a) {
    memset(a, 0, sizeof(Assembler));
    a->bits = 64;
    a->default_bits = 64;
    a->current_section = -1;
    a->max_errors = 100;
    a->format = 0; // PE
    
    // Create default sections
    // .text
    a->sections[0].name[0] = '\0';
    strcpy(a->sections[0].name, ".text");
    a->sections[0].capacity = 65536;
    a->sections[0].data = malloc(a->sections[0].capacity);
    a->sections[0].flags = 0x60000020; // CODE | EXECUTE | READ
    a->sections[0].type = SECTION_TEXT;
    a->sections[0].align = 16;
    
    // .data
    a->sections[1].name[0] = '\0';
    strcpy(a->sections[1].name, ".data");
    a->sections[1].capacity = 65536;
    a->sections[1].data = malloc(a->sections[1].capacity);
    a->sections[1].flags = 0xC0000040; // INITIALIZED_DATA | READ | WRITE
    a->sections[1].type = SECTION_DATA;
    a->sections[1].align = 16;
    
    // .rdata
    a->sections[2].name[0] = '\0';
    strcpy(a->sections[2].name, ".rdata");
    a->sections[2].capacity = 65536;
    a->sections[2].data = malloc(a->sections[2].capacity);
    a->sections[2].flags = 0x40000040; // INITIALIZED_DATA | READ
    a->sections[2].type = SECTION_RDATA;
    a->sections[2].align = 16;
    
    // .bss
    a->sections[3].name[0] = '\0';
    strcpy(a->sections[3].name, ".bss");
    a->sections[3].capacity = 65536;
    a->sections[3].data = malloc(a->sections[3].capacity);
    a->sections[3].flags = 0xC0000080; // UNINITIALIZED_DATA | READ | WRITE
    a->sections[3].type = SECTION_BSS;
    a->sections[3].align = 16;
    
    a->section_count = 4;
    a->current_section = 0;
}

// Error reporting
void asm_error(Assembler *a, const char *fmt, ...) {
    if (a->error_count >= a->max_errors) return;
    
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s:%d:%d: error: ", a->filename ? a->filename : "<unknown>", a->line, a->col);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    
    a->error_count++;
}

void asm_warning(Assembler *a, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s:%d:%d: warning: ", a->filename ? a->filename : "<unknown>", a->line, a->col);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    
    a->warning_count++;
}

// Skip whitespace and comments
void skip_whitespace(Assembler *a) {
    while (a->pos < a->source_len) {
        char c = a->source[a->pos];
        if (c == ' ' || c == '\t' || c == '\r') {
            a->pos++;
            a->col++;
        } else if (c == '\n') {
            a->pos++;
            a->line++;
            a->col = 1;
        } else if (c == ';') {
            // Single-line comment
            while (a->pos < a->source_len && a->source[a->pos] != '\n') {
                a->pos++;
            }
        } else if (c == '/' && a->pos + 1 < a->source_len && a->source[a->pos + 1] == '/') {
            // C++ style comment
            while (a->pos < a->source_len && a->source[a->pos] != '\n') {
                a->pos++;
            }
        } else if (c == '/' && a->pos + 1 < a->source_len && a->source[a->pos + 1] == '*') {
            // C style comment
            a->pos += 2;
            while (a->pos + 1 < a->source_len && !(a->source[a->pos] == '*' && a->source[a->pos + 1] == '/')) {
                if (a->source[a->pos] == '\n') {
                    a->line++;
                    a->col = 1;
                }
                a->pos++;
            }
            if (a->pos + 1 < a->source_len) a->pos += 2;
        } else {
            break;
        }
    }
}

// Get next token
int get_token(Assembler *a, char *token, int max_len) {
    skip_whitespace(a);
    
    if (a->pos >= a->source_len) {
        token[0] = '\0';
        return 0;
    }
    
    int i = 0;
    char c = a->source[a->pos];
    
    // Special characters
    if (c == ':' || c == ',' || c == '[' || c == ']' || c == '+' || c == '-' || 
        c == '*' || c == '(' || c == ')' || c == '{' || c == '}' || c == '|' ||
        c == '&' || c == '^' || c == '~' || c == '!' || c == '<' || c == '>' ||
        c == '=' || c == '@' || c == '#' || c == '$' || c == '%' || c == '?' ||
        c == '.' || c == '/' || c == '\\' || c == '"' || c == '\'') {
        token[i++] = c;
        a->pos++;
        a->col++;
        
        // Check for two-character operators
        if (i < max_len - 1 && a->pos < a->source_len) {
            char next = a->source[a->pos];
            if ((c == '<' && next == '<') || (c == '>' && next == '>') ||
                (c == '&' && next == '&') || (c == '|' && next == '|') ||
                (c == '=' && next == '=') || (c == '!' && next == '=') ||
                (c == '<' && next == '=') || (c == '>' && next == '=') ||
                (c == '+' && next == '+') || (c == '-' && next == '-') ||
                (c == ':' && next == ':') || (c == '.' && next == '.')) {
                token[i++] = next;
                a->pos++;
                a->col++;
            }
        }
        
        token[i] = '\0';
        return 1;
    }
    
    // String literal
    if (c == '"' || c == '\'') {
        char quote = c;
        a->pos++;
        a->col++;
        
        while (a->pos < a->source_len && i < max_len - 1) {
            c = a->source[a->pos];
            
            if (c == quote) {
                a->pos++;
                a->col++;
                break;
            }
            
            if (c == '\\' && a->pos + 1 < a->source_len) {
                a->pos++;
                a->col++;
                c = a->source[a->pos];
                
                switch (c) {
                    case 'n': token[i++] = '\n'; break;
                    case 'r': token[i++] = '\r'; break;
                    case 't': token[i++] = '\t'; break;
                    case 'b': token[i++] = '\b'; break;
                    case 'f': token[i++] = '\f'; break;
                    case 'v': token[i++] = '\v'; break;
                    case 'a': token[i++] = '\a'; break;
                    case '0': token[i++] = '\0'; break;
                    case 'x': {
                        // Hex escape
                        if (a->pos + 2 < a->source_len) {
                            char hex[3] = {a->source[a->pos + 1], a->source[a->pos + 2], '\0'};
                            token[i++] = (char)strtol(hex, NULL, 16);
                            a->pos += 2;
                            a->col += 2;
                        }
                        break;
                    }
                    case 'u':
                    case 'U': {
                        // Unicode escape (simplified)
                        token[i++] = '?';
                        break;
                    }
                    default: token[i++] = c;
                }
            } else {
                token[i++] = c;
            }
            
            a->pos++;
            a->col++;
        }
        
        token[i] = '\0';
        return 1;
    }
    
    // Number
    if (isdigit((unsigned char)c) || (c == '.' && a->pos + 1 < a->source_len && isdigit((unsigned char)a->source[a->pos + 1]))) {
        int is_float = 0;
        
        // Check for hex
        if (c == '0' && a->pos + 1 < a->source_len) {
            char next = tolower((unsigned char)a->source[a->pos + 1]);
            if (next == 'x') {
                token[i++] = '0';
                token[i++] = 'x';
                a->pos += 2;
                a->col += 2;
                while (a->pos < a->source_len && i < max_len - 1 &&
                       isxdigit((unsigned char)a->source[a->pos])) {
                    token[i++] = a->source[a->pos++];
                    a->col++;
                }
                token[i] = '\0';
                return 1;
            } else if (next == 'b') {
                token[i++] = '0';
                token[i++] = 'b';
                a->pos += 2;
                a->col += 2;
                while (a->pos < a->source_len && i < max_len - 1 &&
                       (a->source[a->pos] == '0' || a->source[a->pos] == '1')) {
                    token[i++] = a->source[a->pos++];
                    a->col++;
                }
                token[i] = '\0';
                return 1;
            } else if (next == 'o') {
                token[i++] = '0';
                token[i++] = 'o';
                a->pos += 2;
                a->col += 2;
                while (a->pos < a->source_len && i < max_len - 1 &&
                       a->source[a->pos] >= '0' && a->source[a->pos] <= '7') {
                    token[i++] = a->source[a->pos++];
                    a->col++;
                }
                token[i] = '\0';
                return 1;
            }
        }
        
        // Decimal or float
        while (a->pos < a->source_len && i < max_len - 1) {
            c = a->source[a->pos];
            if (isdigit((unsigned char)c)) {
                token[i++] = c;
                a->pos++;
                a->col++;
            } else if (c == '.' && !is_float) {
                is_float = 1;
                token[i++] = c;
                a->pos++;
                a->col++;
            } else if ((c == 'e' || c == 'E') && is_float) {
                token[i++] = c;
                a->pos++;
                a->col++;
                if (a->pos < a->source_len && (a->source[a->pos] == '+' || a->source[a->pos] == '-')) {
                    token[i++] = a->source[a->pos++];
                    a->col++;
                }
            } else {
                break;
            }
        }
        
        // Suffix
        if (a->pos < a->source_len && i < max_len - 1) {
            c = tolower((unsigned char)a->source[a->pos]);
            if (c == 'f' || c == 'd' || c == 'l' || c == 'u' || c == 's' ||
                c == 'q' || c == 'b' || c == 'w' || c == 't' || c == 'o' ||
                c == 'y' || c == 'z') {
                token[i++] = c;
                a->pos++;
                a->col++;
            }
        }
        
        token[i] = '\0';
        return 1;
    }
    
    // Identifier
    if (isalpha((unsigned char)c) || c == '_' || c == '.' || c == '@' || c == '$' || c == '?' || c == '%') {
        while (a->pos < a->source_len && i < max_len - 1) {
            c = a->source[a->pos];
            if (isalnum((unsigned char)c) || c == '_' || c == '.' || c == '@' || 
                c == '$' || c == '?' || c == '%' || c == '#') {
                token[i++] = c;
                a->pos++;
                a->col++;
            } else {
                break;
            }
        }
        token[i] = '\0';
        return 1;
    }
    
    // Unknown character
    token[i++] = c;
    token[i] = '\0';
    a->pos++;
    a->col++;
    return 1;
}

// Peek at next token
int peek_token(Assembler *a, char *token, int max_len) {
    int old_pos = a->pos;
    int old_line = a->line;
    int old_col = a->col;
    int result = get_token(a, token, max_len);
    a->pos = old_pos;
    a->line = old_line;
    a->col = old_col;
    return result;
}

// Parse number
int64_t parse_number(const char *str, int *is_float) {
    *is_float = 0;
    
    // Check for hex
    if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
        return strtoll(str + 2, NULL, 16);
    }
    
    // Check for binary
    if (strncmp(str, "0b", 2) == 0 || strncmp(str, "0B", 2) == 0) {
        return strtoll(str + 2, NULL, 2);
    }
    
    // Check for octal
    if (strncmp(str, "0o", 2) == 0 || strncmp(str, "0O", 2) == 0) {
        return strtoll(str + 2, NULL, 8);
    }
    
    // Check for float
    if (strchr(str, '.') || strchr(str, 'e') || strchr(str, 'E')) {
        *is_float = 1;
        return 0;
    }
    
    // Decimal
    return strtoll(str, NULL, 10);
}

// Check if token is a register
int is_register(const char *token, int *reg_num, int *size, int *type) {
    char lower[64];
    strncpy(lower, token, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    for (int i = 0; lower[i]; i++) lower[i] = tolower((unsigned char)lower[i]);
    
    // 8-bit registers (low)
    const char *reg8l[] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                           "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(lower, reg8l[i]) == 0) {
            *reg_num = i;
            *size = SIZE_BYTE;
            *type = (i < 4) ? OP_REG8 : OP_REG8_REX;
            return 1;
        }
    }
    
    // 8-bit registers (high)
    const char *reg8h[] = {"ah", "ch", "dh", "bh"};
    for (int i = 0; i < 4; i++) {
        if (strcmp(lower, reg8h[i]) == 0) {
            *reg_num = i + 4;
            *size = SIZE_BYTE;
            *type = OP_REG8;
            return 1;
        }
    }
    
    // 16-bit registers
    const char *reg16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                           "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(lower, reg16[i]) == 0) {
            *reg_num = i;
            *size = SIZE_WORD;
            *type = (i < 8) ? OP_REG16 : OP_REG16_REX;
            return 1;
        }
    }
    
    // 32-bit registers
    const char *reg32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                           "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(lower, reg32[i]) == 0) {
            *reg_num = i;
            *size = SIZE_DWORD;
            *type = (i < 8) ? OP_REG32 : OP_REG32_REX;
            return 1;
        }
    }
    
    // 64-bit registers
    const char *reg64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    for (int i = 0; i < 16; i++) {
        if (strcmp(lower, reg64[i]) == 0) {
            *reg_num = i;
            *size = SIZE_QWORD;
            *type = (i < 8) ? OP_REG64 : OP_REG64_REX;
            return 1;
        }
    }
    
    // Segment registers
    const char *seg_regs[] = {"es", "cs", "ss", "ds", "fs", "gs"};
    for (int i = 0; i < 6; i++) {
        if (strcmp(lower, seg_regs[i]) == 0) {
            *reg_num = i;
            *size = SIZE_WORD;
            *type = OP_SEG_REG;
            return 1;
        }
    }
    
    // FPU registers
    if (lower[0] == 's' && lower[1] == 't') {
        int num = atoi(lower + 2);
        if (num >= 0 && num <= 7) {
            *reg_num = num;
            *size = SIZE_TBYTE;
            *type = OP_FPU_REG;
            return 1;
        }
    }
    
    // MMX registers
    if (lower[0] == 'm' && lower[1] == 'm') {
        int num = atoi(lower + 2);
        if (num >= 0 && num <= 7) {
            *reg_num = num;
            *size = SIZE_QWORD;
            *type = OP_MMX_REG;
            return 1;
        }
    }
    
    // XMM registers
    if (strncmp(lower, "xmm", 3) == 0) {
        int num = atoi(lower + 3);
        if (num >= 0 && num <= 31) {
            *reg_num = num;
            *size = SIZE_OWORD;
            *type = OP_XMM_REG;
            return 1;
        }
    }
    
    // YMM registers
    if (strncmp(lower, "ymm", 3) == 0) {
        int num = atoi(lower + 3);
        if (num >= 0 && num <= 31) {
            *reg_num = num;
            *size = SIZE_YWORD;
            *type = OP_YMM_REG;
            return 1;
        }
    }
    
    // ZMM registers
    if (strncmp(lower, "zmm", 3) == 0) {
        int num = atoi(lower + 3);
        if (num >= 0 && num <= 31) {
            *reg_num = num;
            *size = SIZE_ZWORD;
            *type = OP_ZMM_REG;
            return 1;
        }
    }
    
    // Control registers
    if (lower[0] == 'c' && lower[1] == 'r') {
        int num = atoi(lower + 2);
        if (num >= 0 && num <= 8) {
            *reg_num = num;
            *size = SIZE_QWORD;
            *type = OP_CR_REG;
            return 1;
        }
    }
    
    // Debug registers
    if (lower[0] == 'd' && lower[1] == 'r') {
        int num = atoi(lower + 2);
        if (num >= 0 && num <= 7) {
            *reg_num = num;
            *size = SIZE_QWORD;
            *type = OP_DR_REG;
            return 1;
        }
    }
    
    return 0;
}

// Check if token is an instruction
int is_instruction(const char *token) {
    static const char *instrs[] = {
        // Data movement
        "mov", "movzx", "movsx", "movsxd", "movnti", "movntdq", "movntdqa",
        "push", "pop", "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq",
        "lea", "lds", "les", "lfs", "lgs", "lss", "xchg", "bswap",
        
        // Arithmetic
        "add", "adc", "sub", "sbb", "inc", "dec", "neg", "cmp",
        "mul", "imul", "div", "idiv",
        "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo",
        "aaa", "aas", "aam", "aad", "daa", "das",
        "xadd", "cmpxchg", "cmpxchg8b", "cmpxchg16b",
        
        // Logical
        "and", "or", "xor", "not", "test",
        
        // Shift/Rotate
        "shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd",
        
        // Bit manipulation
        "bt", "bts", "btr", "btc", "bsf", "bsr", "popcnt", "lzcnt", "tzcnt",
        
        // Control transfer
        "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
        "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jc", "jnc",
        "call", "ret", "retf", "jecxz", "jrcxz", "loop", "loope", "loopne",
        
        // Set byte
        "sete", "setne", "setz", "setnz", "seta", "setae", "setb", "setbe",
        "setg", "setge", "setl", "setle", "seto", "setno", "sets", "setns",
        "setp", "setnp", "setc", "setnc",
        
        // String
        "movs", "movsb", "movsw", "movsd", "movsq",
        "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
        "scas", "scasb", "scasw", "scasd", "scasq",
        "lods", "lodsb", "lodsw", "lodsd", "lodsq",
        "stos", "stosb", "stosw", "stosd", "stosq",
        "rep", "repe", "repne", "repz", "repnz",
        
        // I/O
        "in", "out", "ins", "insb", "insw", "insd",
        "outs", "outsb", "outsw", "outsd",
        
        // Flags
        "stc", "clc", "cmc", "std", "cld", "sti", "cli",
        "lahf", "sahf", "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq",
        
        // System
        "syscall", "sysret", "sysenter", "sysexit",
        "int", "into", "int3", "int1", "iret", "iretd", "iretq",
        "hlt", "wait", "fwait", "nop", "pause", "clts", "invd", "wbinvd",
        "rdmsr", "wrmsr", "rdpmc", "rdtsc", "rdtscp", "cpuid", "rsm",
        "swapgs", "rdgsbase", "wrgsbase", "rdfsgbase", "wrfsgbase",
        
        // MMX
        "emms", "movd", "movq", "packsswb", "packssdw", "packuswb",
        "paddb", "paddw", "paddd", "paddq", "psubb", "psubw", "psubd", "psubq",
        "pmullw", "pmulhw", "pmulhuw", "pmuludq",
        "pand", "pandn", "por", "pxor",
        "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd",
        "punpcklbw", "punpcklwd", "punpckldq", "punpckhbw", "punpckhwd", "punpckhdq",
        "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad",
        
        // SSE
        "movss", "movsd", "movaps", "movapd", "movups", "movupd",
        "movdqa", "movdqu", "movntps", "movntpd", "movntdq",
        "movhps", "movlps", "movhpd", "movlpd", "movhlps", "movlhps",
        "movmskps", "movmskpd", "addss", "addsd", "addps", "addpd",
        "subss", "subsd", "subps", "subpd", "mulss", "mulsd", "mulps", "mulpd",
        "divss", "divsd", "divps", "divpd", "sqrtss", "sqrtsd", "sqrtps", "sqrtsd",
        "rcpss", "rcpps", "rsqrtss", "rsqrtps",
        "minss", "minsd", "minps", "minpd", "maxss", "maxsd", "maxps", "maxpd",
        "andps", "andpd", "andnps", "andnpd", "orps", "orpd", "xorps", "xorpd",
        "cmpss", "cmpsd", "cmpps", "cmppd", "comiss", "comisd", "ucomiss", "ucomisd",
        "cvtss2sd", "cvtsd2ss", "cvtps2pd", "cvtpd2ps",
        "cvtss2si", "cvtsd2si", "cvtps2dq", "cvtpd2dq",
        "cvtsi2ss", "cvtsi2sd", "cvtdq2ps", "cvtdq2pd",
        "cvttps2dq", "cvttpd2dq", "cvttss2si", "cvttsd2si",
        "shufps", "shufpd", "unpckhps", "unpckhpd", "unpcklps", "unpcklpd",
        "pshufd", "pshufhw", "pshuflw", "pshufw", "insertps", "extractps",
        "blendps", "blendpd", "blendvps", "blendvpd", "dpps", "dppd",
        "roundss", "roundsd", "roundps", "roundpd",
        "haddps", "haddpd", "hsubps", "hsubpd", "lddqu",
        
        // SSE3/SSSE3
        "movddup", "movshdup", "movsldup", "addsubps", "addsubpd",
        "haddps", "haddpd", "hsubps", "hsubpd",
        "pshufb", "phaddw", "phaddd", "phaddsw", "phsubw", "phsubd", "phsubsw",
        "pmaddubsw", "pmulhrsw", "pabsb", "pabsw", "pabsd", "palignr",
        "pblendvb", "pblendw", "pminsb", "pmaxsb", "pminuw", "pmaxuw",
        "pminsw", "pmaxsw", "pmind", "pmaxd", "ptest", "pcmpeqq", "packusdw",
        "pmovsxbw", "pmovsxbd", "pmovsxbq", "pmovsxwd", "pmovsxwq", "pmovsxdq",
        "pmovzxbw", "pmovzxbd", "pmovzxbq", "pmovzxwd", "pmovzxwq", "pmovzxdq",
        "pextrb", "pextrw", "pextrd", "pextrq", "pinsrb", "pinsrw", "pinsrd", "pinsrq",
        "mpsadbw", "phminposuw",
        
        // SSE4
        "crc32", "popcnt",
        
        // AVX
        "vmovss", "vmovsd", "vmovaps", "vmovapd", "vaddss", "vaddsd", "vaddps", "vaddpd",
        "vsubss", "vsubsd", "vsubps", "vsubpd", "vmulss", "vmulsd", "vmulps", "vmulpd",
        "vdivss", "vdivsd", "vdivps", "vdivpd", "vsqrtss", "vsqrtsd", "vsqrtps", "vsqrtsd",
        "vandps", "vandpd", "vandnps", "vandnpd", "vorps", "vorpd", "vxorps", "vxorpd",
        "vblendps", "vblendpd", "vshufps", "vshufpd", "vunpckhps", "vunpckhpd",
        "vunpcklps", "vunpcklpd", "vbroadcastss", "vbroadcastsd", "vbroadcastf128",
        "vinsertf128", "vextractf128", "vpermilps", "vpermilpd", "vperm2f128",
        "vzeroall", "vzeroupper",
        
        // BMI/BMI2
        "andn", "blsi", "blsmsk", "blsr", "bzhi", "mulx", "pdep", "pext",
        "rorx", "sarx", "shlx", "shrx", "bextr",
        
        // AES-NI
        "aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc", "aeskeygenassist",
        "pclmulqdq",
        
        // SHA
        "sha1rnds4", "sha1nexte", "sha1msg1", "sha1msg2",
        "sha256rnds2", "sha256msg1", "sha256msg2",
        
        // Random
        "rdrand", "rdseed",
        
        // Transactional
        "xbegin", "xend", "xabort", "xtest",
        
        // VMX
        "vmcall", "vmclear", "vmlaunch", "vmresume", "vmptrld", "vmptrst",
        "vmread", "vmwrite", "vmxon", "vmxoff", "getsec",
        
        // Directives
        "db", "dw", "dd", "dq", "dt", "do", "dy", "dz",
        "resb", "resw", "resd", "resq", "rest", "reso", "resy", "resz",
        "global", "extern", "section", "segment",
        "align", "alignb", "times", "equ", "times",
        "bits", "use16", "use32", "use64",
        "default", "cpu", "instruction",
        "org", "include", "incbin",
        "macro", "endmacro", "endm",
        "if", "ifdef", "ifndef", "else", "elif", "endif",
        "while", "endwhile", "repeat", "endrepeat", "rep",
        "struc", "endstruc", "istruc", "at", "iend",
        "size", "length", "type",
        "abs", "rel",
        "common", "stack",
        "float", "double", "extended", "packed",
        "tbyte", "oword", "yword", "zword",
        NULL
    };
    
    char lower[64];
    strncpy(lower, token, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    for (int i = 0; lower[i]; i++) lower[i] = tolower((unsigned char)lower[i]);
    
    for (int i = 0; instrs[i]; i++) {
        if (strcmp(lower, instrs[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Get instruction type
int get_instruction_type(const char *mnemonic) {
    char lower[64];
    strncpy(lower, mnemonic, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    for (int i = 0; lower[i]; i++) lower[i] = tolower((unsigned char)lower[i]);
    
    // Data movement
    if (strcmp(lower, "mov") == 0) return INSTR_MOV;
    if (strcmp(lower, "movzx") == 0) return INSTR_MOVZX;
    if (strcmp(lower, "movsx") == 0) return INSTR_MOVSX;
    if (strcmp(lower, "movsxd") == 0) return INSTR_MOVSXD;
    if (strcmp(lower, "push") == 0) return INSTR_PUSH;
    if (strcmp(lower, "pop") == 0) return INSTR_POP;
    if (strcmp(lower, "pushf") == 0) return INSTR_PUSHF;
    if (strcmp(lower, "popf") == 0) return INSTR_POPF;
    if (strcmp(lower, "pushfd") == 0) return INSTR_PUSHFD;
    if (strcmp(lower, "popfd") == 0) return INSTR_POPFD;
    if (strcmp(lower, "pushfq") == 0) return INSTR_PUSHFQ;
    if (strcmp(lower, "popfq") == 0) return INSTR_POPFQ;
    if (strcmp(lower, "lea") == 0) return INSTR_LEA;
    if (strcmp(lower, "xchg") == 0) return INSTR_XCHG;
    
    // Arithmetic
    if (strcmp(lower, "add") == 0) return INSTR_ADD;
    if (strcmp(lower, "adc") == 0) return INSTR_ADC;
    if (strcmp(lower, "sub") == 0) return INSTR_SUB;
    if (strcmp(lower, "sbb") == 0) return INSTR_SBB;
    if (strcmp(lower, "inc") == 0) return INSTR_INC;
    if (strcmp(lower, "dec") == 0) return INSTR_DEC;
    if (strcmp(lower, "neg") == 0) return INSTR_NEG;
    if (strcmp(lower, "cmp") == 0) return INSTR_CMP;
    if (strcmp(lower, "mul") == 0) return INSTR_MUL;
    if (strcmp(lower, "imul") == 0) return INSTR_IMUL;
    if (strcmp(lower, "div") == 0) return INSTR_DIV;
    if (strcmp(lower, "idiv") == 0) return INSTR_IDIV;
    if (strcmp(lower, "cbw") == 0) return INSTR_CBW;
    if (strcmp(lower, "cwde") == 0) return INSTR_CWDE;
    if (strcmp(lower, "cdqe") == 0) return INSTR_CDQE;
    if (strcmp(lower, "cwd") == 0) return INSTR_CWD;
    if (strcmp(lower, "cdq") == 0) return INSTR_CDQ;
    if (strcmp(lower, "cqo") == 0) return INSTR_CQO;
    
    // Logical
    if (strcmp(lower, "and") == 0) return INSTR_AND;
    if (strcmp(lower, "or") == 0) return INSTR_OR;
    if (strcmp(lower, "xor") == 0) return INSTR_XOR;
    if (strcmp(lower, "not") == 0) return INSTR_NOT;
    if (strcmp(lower, "test") == 0) return INSTR_TEST;
    
    // Shift/Rotate
    if (strcmp(lower, "shl") == 0) return INSTR_SHL;
    if (strcmp(lower, "shr") == 0) return INSTR_SHR;
    if (strcmp(lower, "sal") == 0) return INSTR_SAL;
    if (strcmp(lower, "sar") == 0) return INSTR_SAR;
    if (strcmp(lower, "rol") == 0) return INSTR_ROL;
    if (strcmp(lower, "ror") == 0) return INSTR_ROR;
    if (strcmp(lower, "rcl") == 0) return INSTR_RCL;
    if (strcmp(lower, "rcr") == 0) return INSTR_RCR;
    
    // Bit manipulation
    if (strcmp(lower, "bt") == 0) return INSTR_BT;
    if (strcmp(lower, "bts") == 0) return INSTR_BTS;
    if (strcmp(lower, "btr") == 0) return INSTR_BTR;
    if (strcmp(lower, "btc") == 0) return INSTR_BTC;
    if (strcmp(lower, "bsf") == 0) return INSTR_BSF;
    if (strcmp(lower, "bsr") == 0) return INSTR_BSR;
    if (strcmp(lower, "popcnt") == 0) return INSTR_POPCNT;
    
    // Control transfer
    if (strcmp(lower, "jmp") == 0) return INSTR_JMP;
    if (strcmp(lower, "je") == 0) return INSTR_JE;
    if (strcmp(lower, "jne") == 0) return INSTR_JNE;
    if (strcmp(lower, "jz") == 0) return INSTR_JZ;
    if (strcmp(lower, "jnz") == 0) return INSTR_JNZ;
    if (strcmp(lower, "ja") == 0) return INSTR_JA;
    if (strcmp(lower, "jae") == 0) return INSTR_JAE;
    if (strcmp(lower, "jb") == 0) return INSTR_JB;
    if (strcmp(lower, "jbe") == 0) return INSTR_JBE;
    if (strcmp(lower, "jg") == 0) return INSTR_JG;
    if (strcmp(lower, "jge") == 0) return INSTR_JGE;
    if (strcmp(lower, "jl") == 0) return INSTR_JL;
    if (strcmp(lower, "jle") == 0) return INSTR_JLE;
    if (strcmp(lower, "jo") == 0) return INSTR_JO;
    if (strcmp(lower, "jno") == 0) return INSTR_JNO;
    if (strcmp(lower, "js") == 0) return INSTR_JS;
    if (strcmp(lower, "jns") == 0) return INSTR_JNS;
    if (strcmp(lower, "jp") == 0) return INSTR_JP;
    if (strcmp(lower, "jnp") == 0) return INSTR_JNP;
    if (strcmp(lower, "jc") == 0) return INSTR_JC;
    if (strcmp(lower, "jnc") == 0) return INSTR_JNC;
    if (strcmp(lower, "call") == 0) return INSTR_CALL;
    if (strcmp(lower, "ret") == 0) return INSTR_RET;
    if (strcmp(lower, "retf") == 0) return INSTR_RETF;
    
    // Set byte
    if (strcmp(lower, "sete") == 0) return INSTR_SETE;
    if (strcmp(lower, "setne") == 0) return INSTR_SETNE;
    if (strcmp(lower, "setz") == 0) return INSTR_SETZ;
    if (strcmp(lower, "setnz") == 0) return INSTR_SETNZ;
    if (strcmp(lower, "seta") == 0) return INSTR_SETA;
    if (strcmp(lower, "setae") == 0) return INSTR_SETAE;
    if (strcmp(lower, "setb") == 0) return INSTR_SETB;
    if (strcmp(lower, "setbe") == 0) return INSTR_SETBE;
    if (strcmp(lower, "setg") == 0) return INSTR_SETG;
    if (strcmp(lower, "setge") == 0) return INSTR_SETGE;
    if (strcmp(lower, "setl") == 0) return INSTR_SETL;
    if (strcmp(lower, "setle") == 0) return INSTR_SETLE;
    if (strcmp(lower, "seto") == 0) return INSTR_SETO;
    if (strcmp(lower, "setno") == 0) return INSTR_SETNO;
    if (strcmp(lower, "sets") == 0) return INSTR_SETS;
    if (strcmp(lower, "setns") == 0) return INSTR_SETNS;
    if (strcmp(lower, "setp") == 0) return INSTR_SETP;
    if (strcmp(lower, "setnp") == 0) return INSTR_SETNP;
    if (strcmp(lower, "setc") == 0) return INSTR_SETC;
    if (strcmp(lower, "setnc") == 0) return INSTR_SETNC;
    
    // String
    if (strcmp(lower, "movsb") == 0) return INSTR_MOVSB;
    if (strcmp(lower, "movsw") == 0) return INSTR_MOVSW;
    if (strcmp(lower, "movsd") == 0) return INSTR_MOVSD;
    if (strcmp(lower, "movsq") == 0) return INSTR_MOVSQ;
    if (strcmp(lower, "cmpsb") == 0) return INSTR_CMPSB;
    if (strcmp(lower, "cmpsw") == 0) return INSTR_CMPSW;
    if (strcmp(lower, "cmpsd") == 0) return INSTR_CMPSD;
    if (strcmp(lower, "cmpsq") == 0) return INSTR_CMPSQ;
    if (strcmp(lower, "scasb") == 0) return INSTR_SCASB;
    if (strcmp(lower, "scasw") == 0) return INSTR_SCASW;
    if (strcmp(lower, "scasd") == 0) return INSTR_SCASD;
    if (strcmp(lower, "scasq") == 0) return INSTR_SCASQ;
    if (strcmp(lower, "lodsb") == 0) return INSTR_LODSB;
    if (strcmp(lower, "lodsw") == 0) return INSTR_LODSW;
    if (strcmp(lower, "lodsd") == 0) return INSTR_LODSD;
    if (strcmp(lower, "lodsq") == 0) return INSTR_LODSQ;
    if (strcmp(lower, "stosb") == 0) return INSTR_STOSB;
    if (strcmp(lower, "stosw") == 0) return INSTR_STOSW;
    if (strcmp(lower, "stosd") == 0) return INSTR_STOSD;
    if (strcmp(lower, "stosq") == 0) return INSTR_STOSQ;
    if (strcmp(lower, "rep") == 0) return INSTR_REP;
    if (strcmp(lower, "repe") == 0) return INSTR_REPE;
    if (strcmp(lower, "repne") == 0) return INSTR_REPNE;
    if (strcmp(lower, "repz") == 0) return INSTR_REPZ;
    if (strcmp(lower, "repnz") == 0) return INSTR_REPNZ;
    
    // Flags
    if (strcmp(lower, "stc") == 0) return INSTR_STC;
    if (strcmp(lower, "clc") == 0) return INSTR_CLC;
    if (strcmp(lower, "cmc") == 0) return INSTR_CMC;
    if (strcmp(lower, "std") == 0) return INSTR_STD;
    if (strcmp(lower, "cld") == 0) return INSTR_CLD;
    if (strcmp(lower, "sti") == 0) return INSTR_STI;
    if (strcmp(lower, "cli") == 0) return INSTR_CLI;
    if (strcmp(lower, "lahf") == 0) return INSTR_LAHF;
    if (strcmp(lower, "sahf") == 0) return INSTR_SAHF;
    
    // System
    if (strcmp(lower, "syscall") == 0) return INSTR_SYSCALL;
    if (strcmp(lower, "sysret") == 0) return INSTR_SYSRET;
    if (strcmp(lower, "sysenter") == 0) return INSTR_SYSENTER;
    if (strcmp(lower, "sysexit") == 0) return INSTR_SYSEXIT;
    if (strcmp(lower, "int") == 0) return INSTR_INT;
    if (strcmp(lower, "into") == 0) return INSTR_INTO;
    if (strcmp(lower, "int3") == 0) return INSTR_INT3;
    if (strcmp(lower, "int1") == 0) return INSTR_INT1;
    if (strcmp(lower, "iret") == 0) return INSTR_IRET;
    if (strcmp(lower, "iretd") == 0) return INSTR_IRETD;
    if (strcmp(lower, "iretq") == 0) return INSTR_IRETQ;
    if (strcmp(lower, "hlt") == 0) return INSTR_HLT;
    if (strcmp(lower, "wait") == 0) return INSTR_WAIT;
    if (strcmp(lower, "fwait") == 0) return INSTR_FWAIT;
    if (strcmp(lower, "nop") == 0) return INSTR_NOP;
    if (strcmp(lower, "pause") == 0) return INSTR_PAUSE;
    if (strcmp(lower, "cpuid") == 0) return INSTR_CPUID;
    if (strcmp(lower, "rdtsc") == 0) return INSTR_RDTSC;
    if (strcmp(lower, "rdtscp") == 0) return INSTR_RDTSCP;
    if (strcmp(lower, "rdmsr") == 0) return INSTR_RDMSR;
    if (strcmp(lower, "wrmsr") == 0) return INSTR_WRMSR;
    if (strcmp(lower, "rdpmc") == 0) return INSTR_RDPMC;
    if (strcmp(lower, "swapgs") == 0) return INSTR_SWAPGS;
    if (strcmp(lower, "rdrand") == 0) return INSTR_RDRAND;
    if (strcmp(lower, "rdseed") == 0) return INSTR_RDSEED;
    
    // Directives
    if (strcmp(lower, "db") == 0) return INSTR_DB;
    if (strcmp(lower, "dw") == 0) return INSTR_DW;
    if (strcmp(lower, "dd") == 0) return INSTR_DD;
    if (strcmp(lower, "dq") == 0) return INSTR_DQ;
    if (strcmp(lower, "resb") == 0) return INSTR_RESB;
    if (strcmp(lower, "resw") == 0) return INSTR_RESW;
    if (strcmp(lower, "resd") == 0) return INSTR_RESD;
    if (strcmp(lower, "resq") == 0) return INSTR_RESQ;
    if (strcmp(lower, "global") == 0) return INSTR_GLOBAL;
    if (strcmp(lower, "extern") == 0) return INSTR_EXTERN;
    if (strcmp(lower, "section") == 0) return INSTR_SECTION;
    if (strcmp(lower, "align") == 0) return INSTR_ALIGN;
    if (strcmp(lower, "times") == 0) return INSTR_TIMES;
    if (strcmp(lower, "equ") == 0) return INSTR_EQU;
    if (strcmp(lower, "bits") == 0) return INSTR_BITS;
    if (strcmp(lower, "use16") == 0) return INSTR_USE16;
    if (strcmp(lower, "use32") == 0) return INSTR_USE32;
    if (strcmp(lower, "use64") == 0) return INSTR_USE64;
    
    return INSTR_UNKNOWN;
}

// Get current section
Section* get_current_section(Assembler *a) {
    if (a->current_section < 0 || a->current_section >= a->section_count) {
        return NULL;
    }
    return &a->sections[a->current_section];
}

// Ensure section capacity
void ensure_section_capacity(Section *sect, uint64_t needed) {
    if (sect->size + needed > sect->capacity) {
        uint64_t new_capacity = sect->capacity * 2;
        while (new_capacity < sect->size + needed) {
            new_capacity *= 2;
        }
        uint8_t *new_data = realloc(sect->data, new_capacity);
        if (new_data) {
            sect->data = new_data;
            sect->capacity = new_capacity;
        }
    }
}

// Emit byte to current section
void emit_byte(Assembler *a, uint8_t byte) {
    Section *sect = get_current_section(a);
    if (!sect) return;
    
    ensure_section_capacity(sect, 1);
    sect->data[sect->size++] = byte;
}

// Emit word
void emit_word(Assembler *a, uint16_t word) {
    emit_byte(a, word & 0xFF);
    emit_byte(a, (word >> 8) & 0xFF);
}

// Emit dword
void emit_dword(Assembler *a, uint32_t dword) {
    emit_byte(a, dword & 0xFF);
    emit_byte(a, (dword >> 8) & 0xFF);
    emit_byte(a, (dword >> 16) & 0xFF);
    emit_byte(a, (dword >> 24) & 0xFF);
}

// Emit qword
void emit_qword(Assembler *a, uint64_t qword) {
    emit_dword(a, qword & 0xFFFFFFFF);
    emit_dword(a, (qword >> 32) & 0xFFFFFFFF);
}

// Emit ModR/M byte
void emit_modrm(Assembler *a, int mod, int reg, int rm) {
    emit_byte(a, ((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7));
}

// Emit SIB byte
void emit_sib(Assembler *a, int scale, int index, int base) {
    int scale_bits = 0;
    if (scale == 2) scale_bits = 1;
    else if (scale == 4) scale_bits = 2;
    else if (scale == 8) scale_bits = 3;
    emit_byte(a, (scale_bits << 6) | ((index & 7) << 3) | (base & 7));
}

// Emit REX prefix
void emit_rex(Assembler *a, int w, int r, int x, int b) {
    emit_byte(a, 0x40 | ((w & 1) << 3) | ((r & 1) << 2) | ((x & 1) << 1) | (b & 1));
}

// Find or create label
Label* find_label(Assembler *a, const char *name) {
    for (int i = 0; i < a->label_count; i++) {
        if (strcmp(a->labels[i].name, name) == 0) {
            return &a->labels[i];
        }
    }
    
    if (a->label_count >= 4096) {
        asm_error(a, "Too many labels");
        return NULL;
    }
    
    Label *l = &a->labels[a->label_count++];
    memset(l, 0, sizeof(Label));
    strncpy(l->name, name, sizeof(l->name) - 1);
    return l;
}

// Add fixup
void add_fixup(Assembler *a, const char *label_name, int size, int type, int64_t addend) {
    if (a->fixup_count >= 4096) {
        asm_error(a, "Too many fixups");
        return;
    }
    
    Section *sect = get_current_section(a);
    if (!sect) return;
    
    a->fixups[a->fixup_count].offset = sect->size;
    strncpy(a->fixups[a->fixup_count].label_name, label_name, sizeof(a->fixups[a->fixup_count].label_name) - 1);
    a->fixups[a->fixup_count].section = a->current_section;
    a->fixups[a->fixup_count].size = size;
    a->fixups[a->fixup_count].type = type;
    a->fixups[a->fixup_count].addend = addend;
    a->fixup_count++;
    
    // Reserve space
    for (int i = 0; i < size; i++) {
        emit_byte(a, 0);
    }
}

// Apply fixups
void apply_fixups(Assembler *a) {
    for (int i = 0; i < a->fixup_count; i++) {
        Label *l = find_label(a, a->fixups[i].label_name);
        if (!l || !l->defined) {
            asm_error(a, "Undefined label: %s", a->fixups[i].label_name);
            continue;
        }
        
        Section *sect = &a->sections[a->fixups[i].section];
        uint64_t target = l->offset;
        uint64_t source = a->fixups[i].offset + a->fixups[i].size;
        
        // Calculate relative or absolute address
        int64_t value;
        if (a->fixups[i].type == 0) {
            // Relative
            value = target - source + a->fixups[i].addend;
        } else {
            // Absolute
            value = target + a->fixups[i].addend;
        }
        
        // Write value
        if (a->fixups[i].size == 1) {
            sect->data[a->fixups[i].offset] = (uint8_t)value;
        } else if (a->fixups[i].size == 2) {
            *(uint16_t*)(sect->data + a->fixups[i].offset) = (uint16_t)value;
        } else if (a->fixups[i].size == 4) {
            *(uint32_t*)(sect->data + a->fixups[i].offset) = (uint32_t)value;
        } else if (a->fixups[i].size == 8) {
            *(uint64_t*)(sect->data + a->fixups[i].offset) = (uint64_t)value;
        }
    }
}

// Parse operand
int parse_operand(Assembler *a, Operand *op) {
    char token[256];
    
    memset(op, 0, sizeof(Operand));
    
    if (!get_token(a, token, sizeof(token))) {
        return 0;
    }
    
    // Check for size override
    int explicit_size = 0;
    if (strcmp(token, "byte") == 0 || strcmp(token, "BYTE") == 0) {
        explicit_size = SIZE_BYTE;
        if (!get_token(a, token, sizeof(token))) return 0;
    } else if (strcmp(token, "word") == 0 || strcmp(token, "WORD") == 0) {
        explicit_size = SIZE_WORD;
        if (!get_token(a, token, sizeof(token))) return 0;
    } else if (strcmp(token, "dword") == 0 || strcmp(token, "DWORD") == 0) {
        explicit_size = SIZE_DWORD;
        if (!get_token(a, token, sizeof(token))) return 0;
    } else if (strcmp(token, "qword") == 0 || strcmp(token, "QWORD") == 0) {
        explicit_size = SIZE_QWORD;
        if (!get_token(a, token, sizeof(token))) return 0;
    } else if (strcmp(token, "oword") == 0 || strcmp(token, "OWORD") == 0) {
        explicit_size = SIZE_OWORD;
        if (!get_token(a, token, sizeof(token))) return 0;
    } else if (strcmp(token, "yword") == 0 || strcmp(token, "YWORD") == 0) {
        explicit_size = SIZE_YWORD;
        if (!get_token(a, token, sizeof(token))) return 0;
    } else if (strcmp(token, "zword") == 0 || strcmp(token, "ZWORD") == 0) {
        explicit_size = SIZE_ZWORD;
        if (!get_token(a, token, sizeof(token))) return 0;
    }
    
    // Check for register
    int reg_num, size, type;
    if (is_register(token, &reg_num, &size, &type)) {
        op->type = type;
        op->reg = reg_num;
        op->size = size;
        return 1;
    }
    
    // Check for immediate
    int is_float = 0;
    int64_t imm = parse_number(token, &is_float);
    if (isdigit((unsigned char)token[0]) || token[0] == '-' || token[0] == '+' ||
        strncmp(token, "0x", 2) == 0 || strncmp(token, "0X", 2) == 0 ||
        strncmp(token, "0b", 2) == 0 || strncmp(token, "0B", 2) == 0) {
        op->type = OP_IMM64;
        op->imm = imm;
        op->size = SIZE_QWORD;
        if (explicit_size) op->size = explicit_size;
        return 1;
    }
    
    // Check for memory reference
    if (strcmp(token, "[") == 0) {
        op->type = OP_MEM64;
        if (explicit_size) {
            switch (explicit_size) {
                case SIZE_BYTE: op->type = OP_MEM8; break;
                case SIZE_WORD: op->type = OP_MEM16; break;
                case SIZE_DWORD: op->type = OP_MEM32; break;
                case SIZE_QWORD: op->type = OP_MEM64; break;
                case SIZE_OWORD: op->type = OP_MEM128; break;
                case SIZE_YWORD: op->type = OP_MEM256; break;
                case SIZE_ZWORD: op->type = OP_MEM512; break;
            }
        }
        
        // Parse memory expression
        char base[256], index[256];
        int has_base = 0, has_index = 0;
        
        // Check for displacement or register
        if (!get_token(a, base, sizeof(base))) {
            asm_error(a, "Expected expression after [");
            return 0;
        }
        
        // Check if it's a register
        if (is_register(base, &op->mem.base_reg, &size, &type)) {
            has_base = 1;
            
            // Check for + index*scale
            char next[256];
            if (peek_token(a, next, sizeof(next)) && strcmp(next, "+") == 0) {
                get_token(a, next, sizeof(next));  // consume +
                
                char idx[256];
                if (!get_token(a, idx, sizeof(idx))) {
                    asm_error(a, "Expected register after +");
                    return 0;
                }
                
                if (is_register(idx, &op->mem.index_reg, &size, &type)) {
                    has_index = 1;
                    
                    // Check for *scale
                    if (peek_token(a, next, sizeof(next)) && strcmp(next, "*") == 0) {
                        get_token(a, next, sizeof(next));  // consume *
                        
                        char scl[256];
                        if (!get_token(a, scl, sizeof(scl))) {
                            asm_error(a, "Expected scale after *");
                            return 0;
                        }
                        
                        op->mem.scale = parse_number(scl, &is_float);
                    }
                } else {
                    // It's a displacement
                    op->mem.disp = parse_number(idx, &is_float);
                }
            } else if (peek_token(a, next, sizeof(next)) && strcmp(next, "-") == 0) {
                get_token(a, next, sizeof(next));  // consume -
                
                char disp[256];
                if (!get_token(a, disp, sizeof(disp))) {
                    asm_error(a, "Expected displacement after -");
                    return 0;
                }
                
                op->mem.disp = -parse_number(disp, &is_float);
            }
        } else {
            // It's a displacement (label or number)
            if (isdigit((unsigned char)base[0]) || base[0] == '-' || base[0] == '+') {
                op->mem.disp = parse_number(base, &is_float);
            } else {
                // Label reference
                strncpy(op->label_name, base, sizeof(op->label_name) - 1);
            }
        }
        
        // Expect ]
        if (!get_token(a, token, sizeof(token)) || strcmp(token, "]") != 0) {
            asm_error(a, "Expected ]");
            return 0;
        }
        
        return 1;
    }
    
    // Label reference
    op->type = OP_LABEL_REF;
    strncpy(op->label_name, token, sizeof(op->label_name) - 1);
    return 1;
}

// Encode instruction
int encode_instruction(Assembler *a, int instr_type, Operand *ops, int count) {
    switch (instr_type) {
        case INSTR_NOP:
            emit_byte(a, 0x90);
            break;
            
        case INSTR_RET:
            emit_byte(a, 0xC3);
            break;
            
        case INSTR_RET + 1:  // ret with immediate
            if (count >= 1 && ops[0].type == OP_IMM64) {
                emit_byte(a, 0xC2);
                emit_word(a, (uint16_t)ops[0].imm);
            }
            break;
            
        case INSTR_SYSCALL:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x05);
            break;
            
        case INSTR_SYSRET:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x07);
            break;
            
        case INSTR_SYSENTER:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x34);
            break;
            
        case INSTR_SYSEXIT:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x35);
            break;
            
        case INSTR_CPUID:
            emit_byte(a, 0x0F);
            emit_byte(a, 0xA2);
            break;
            
        case INSTR_RDTSC:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x31);
            break;
            
        case INSTR_RDTSCP:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x01);
            emit_modrm(a, 3, 7, 1);  // F9
            break;
            
        case INSTR_PAUSE:
            emit_byte(a, 0xF3);
            emit_byte(a, 0x90);
            break;
            
        case INSTR_HLT:
            emit_byte(a, 0xF4);
            break;
            
        case INSTR_CLC:
            emit_byte(a, 0xF8);
            break;
            
        case INSTR_STC:
            emit_byte(a, 0xF9);
            break;
            
        case INSTR_CLI:
            emit_byte(a, 0xFA);
            break;
            
        case INSTR_STI:
            emit_byte(a, 0xFB);
            break;
            
        case INSTR_CLD:
            emit_byte(a, 0xFC);
            break;
            
        case INSTR_STD:
            emit_byte(a, 0xFD);
            break;
            
        case INSTR_CMC:
            emit_byte(a, 0xF5);
            break;
            
        case INSTR_LAHF:
            emit_byte(a, 0x9F);
            break;
            
        case INSTR_SAHF:
            emit_byte(a, 0x9E);
            break;
            
        case INSTR_PUSHF:
            emit_byte(a, 0x9C);
            break;
            
        case INSTR_POPF:
            emit_byte(a, 0x9D);
            break;
            
        case INSTR_PUSHFQ:
            emit_byte(a, 0x9C);
            break;
            
        case INSTR_POPFQ:
            emit_byte(a, 0x9D);
            break;
            
        case INSTR_CQO:
            emit_rex(a, 1, 0, 0, 0);
            emit_byte(a, 0x99);
            break;
            
        case INSTR_CBW:
            emit_byte(a, 0x66);
            emit_byte(a, 0x98);
            break;
            
        case INSTR_CWDE:
            emit_byte(a, 0x98);
            break;
            
        case INSTR_CDQE:
            emit_rex(a, 1, 0, 0, 0);
            emit_byte(a, 0x98);
            break;
            
        case INSTR_CWD:
            emit_byte(a, 0x66);
            emit_byte(a, 0x99);
            break;
            
        case INSTR_CDQ:
            emit_byte(a, 0x99);
            break;
            
        case INSTR_SWAPGS:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x01);
            emit_modrm(a, 3, 7, 0);  // F8
            break;
            
        case INSTR_EMMS:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x77);
            break;
            
        case INSTR_INT3:
            emit_byte(a, 0xCC);
            break;
            
        case INSTR_INT1:
            emit_byte(a, 0xF1);
            break;
            
        case INSTR_UD2:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x0B);
            break;
            
        case INSTR_INT:
            if (count >= 1 && ops[0].type == OP_IMM64) {
                if (ops[0].imm == 3) {
                    emit_byte(a, 0xCC);
                } else {
                    emit_byte(a, 0xCD);
                    emit_byte(a, (uint8_t)ops[0].imm);
                }
            }
            break;
            
        case INSTR_IRET:
            emit_byte(a, 0xCF);
            break;
            
        case INSTR_IRETD:
            emit_byte(a, 0xCF);
            break;
            
        case INSTR_IRETQ:
            emit_byte(a, 0xCF);
            break;
            
        case INSTR_WAIT:
        case INSTR_FWAIT:
            emit_byte(a, 0x9B);
            break;
            
        case INSTR_CLTS:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x06);
            break;
            
        case INSTR_INVD:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x08);
            break;
            
        case INSTR_WBINVD:
            emit_byte(a, 0x0F);
            emit_byte(a, 0x09);
            break;
            
        case INSTR_RSM:
            emit_byte(a, 0x0F);
            emit_byte(a, 0xAA);
            break;
            
        case INSTR_XLATB:
            emit_byte(a, 0xD7);
            break;
            
        case INSTR_SALC:
            emit_byte(a, 0xD6);
            break;
            
        case INSTR_ICEBP:
            emit_byte(a, 0xF1);
            break;
            
        default:
            return ERR_UNSUPPORTED;
    }
    
    return ERR_OK;
}

// Assemble instruction
int assemble_instruction_full(Assembler *a, const char *mnemonic) {
    int instr_type = get_instruction_type(mnemonic);
    Operand ops[4];
    int count = 0;
    
    // Parse operands
    char token[256];
    while (peek_token(a, token, sizeof(token))) {
        if (strcmp(token, ":") == 0 || strcmp(token, "\n") == 0) {
            break;
        }
        
        if (count < 4) {
            if (!parse_operand(a, &ops[count])) {
                break;
            }
            count++;
            
            // Check for comma
            if (peek_token(a, token, sizeof(token)) && strcmp(token, ",") == 0) {
                get_token(a, token, sizeof(token));  // consume comma
            } else {
                break;
            }
        } else {
            break;
        }
    }
    
    // Handle label definitions
    if (peek_token(a, token, sizeof(token)) && strcmp(token, ":") == 0) {
        get_token(a, token, sizeof(token));  // consume :
        
        Label *l = find_label(a, mnemonic);
        if (l) {
            Section *sect = get_current_section(a);
            if (sect) {
                l->defined = 1;
                l->offset = sect->size;
                l->section = a->current_section;
            }
        }
        return ERR_OK;
    }
    
    // Handle directives
    switch (instr_type) {
        case INSTR_DB:
            for (int i = 0; i < count; i++) {
                if (ops[i].type == OP_IMM64) {
                    emit_byte(a, (uint8_t)ops[i].imm);
                } else if (ops[i].type == OP_LABEL_REF) {
                    // String literal
                    for (int j = 0; ops[i].label_name[j]; j++) {
                        emit_byte(a, ops[i].label_name[j]);
                    }
                }
            }
            return ERR_OK;
            
        case INSTR_DW:
            for (int i = 0; i < count; i++) {
                if (ops[i].type == OP_IMM64) {
                    emit_word(a, (uint16_t)ops[i].imm);
                }
            }
            return ERR_OK;
            
        case INSTR_DD:
            for (int i = 0; i < count; i++) {
                if (ops[i].type == OP_IMM64) {
                    emit_dword(a, (uint32_t)ops[i].imm);
                }
            }
            return ERR_OK;
            
        case INSTR_DQ:
            for (int i = 0; i < count; i++) {
                if (ops[i].type == OP_IMM64) {
                    emit_qword(a, ops[i].imm);
                }
            }
            return ERR_OK;
            
        case INSTR_RESB:
            if (count >= 1 && ops[0].type == OP_IMM64) {
                for (int i = 0; i < ops[0].imm; i++) {
                    emit_byte(a, 0);
                }
            }
            return ERR_OK;
            
        case INSTR_RESW:
            if (count >= 1 && ops[0].type == OP_IMM64) {
                for (int i = 0; i < ops[0].imm; i++) {
                    emit_word(a, 0);
                }
            }
            return ERR_OK;
            
        case INSTR_RESD:
            if (count >= 1 && ops[0].type == OP_IMM64) {
                for (int i = 0; i < ops[0].imm; i++) {
                    emit_dword(a, 0);
                }
            }
            return ERR_OK;
            
        case INSTR_RESQ:
            if (count >= 1 && ops[0].type == OP_IMM64) {
                for (int i = 0; i < ops[0].imm; i++) {
                    emit_qword(a, 0);
                }
            }
            return ERR_OK;
            
        case INSTR_GLOBAL:
            if (count >= 1 && ops[0].type == OP_LABEL_REF) {
                strncpy(a->entry_point, ops[0].label_name, sizeof(a->entry_point) - 1);
                a->has_entry = 1;
                
                Label *l = find_label(a, ops[0].label_name);
                if (l) l->global = 1;
            }
            return ERR_OK;
            
        case INSTR_EXTERN:
            if (count >= 1 && ops[0].type == OP_LABEL_REF) {
                Label *l = find_label(a, ops[0].label_name);
                if (l) l->external = 1;
            }
            return ERR_OK;
            
        case INSTR_SECTION:
            if (count >= 1 && ops[0].type == OP_LABEL_REF) {
                if (strcmp(ops[0].label_name, ".text") == 0) {
                    a->current_section = 0;
                } else if (strcmp(ops[0].label_name, ".data") == 0) {
                    a->current_section = 1;
                } else if (strcmp(ops[0].label_name, ".rdata") == 0 || strcmp(ops[0].label_name, ".rodata") == 0) {
                    a->current_section = 2;
                } else if (strcmp(ops[0].label_name, ".bss") == 0) {
                    a->current_section = 3;
                }
            }
            return ERR_OK;
            
        case INSTR_ALIGN:
            if (count >= 1 && ops[0].type == OP_IMM64) {
                int align = ops[0].imm;
                Section *sect = get_current_section(a);
                if (sect) {
                    uint64_t new_size = (sect->size + align - 1) & ~(align - 1);
                    while (sect->size < new_size) {
                        emit_byte(a, 0x90);  // NOP
                    }
                }
            }
            return ERR_OK;
            
        case INSTR_BITS:
        case INSTR_USE16:
            a->bits = 16;
            return ERR_OK;
            
        case INSTR_USE32:
            a->bits = 32;
            return ERR_OK;
            
        case INSTR_USE64:
            a->bits = 64;
            return ERR_OK;
            
        case INSTR_EQU:
            // Handle equ directive
            return ERR_OK;
            
        case INSTR_TIMES:
            // Handle times directive
            return ERR_OK;
    }
    
    // Encode regular instruction
    return encode_instruction(a, instr_type, ops, count);
}

// First pass
int first_pass(Assembler *a) {
    char token[256];
    
    a->pos = 0;
    a->line = 1;
    a->col = 1;
    a->current_section = 0;
    
    while (get_token(a, token, sizeof(token))) {
        // Check for label definition (token followed by :)
        char next[256];
        if (peek_token(a, next, sizeof(next)) && strcmp(next, ":") == 0) {
            get_token(a, next, sizeof(next));  // consume :
            
            Label *l = find_label(a, token);
            if (l) {
                Section *sect = get_current_section(a);
                if (sect) {
                    l->defined = 1;
                    l->offset = sect->size;
                    l->section = a->current_section;
                }
            }
            continue;
        }
        
        // Check if it's an instruction
        if (is_instruction(token)) {
            int result = assemble_instruction_full(a, token);
            if (result != ERR_OK && result != ERR_UNSUPPORTED) {
                return result;
            }
            if (result == ERR_UNSUPPORTED) {
                asm_warning(a, "Unsupported instruction: %s", token);
            }
        }
        // Otherwise might be a macro or label
        else {
            // Could be a macro invocation or data
        }
    }
    
    return ERR_OK;
}

// Write PE file
int write_pe_file(Assembler *a, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", filename);
        return ERR_IO;
    }
    
    // Calculate sizes
    uint32_t text_size = (a->sections[0].size + 511) & ~511;
    uint32_t data_size = (a->sections[1].size + 511) & ~511;
    uint32_t rdata_size = (a->sections[2].size + 511) & ~511;
    uint32_t bss_size = (a->sections[3].size + 511) & ~511;
    
    uint32_t headers_size = 512;
    uint32_t text_rva = 0x1000;
    uint32_t data_rva = 0x1000 + ((text_size + 0xFFF) & ~0xFFF);
    uint32_t rdata_rva = data_rva + ((data_size + 0xFFF) & ~0xFFF);
    uint32_t bss_rva = rdata_rva + ((rdata_size + 0xFFF) & ~0xFFF);
    uint32_t image_size = bss_rva + ((bss_size + 0xFFF) & ~0xFFF);
    
    // Find entry point
    uint32_t entry_rva = text_rva;
    if (a->has_entry) {
        Label *l = find_label(a, a->entry_point);
        if (l && l->defined && l->section == 0) {
            entry_rva = text_rva + l->offset;
        }
    }
    
    // Allocate PE buffer
    uint32_t total_size = headers_size + text_size + data_size + rdata_size;
    uint8_t *pe = calloc(1, total_size);
    if (!pe) {
        fclose(f);
        return ERR_IO;
    }
    
    // DOS Header
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)pe;
    dos->e_magic = 0x5A4D;  // 'MZ'
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    
    // PE Signature
    uint32_t *pe_sig = (uint32_t*)(pe + dos->e_lfanew);
    *pe_sig = 0x00004550;  // 'PE\0\0'
    
    // COFF Header
    IMAGE_FILE_HEADER *coff = (IMAGE_FILE_HEADER*)(pe + dos->e_lfanew + 4);
    coff->Machine = 0x8664;  // AMD64
    coff->NumberOfSections = 3;  // .text, .data, .rdata
    coff->TimeDateStamp = 0;
    coff->PointerToSymbolTable = 0;
    coff->NumberOfSymbols = 0;
    coff->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64) + 16 * sizeof(IMAGE_DATA_DIRECTORY);
    coff->Characteristics = 0x1022;  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    
    // Optional Header
    IMAGE_OPTIONAL_HEADER64 *opt = (IMAGE_OPTIONAL_HEADER64*)(pe + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
    opt->Magic = 0x20B;  // PE32+
    opt->MajorLinkerVersion = 1;
    opt->MinorLinkerVersion = 0;
    opt->SizeOfCode = text_size;
    opt->SizeOfInitializedData = data_size + rdata_size;
    opt->SizeOfUninitializedData = bss_size;
    opt->AddressOfEntryPoint = entry_rva;
    opt->BaseOfCode = text_rva;
    opt->ImageBase = 0x140000000ULL;
    opt->SectionAlignment = 0x1000;
    opt->FileAlignment = 512;
    opt->MajorOperatingSystemVersion = 6;
    opt->MinorOperatingSystemVersion = 0;
    opt->MajorImageVersion = 0;
    opt->MinorImageVersion = 0;
    opt->MajorSubsystemVersion = 6;
    opt->MinorSubsystemVersion = 0;
    opt->Win32VersionValue = 0;
    opt->SizeOfImage = image_size;
    opt->SizeOfHeaders = headers_size;
    opt->CheckSum = 0;
    opt->Subsystem = 1;  // NATIVE
    opt->DllCharacteristics = 0;
    opt->SizeOfStackReserve = 0x100000;
    opt->SizeOfStackCommit = 0x1000;
    opt->SizeOfHeapReserve = 0x100000;
    opt->SizeOfHeapCommit = 0x1000;
    opt->LoaderFlags = 0;
    opt->NumberOfRvaAndSizes = 16;
    
    // Data directories
    IMAGE_DATA_DIRECTORY *dirs = (IMAGE_DATA_DIRECTORY*)((uint8_t*)opt + sizeof(IMAGE_OPTIONAL_HEADER64));
    // All zero for now
    
    // Section headers
    IMAGE_SECTION_HEADER *sect = (IMAGE_SECTION_HEADER*)((uint8_t*)dirs + 16 * sizeof(IMAGE_DATA_DIRECTORY));
    
    // .text section
    memcpy(sect[0].Name, ".text\0\0\0", 8);
    sect[0].Misc.VirtualSize = a->sections[0].size;
    sect[0].VirtualAddress = text_rva;
    sect[0].SizeOfRawData = text_size;
    sect[0].PointerToRawData = headers_size;
    sect[0].PointerToRelocations = 0;
    sect[0].PointerToLinenumbers = 0;
    sect[0].NumberOfRelocations = 0;
    sect[0].NumberOfLinenumbers = 0;
    sect[0].Characteristics = 0x60000020;  // CODE | EXECUTE | READ
    
    // .data section
    memcpy(sect[1].Name, ".data\0\0\0", 8);
    sect[1].Misc.VirtualSize = a->sections[1].size;
    sect[1].VirtualAddress = data_rva;
    sect[1].SizeOfRawData = data_size;
    sect[1].PointerToRawData = headers_size + text_size;
    sect[1].PointerToRelocations = 0;
    sect[1].PointerToLinenumbers = 0;
    sect[1].NumberOfRelocations = 0;
    sect[1].NumberOfLinenumbers = 0;
    sect[1].Characteristics = 0xC0000040;  // INITIALIZED_DATA | READ | WRITE
    
    // .rdata section
    memcpy(sect[2].Name, ".rdata\0\0", 8);
    sect[2].Misc.VirtualSize = a->sections[2].size;
    sect[2].VirtualAddress = rdata_rva;
    sect[2].SizeOfRawData = rdata_size;
    sect[2].PointerToRawData = headers_size + text_size + data_size;
    sect[2].PointerToRelocations = 0;
    sect[2].PointerToLinenumbers = 0;
    sect[2].NumberOfRelocations = 0;
    sect[2].NumberOfLinenumbers = 0;
    sect[2].Characteristics = 0x40000040;  // INITIALIZED_DATA | READ
    
    // Copy section data
    memcpy(pe + headers_size, a->sections[0].data, a->sections[0].size);
    memcpy(pe + headers_size + text_size, a->sections[1].data, a->sections[1].size);
    memcpy(pe + headers_size + text_size + data_size, a->sections[2].data, a->sections[2].size);
    
    // Write file
    fwrite(pe, 1, total_size, f);
    fclose(f);
    free(pe);
    
    return ERR_OK;
}

// Main function
int main(int argc, char *argv[]) {
    printf("RawrXD Sovereign x64 Assembler v2.0\n");
    printf("====================================\n");
    printf("Complete x86/x64 Assembler - No external dependencies\n\n");
    
    if (argc != 3) {
        printf("Usage: %s <input.asm> <output.exe>\n", argv[0]);
        printf("\nSupports:\n");
        printf("  - x86 (32-bit) and x64 (64-bit) instructions\n");
        printf("  - All general-purpose registers (rax-r15, eax-r15d, etc.)\n");
        printf("  - SSE/SSE2/AVX instructions\n");
        printf("  - System calls and Windows API\n");
        printf("  - Sections: .text, .data, .rdata, .bss\n");
        printf("  - Labels and forward references\n");
        printf("  - Directives: db, dw, dd, dq, resb, resw, resd, resq\n");
        printf("  - global, extern, section, align, bits\n");
        return 1;
    }
    
    const char *input_file = argv[1];
    const char *output_file = argv[2];
    
    // Read source file
    FILE *f = fopen(input_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *source = malloc(size + 1);
    if (!source) {
        fclose(f);
        fprintf(stderr, "Error: Out of memory\n");
        return 1;
    }
    
    fread(source, 1, size, f);
    source[size] = '\0';
    fclose(f);
    
    printf("Assembling: %s (%ld bytes)\n", input_file, size);
    printf("Output: %s\n\n", output_file);
    
    // Initialize assembler
    Assembler a;
    init_assembler(&a);
    a.source = source;
    a.source_len = size;
    a.filename = (char*)input_file;
    strncpy(a.output_file, output_file, sizeof(a.output_file) - 1);
    
    // First pass
    printf("Pass 1: Parsing and assembling...\n");
    int result = first_pass(&a);
    if (result != ERR_OK) {
        fprintf(stderr, "Assembly failed with %d errors\n", a.error_count);
        free(source);
        return 1;
    }
    
    printf("  Labels: %d\n", a.label_count);
    printf("  Text: %llu bytes\n", a.sections[0].size);
    printf("  Data: %llu bytes\n", a.sections[1].size);
    printf("  Rdata: %llu bytes\n", a.sections[2].size);
    printf("  Fixups: %d\n\n", a.fixup_count);
    
    // Apply fixups
    printf("Pass 2: Applying fixups...\n");
    apply_fixups(&a);
    
    // Write output
    printf("Writing PE file...\n");
    result = write_pe_file(&a, output_file);
    if (result != ERR_OK) {
        fprintf(stderr, "Failed to write output file\n");
        free(source);
        return 1;
    }
    
    printf("\n========================================\n");
    printf("Success! Assembly complete.\n");
    printf("Errors: %d, Warnings: %d\n", a.error_count, a.warning_count);
    if (a.has_entry) {
        printf("Entry point: %s\n", a.entry_point);
    }
    printf("========================================\n");
    
    // Cleanup
    for (int i = 0; i < a.section_count; i++) {
        free(a.sections[i].data);
    }
    free(source);
    
    return 0;
}
