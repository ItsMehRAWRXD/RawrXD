;=============================================================================
; x64_instructions.inc - Complete x64 Instruction Set for Native Assembler
;=============================================================================
; This file contains ALL x64 instructions needed for language backend generation
; Supports: C, C++, Java, JavaScript, Python, Rust, Go, and 50+ languages
;=============================================================================

;=============================================================================
; SECTION 1: DATA MOVEMENT INSTRUCTIONS
;=============================================================================

; MOV - Move data
; Variants: MOV r64, r64 | MOV r64, imm64 | MOV r64, [mem] | MOV [mem], r64
;           MOV r32, r32 | MOV r32, imm32 | MOV r32, [mem] | MOV [mem], r32
;           MOV r16, r16 | MOV r16, imm16 | MOV r16, [mem] | MOV [mem], r16
;           MOV r8, r8   | MOV r8, imm8   | MOV r8, [mem]  | MOV [mem], r8

; MOVZX - Move with zero extension
; MOVZX r64, r32 | MOVZX r64, r16 | MOVZX r64, r8
; MOVZX r32, r16 | MOVZX r32, r8 | MOVZX r16, r8

; MOVSX - Move with sign extension
; MOVSX r64, r32 | MOVSX r64, r16 | MOVSX r64, r8
; MOVSX r32, r16 | MOVSX r32, r8 | MOVSX r16, r8

; MOVSXD - Move with sign extension (32 to 64)
; MOVSXD r64, r32

; CMOVcc - Conditional move
; CMOVA, CMOVAE, CMOVB, CMOVBE, CMOVC, CMOVE, CMOVG, CMOVGE, CMOVL, CMOVLE
; CMOVNA, CMOVNAE, CMOVNB, CMOVNBE, CMOVNC, CMOVNE, CMOVNG, CMOVNGE
; CMOVNL, CMOVNLE, CMOVNO, CMOVNP, CMOVNS, CMOVNZ, CMOVO, CMOVP, CMOVS, CMOVZ

; XCHG - Exchange
; XCHG r64, r64 | XCHG r64, [mem] | XCHG [mem], r64

; BSWAP - Byte swap
; BSWAP r64 | BSWAP r32

; XADD - Exchange and add
; XADD r64, r64 | XADD [mem], r64

; CMPXCHG - Compare and exchange
; CMPXCHG r64, r64 | CMPXCHG [mem], r64

; CMPXCHG8B/CMPXCHG16B - Compare and exchange 8/16 bytes
; CMPXCHG8B [mem] | CMPXCHG16B [mem]

;=============================================================================
; SECTION 2: ARITHMETIC INSTRUCTIONS
;=============================================================================

; ADD - Addition
; ADD r64, r64 | ADD r64, imm32 | ADD r64, [mem]
; ADD r32, r32 | ADD r32, imm32 | ADD r32, [mem]
; ADD [mem], r64 | ADD [mem], imm32

; ADC - Add with carry
; ADC r64, r64 | ADC r64, imm32 | ADC r64, [mem]

; SUB - Subtraction
; SUB r64, r64 | SUB r64, imm32 | SUB r64, [mem]

; SBB - Subtract with borrow
; SBB r64, r64 | SBB r64, imm32 | SBB r64, [mem]

; IMUL - Signed multiplication
; IMUL r64, r64 | IMUL r64, [mem] | IMUL r64, r64, imm32
; IMUL r32, r32 | IMUL r32, [mem] | IMUL r32, r32, imm32
; IMUL r64 (one operand - RAX * RDX:RAX)
; IMUL r32 (one operand - EAX * EDX:EAX)

; MUL - Unsigned multiplication
; MUL r64 | MUL r32 | MUL [mem]

; IDIV - Signed division
; IDIV r64 | IDIV r32 | IDIV [mem]

; DIV - Unsigned division
; DIV r64 | DIV r32 | DIV [mem]

; INC - Increment
; INC r64 | INC r32 | INC [mem]

; DEC - Decrement
; DEC r64 | DEC r32 | DEC [mem]

; NEG - Two's complement negation
; NEG r64 | NEG r32 | NEG [mem]

; MULX - Unsigned multiply without affecting flags (BMI2)
; MULX r64, r64, r64 | MULX r64, r64, [mem]

;=============================================================================
; SECTION 3: LOGICAL INSTRUCTIONS
;=============================================================================

; AND - Bitwise AND
; AND r64, r64 | AND r64, imm32 | AND r64, [mem]
; AND [mem], r64 | AND [mem], imm32

; OR - Bitwise OR
; OR r64, r64 | OR r64, imm32 | OR r64, [mem]

; XOR - Bitwise XOR
; XOR r64, r64 | XOR r64, imm32 | XOR r64, [mem]

; NOT - Bitwise NOT
; NOT r64 | NOT r32 | NOT [mem]

; TEST - Test bits (AND without storing result)
; TEST r64, r64 | TEST r64, imm32 | TEST [mem], r64

; SHL/SAL - Shift left
; SHL r64, imm8 | SHL r64, CL | SHL [mem], imm8

; SHR - Shift right (logical)
; SHR r64, imm8 | SHR r64, CL | SHR [mem], imm8

; SAR - Shift right (arithmetic)
; SAR r64, imm8 | SAR r64, CL | SAR [mem], imm8

; ROL - Rotate left
; ROL r64, imm8 | ROL r64, CL | ROL [mem], imm8

; ROR - Rotate right
; ROR r64, imm8 | ROR r64, CL | ROR [mem], imm8

; RCL - Rotate through carry left
; RCL r64, imm8 | RCL r64, CL | RCL [mem], imm8

; RCR - Rotate through carry right
; RCR r64, imm8 | RCR r64, CL | RCR [mem], imm8

; SHLD - Double precision shift left
; SHLD r64, r64, imm8 | SHLD [mem], r64, imm8

; SHRD - Double precision shift right
; SHRD r64, r64, imm8 | SHRD [mem], r64, imm8

; ANDN - AND NOT (BMI1)
; ANDN r64, r64, r64 | ANDN r64, r64, [mem]

; BLSI - Extract lowest set isolated bit (BMI1)
; BLSI r64, r64 | BLSI r64, [mem]

; BLSMSK - Get mask up to lowest set bit (BMI1)
; BLSMSK r64, r64 | BLSMSK r64, [mem]

; BLSR - Reset lowest set bit (BMI1)
; BLSR r64, r64 | BLSR r64, [mem]

;=============================================================================
; SECTION 4: CONTROL FLOW INSTRUCTIONS
;=============================================================================

; JMP - Unconditional jump
; JMP label | JMP r64 | JMP [mem]

; Jcc - Conditional jump
; JA, JAE, JB, JBE, JC, JE, JG, JGE, JL, JLE
; JNA, JNAE, JNB, JNBE, JNC, JNE, JNG, JNGE
; JNL, JNLE, JNO, JNP, JNS, JNZ, JO, JP, JS, JZ
; Jcc label (relative)

; CALL - Call procedure
; CALL label | CALL r64 | CALL [mem]

; RET - Return
; RET | RET imm16

; LOOP - Loop with counter
; LOOP label | LOOPZ label | LOOPNZ label

; JRCXZ - Jump if RCX is zero
; JRCXZ label

;=============================================================================
; SECTION 5: COMPARISON INSTRUCTIONS
;=============================================================================

; CMP - Compare
; CMP r64, r64 | CMP r64, imm32 | CMP r64, [mem]
; CMP [mem], r64 | CMP [mem], imm32

; CMPSB/CMPSW/CMPSD/CMPSQ - Compare string operands
; CMPSB | CMPSW | CMPSD | CMPSQ

; SCASB/SCASW/SCASD/SCASQ - Scan string
; SCASB | SCASW | SCASD | SCASQ

;=============================================================================
; SECTION 6: STACK INSTRUCTIONS
;=============================================================================

; PUSH - Push onto stack
; PUSH r64 | PUSH imm32 | PUSH [mem]

; POP - Pop from stack
; POP r64 | POP [mem]

; PUSHA/PUSHAD - Push all general registers (16/32-bit)
; PUSHA | PUSHAD

; POPA/POPAD - Pop all general registers (16/32-bit)
; POPA | POPAD

; PUSHF/PUSHFD/PUSHFQ - Push flags
; PUSHF | PUSHFD | PUSHFQ

; POPF/POPFD/POPFQ - Pop flags
; POPF | POPFD | POPFQ

; ENTER - Build stack frame
; ENTER imm16, imm8

; LEAVE - High-level procedure exit
; LEAVE

;=============================================================================
; SECTION 7: STRING INSTRUCTIONS
;=============================================================================

; MOVS/MOVSB/MOVSW/MOVSD/MOVSQ - Move string
; MOVSB | MOVSW | MOVSD | MOVSQ

; STOS/STOSB/STOSW/STOSD/STOSQ - Store string
; STOSB | STOSW | STOSD | STOSQ

; LODS/LODSB/LODSW/LODSD/LODSQ - Load string
; LODSB | LODSW | LODSD | LODSQ

; REP/REPE/REPZ/REPNE/REPNZ - Repeat prefix
; REP MOVSB | REPE CMPSB | REPNE SCASB

;=============================================================================
; SECTION 8: FLOATING POINT INSTRUCTIONS (x87)
;=============================================================================

; FLD - Load floating point
; FLD m32 | FLD m64 | FLD m80 | FLD ST(i)

; FST/FSTP - Store floating point
; FST m32 | FST m64 | FST ST(i)
; FSTP m32 | FSTP m64 | FSTP m80 | FSTP ST(i)

; FADD/FADDP - Add floating point
; FADD m32 | FADD m64 | FADD ST(i), ST(0) | FADD ST(0), ST(i)
; FADDP ST(i), ST(0)

; FSUB/FSUBP - Subtract floating point
; FSUB m32 | FSUB m64 | FSUB ST(i), ST(0) | FSUB ST(0), ST(i)
; FSUBP ST(i), ST(0)

; FMUL/FMULP - Multiply floating point
; FMUL m32 | FMUL m64 | FMUL ST(i), ST(0) | FMUL ST(0), ST(i)
; FMULP ST(i), ST(0)

; FDIV/FDIVP - Divide floating point
; FDIV m32 | FDIV m64 | FDIV ST(i), ST(0) | FDIV ST(0), ST(i)
; FDIVP ST(i), ST(0)

; FSQRT - Square root
; FSQRT

; FCOM/FCOMP/FCOMPP - Compare floating point
; FCOM m32 | FCOM m64 | FCOM ST(i)
; FCOMP m32 | FCOMP m64 | FCOMP ST(i)
; FCOMPP

; FUCOM/FUCOMP/FUCOMPP - Unordered compare
; FUCOM ST(i) | FUCOMP ST(i) | FUCOMPP

; FCHS - Change sign
; FCHS

; FABS - Absolute value
; FABS

; FPREM - Partial remainder
; FPREM | FPREM1

; FXCH - Exchange registers
; FXCH ST(i)

; FINCSTP/FDECSTP - Increment/decrement stack pointer
; FINCSTP | FDECSTP

; FFREE - Free register
; FFREE ST(i)

; FLD1/FLDZ/FLDPI/FLD2E/FLDL2T/FLDLG2/FLDLN2 - Load constants
; FLD1 | FLDZ | FLDPI | FLD2E | FLDL2T | FLDLG2 | FLDLN2

;=============================================================================
; SECTION 9: SSE INSTRUCTIONS (128-bit)
;=============================================================================

; MOVAPS/MOVUPS - Move aligned/unaligned packed single
; MOVAPS xmm, xmm | MOVAPS xmm, m128 | MOVAPS m128, xmm
; MOVUPS xmm, xmm | MOVUPS xmm, m128 | MOVUPS m128, xmm

; MOVSS - Move scalar single
; MOVSS xmm, xmm | MOVSS xmm, m32 | MOVSS m32, xmm

; MOVAPD/MOVUPD - Move aligned/unaligned packed double
; MOVAPD xmm, xmm | MOVAPD xmm, m128 | MOVAPD m128, xmm
; MOVUPD xmm, xmm | MOVUPD xmm, m128 | MOVUPD m128, xmm

; MOVSD - Move scalar double
; MOVSD xmm, xmm | MOVSD xmm, m64 | MOVSD m64, xmm

; ADDPS/SUBPS/MULPS/DIVPS - Packed single arithmetic
; ADDPS xmm, xmm | ADDPS xmm, m128
; SUBPS xmm, xmm | SUBPS xmm, m128
; MULPS xmm, xmm | MULPS xmm, m128
; DIVPS xmm, xmm | DIVPS xmm, m128

; ADDSS/SUBSS/MULSS/DIVSS - Scalar single arithmetic
; ADDSS xmm, xmm | ADDSS xmm, m32
; SUBSS xmm, xmm | SUBSS xmm, m32
; MULSS xmm, xmm | MULSS xmm, m32
; DIVSS xmm, xmm | DIVSS xmm, m32

; ADDPD/SUBPD/MULPD/DIVPD - Packed double arithmetic
; ADDPD xmm, xmm | ADDPD xmm, m128
; SUBPD xmm, xmm | SUBPD xmm, m128
; MULPD xmm, xmm | MULPD xmm, m128
; DIVPD xmm, xmm | DIVPD xmm, m128

; ADDSD/SUBSD/MULSD/DIVSD - Scalar double arithmetic
; ADDSD xmm, xmm | ADDSD xmm, m64
; SUBSD xmm, xmm | SUBSD xmm, m64
; MULSD xmm, xmm | MULSD xmm, m64
; DIVSD xmm, xmm | DIVSD xmm, m64

; CMPPS/CMPPD/CMPSS/CMPSD - Compare packed/scalar
; CMPPS xmm, xmm, imm8 | CMPPS xmm, m128, imm8
; CMPPD xmm, xmm, imm8 | CMPPD xmm, m128, imm8
; CMPSS xmm, xmm, imm8 | CMPSS xmm, m32, imm8
; CMPSD xmm, xmm, imm8 | CMPSD xmm, m64, imm8

; ANDPS/ANDPD/ORPS/ORPD/XORPS/XORPD - Bitwise logical
; ANDPS xmm, xmm | ANDPS xmm, m128
; ANDPD xmm, xmm | ANDPD xmm, m128
; ORPS xmm, xmm | ORPS xmm, m128
; ORPD xmm, xmm | ORPD xmm, m128
; XORPS xmm, xmm | XORPS xmm, m128
; XORPD xmm, xmm | XORPD xmm, m128

; SHUFPS/SHUFPD - Shuffle packed
; SHUFPS xmm, xmm, imm8 | SHUFPS xmm, m128, imm8
; SHUFPD xmm, xmm, imm8 | SHUFPD xmm, m128, imm8

; UNPCKLPS/UNPCKHPS/UNPCKLPD/UNPCKHPD - Unpack and interleave
; UNPCKLPS xmm, xmm | UNPCKLPS xmm, m128
; UNPCKHPS xmm, xmm | UNPCKHPS xmm, m128
; UNPCKLPD xmm, xmm | UNPCKLPD xmm, m128
; UNPCKHPD xmm, xmm | UNPCKHPD xmm, m128

; CVTPI2PS/CVTPI2PD - Convert packed integer to float/double
; CVTPI2PS xmm, mm | CVTPI2PS xmm, m64
; CVTPI2PD xmm, mm | CVTPI2PD xmm, m64

; CVTPS2PI/CVTPD2PI - Convert packed float/double to integer
; CVTPS2PI mm, xmm | CVTPS2PI mm, m64
; CVTPD2PI mm, xmm | CVTPD2PI mm, m128

; CVTSI2SS/CVTSI2SD - Convert scalar integer to float/double
; CVTSI2SS xmm, r32 | CVTSI2SS xmm, m32
; CVTSI2SD xmm, r32 | CVTSI2SD xmm, m32

; CVTSS2SI/CVTSD2SI - Convert scalar float/double to integer
; CVTSS2SI r32, xmm | CVTSS2SI r32, m32
; CVTSD2SI r32, xmm | CVTSD2SI r32, m64

; CVTTPS2PI/CVTTPD2PI/CVTTSS2SI/CVTTSD2SI - Convert with truncation
; CVTTPS2PI mm, xmm | CVTTPS2PI mm, m64
; CVTTPD2PI mm, xmm | CVTTPD2PI mm, m128
; CVTTSS2SI r32, xmm | CVTTSS2SI r32, m32
; CVTTSD2SI r32, xmm | CVTTSD2SI r32, m64

; COMISS/UCOMISS - Compare scalar single
; COMISS xmm, xmm | COMISS xmm, m32
; UCOMISS xmm, xmm | UCOMISS xmm, m32

; COMISD/UCOMISD - Compare scalar double
; COMISD xmm, xmm | COMISD xmm, m64
; UCOMISD xmm, xmm | UCOMISD xmm, m64

; PAND/POR/PXOR - Packed logical
; PAND mm, mm | PAND mm, m64
; POR mm, mm | POR mm, m64
; PXOR mm, mm | PXOR mm, m64

; PADDQ/PSUBQ - Packed add/subtract quadword
; PADDQ mm, mm | PADDQ mm, m64
; PSUBQ mm, mm | PSUBQ mm, m64

; PMULUDQ - Packed multiply unsigned doubleword
; PMULUDQ mm, mm | PMULUDQ mm, m64

;=============================================================================
; SECTION 10: SSE2 INSTRUCTIONS (128-bit integer)
;=============================================================================

; MOVDQA/MOVDQU - Move aligned/unaligned double quadword
; MOVDQA xmm, xmm | MOVDQA xmm, m128 | MOVDQA m128, xmm
; MOVDQU xmm, xmm | MOVDQU xmm, m128 | MOVDQU m128, xmm

; MOVD/MOVQ - Move doubleword/quadword
; MOVD xmm, r32 | MOVD xmm, m32 | MOVD r32, xmm | MOVD m32, xmm
; MOVQ xmm, r64 | MOVQ xmm, m64 | MOVQ r64, xmm | MOVQ m64, xmm

; PADDW/PADDD/PADDQ - Packed add
; PADDW xmm, xmm | PADDW xmm, m128
; PADDD xmm, xmm | PADDD xmm, m128
; PADDQ xmm, xmm | PADDQ xmm, m128

; PSUBW/PSUBD/PSUBQ - Packed subtract
; PSUBW xmm, xmm | PSUBW xmm, m128
; PSUBD xmm, xmm | PSUBD xmm, m128
; PSUBQ xmm, xmm | PSUBQ xmm, m128

; PMULLW/PMULHW/PMULHUW/PMULLD - Packed multiply
; PMULLW xmm, xmm | PMULLW xmm, m128
; PMULHW xmm, xmm | PMULHW xmm, m128
; PMULHUW xmm, xmm | PMULHUW xmm, m128
; PMULLD xmm, xmm | PMULLD xmm, m128

; PSLLW/PSLLD/PSLLQ - Packed shift left
; PSLLW xmm, imm8 | PSLLW xmm, xmm | PSLLW xmm, m128
; PSLLD xmm, imm8 | PSLLD xmm, xmm | PSLLD xmm, m128
; PSLLQ xmm, imm8 | PSLLQ xmm, xmm | PSLLQ xmm, m128

; PSRLW/PSRLD/PSRLQ - Packed shift right logical
; PSRLW xmm, imm8 | PSRLW xmm, xmm | PSRLW xmm, m128
; PSRLD xmm, imm8 | PSRLD xmm, xmm | PSRLD xmm, m128
; PSRLQ xmm, imm8 | PSRLQ xmm, xmm | PSRLQ xmm, m128

; PSRAW/PSRAD - Packed shift right arithmetic
; PSRAW xmm, imm8 | PSRAW xmm, xmm | PSRAW xmm, m128
; PSRAD xmm, imm8 | PSRAD xmm, xmm | PSRAD xmm, m128

; PAND/PANDN/POR/PXOR - Packed logical
; PAND xmm, xmm | PAND xmm, m128
; PANDN xmm, xmm | PANDN xmm, m128
; POR xmm, xmm | POR xmm, m128
; PXOR xmm, xmm | PXOR xmm, m128

; PCMPEQB/PCMPEQW/PCMPEQD/PCMPEQQ - Packed compare equal
; PCMPEQB xmm, xmm | PCMPEQB xmm, m128
; PCMPEQW xmm, xmm | PCMPEQW xmm, m128
; PCMPEQD xmm, xmm | PCMPEQD xmm, m128
; PCMPEQQ xmm, xmm | PCMPEQQ xmm, m128

; PCMPGTB/PCMPGTW/PCMPGTD/PCMPGTQ - Packed compare greater than
; PCMPGTB xmm, xmm | PCMPGTB xmm, m128
; PCMPGTW xmm, xmm | PCMPGTW xmm, m128
; PCMPGTD xmm, xmm | PCMPGTD xmm, m128
; PCMPGTQ xmm, xmm | PCMPGTQ xmm, m128

; PUNPCKLBW/PUNPCKLWD/PUNPCKLDQ/PUNPCKLQDQ - Unpack low
; PUNPCKLBW xmm, xmm | PUNPCKLBW xmm, m128
; PUNPCKLWD xmm, xmm | PUNPCKLWD xmm, m128
; PUNPCKLDQ xmm, xmm | PUNPCKLDQ xmm, m128
; PUNPCKLQDQ xmm, xmm | PUNPCKLQDQ xmm, m128

; PUNPCKHBW/PUNPCKHWD/PUNPCKHDQ/PUNPCKHQDQ - Unpack high
; PUNPCKHBW xmm, xmm | PUNPCKHBW xmm, m128
; PUNPCKHWD xmm, xmm | PUNPCKHWD xmm, m128
; PUNPCKHDQ xmm, xmm | PUNPCKHDQ xmm, m128
; PUNPCKHQDQ xmm, xmm | PUNPCKHQDQ xmm, m128

; PSHUFD/PSHUFW/PSHUFB - Shuffle
; PSHUFD xmm, xmm, imm8 | PSHUFD xmm, m128, imm8
; PSHUFW mm, mm, imm8 | PSHUFW mm, m64, imm8
; PSHUFB xmm, xmm | PSHUFB xmm, m128

; PACKUSWB/PACKSSWB/PACKSSDW - Pack with saturation
; PACKUSWB xmm, xmm | PACKUSWB xmm, m128
; PACKSSWB xmm, xmm | PACKSSWB xmm, m128
; PACKSSDW xmm, xmm | PACKSSDW xmm, m128

; PUNPCKLWD/PUNPCKHWD - Unpack and interleave
; PUNPCKLWD xmm, xmm | PUNPCKLWD xmm, m128
; PUNPCKHWD xmm, xmm | PUNPCKHWD xmm, m128

;=============================================================================
; SECTION 11: SSE3/SSSE3 INSTRUCTIONS
;=============================================================================

; HADDPS/HSUBPS - Horizontal add/subtract packed single
; HADDPS xmm, xmm | HADDPS xmm, m128
; HSUBPS xmm, xmm | HSUBPS xmm, m128

; HADDPD/HSUBPD - Horizontal add/subtract packed double
; HADDPD xmm, xmm | HADDPD xmm, m128
; HSUBPD xmm, xmm | HSUBPD xmm, m128

; ADDSUBPS/ADDSUBPD - Packed add/subtract
; ADDSUBPS xmm, xmm | ADDSUBPS xmm, m128
; ADDSUBPD xmm, xmm | ADDSUBPD xmm, m128

; MOVSHDUP/MOVSLDUP - Move shuffled duplicates
; MOVSHDUP xmm, xmm | MOVSHDUP xmm, m128
; MOVSLDUP xmm, xmm | MOVSLDUP xmm, m128

; MOVDDUP - Move one double and duplicate
; MOVDDUP xmm, xmm | MOVDDUP xmm, m64

; LDDQU - Load unaligned
; LDDQU xmm, m128

; PHADDW/PHADDD - Packed horizontal add
; PHADDW xmm, xmm | PHADDW xmm, m128
; PHADDD xmm, xmm | PHADDD xmm, m128

; PHSUBW/PHSUBD - Packed horizontal subtract
; PHSUBW xmm, xmm | PHSUBW xmm, m128
; PHSUBD xmm, xmm | PHSUBD xmm, m128

; PHADDSW/PHSUBSW - Packed horizontal add/subtract with saturation
; PHADDSW xmm, xmm | PHADDSW xmm, m128
; PHSUBSW xmm, xmm | PHSUBSW xmm, m128

; PABSAB/PABSW/PABSD - Packed absolute value
; PABSB xmm, xmm | PABSB xmm, m128
; PABSW xmm, xmm | PABSW xmm, m128
; PABSD xmm, xmm | PABSD xmm, m128

; PSIGNB/PSIGNW/PSIGND - Packed sign
; PSIGNB xmm, xmm | PSIGNB xmm, m128
; PSIGNW xmm, xmm | PSIGNW xmm, m128
; PSIGND xmm, xmm | PSIGND xmm, m128

; PALIGNR - Packed align right
; PALIGNR xmm, xmm, imm8 | PALIGNR xmm, m128, imm8

; PSHUFB - Packed shuffle bytes
; PSHUFB xmm, xmm | PSHUFB xmm, m128

; PMADDUBSW - Packed multiply add unsigned bytes signed words
; PMADDUBSW xmm, xmm | PMADDUBSW xmm, m128

; PMULHRSW - Packed multiply high round with saturation
; PMULHRSW xmm, xmm | PMULHRSW xmm, m128

;=============================================================================
; SECTION 12: SSE4.1/SSE4.2 INSTRUCTIONS
;=============================================================================

; PMULLD/PMULUDQ - Packed multiply
; PMULLD xmm, xmm | PMULLD xmm, m128
; PMULUDQ xmm, xmm | PMULUDQ xmm, m128

; PMULDQ - Packed multiply signed
; PMULDQ xmm, xmm | PMULDQ xmm, m128

; DPPS/DPPD - Dot product packed single/double
; DPPS xmm, xmm, imm8 | DPPS xmm, m128, imm8
; DPPD xmm, xmm, imm8 | DPPD xmm, m128, imm8

; BLENDPS/BLENDPD - Blend packed single/double
; BLENDPS xmm, xmm, imm8 | BLENDPS xmm, m128, imm8
; BLENDPD xmm, xmm, imm8 | BLENDPD xmm, m128, imm8

; BLENDVPS/BLENDVPD - Variable blend packed single/double
; BLENDVPS xmm, xmm | BLENDVPS xmm, m128
; BLENDVPD xmm, xmm | BLENDVPD xmm, m128

; PBLENDW - Blend packed words
; PBLENDW xmm, xmm, imm8 | PBLENDW xmm, m128, imm8

; PMINSB/PMAXSB - Packed min/max signed byte
; PMINSB xmm, xmm | PMINSB xmm, m128
; PMAXSB xmm, xmm | PMAXSB xmm, m128

; PMINSD/PMAXSD - Packed min/max signed doubleword
; PMINSD xmm, xmm | PMINSD xmm, m128
; PMAXSD xmm, xmm | PMAXSD xmm, m128

; PMINUW/PMAXUW - Packed min/max unsigned word
; PMINUW xmm, xmm | PMINUW xmm, m128
; PMAXUW xmm, xmm | PMAXUW xmm, m128

; PMINUD/PMAXUD - Packed min/max unsigned doubleword
; PMINUD xmm, xmm | PMINUD xmm, m128
; PMAXUD xmm, xmm | PMAXUD xmm, m128

; ROUNDPS/ROUNDPD - Round packed single/double
; ROUNDPS xmm, xmm, imm8 | ROUNDPS xmm, m128, imm8
; ROUNDPD xmm, xmm, imm8 | ROUNDPD xmm, m128, imm8

; ROUNDSS/ROUNDSD - Round scalar single/double
; ROUNDSS xmm, xmm, imm8 | ROUNDSS xmm, m32, imm8
; ROUNDSD xmm, xmm, imm8 | ROUNDSD xmm, m64, imm8

; EXTRACTPS - Extract packed single
; EXTRACTPS r32, xmm, imm8 | EXTRACTPS m32, xmm, imm8

; INSERTPS - Insert packed single
; INSERTPS xmm, xmm, imm8 | INSERTPS xmm, m32, imm8

; PINSRB/PINSRW/PINSRD/PINSRQ - Insert packed integer
; PINSRB xmm, r32, imm8 | PINSRB xmm, m8, imm8
; PINSRW xmm, r32, imm8 | PINSRW xmm, m16, imm8
; PINSRD xmm, r32, imm8 | PINSRD xmm, m32, imm8
; PINSRQ xmm, r64, imm8 | PINSRQ xmm, m64, imm8

; PEXTRB/PEXTRW/PEXTRD/PEXTRQ - Extract packed integer
; PEXTRB r32, xmm, imm8 | PEXTRB m8, xmm, imm8
; PEXTRW r32, xmm, imm8 | PEXTRW m16, xmm, imm8
; PEXTRD r32, xmm, imm8 | PEXTRD m32, xmm, imm8
; PEXTRQ r64, xmm, imm8 | PEXTRQ m64, xmm, imm8

; PMOVSXBW/PMOVSXBD/PMOVSXBQ - Packed move with sign extension
; PMOVSXBW xmm, xmm | PMOVSXBW xmm, m64
; PMOVSXBD xmm, xmm | PMOVSXBD xmm, m32
; PMOVSXBQ xmm, xmm | PMOVSXBQ xmm, m16

; PMOVZXBW/PMOVZXBD/PMOVZXBQ - Packed move with zero extension
; PMOVZXBW xmm, xmm | PMOVZXBW xmm, m64
; PMOVZXBD xmm, xmm | PMOVZXBD xmm, m32
; PMOVZXBQ xmm, xmm | PMOVZXBQ xmm, m16

; MPSADBW - Multiple packed sum of absolute difference
; MPSADBW xmm, xmm, imm8 | MPSADBW xmm, m128, imm8

; PHMINPOSUW - Packed horizontal minimum
; PHMINPOSUW xmm, xmm | PHMINPOSUW xmm, m128

; PCMPESTRI/PCMPESTRM/PCMPISTRI/PCMPISTRM - Packed compare explicit length
; PCMPESTRI xmm, xmm, imm8 | PCMPESTRI xmm, m128, imm8
; PCMPESTRM xmm, xmm, imm8 | PCMPESTRM xmm, m128, imm8
; PCMPISTRI xmm, xmm, imm8 | PCMPISTRI xmm, m128, imm8
; PCMPISTRM xmm, xmm, imm8 | PCMPISTRM xmm, m128, imm8

; PCMPEQQ - Packed compare equal quadword
; PCMPEQQ xmm, xmm | PCMPEQQ xmm, m128

; PACKUSDW - Pack with unsigned saturation
; PACKUSDW xmm, xmm | PACKUSDW xmm, m128

;=============================================================================
; SECTION 13: AVX INSTRUCTIONS (256-bit)
;=============================================================================

; VMOVAPS/VMOVUPS - Move aligned/unaligned packed single
; VMOVAPS ymm, ymm | VMOVAPS ymm, m256 | VMOVAPS m256, ymm
; VMOVUPS ymm, ymm | VMOVUPS ymm, m256 | VMOVUPS m256, ymm

; VMOVAPD/VMOVUPD - Move aligned/unaligned packed double
; VMOVAPD ymm, ymm | VMOVAPD ymm, m256 | VMOVAPD m256, ymm
; VMOVUPD ymm, ymm | VMOVUPD ymm, m256 | VMOVUPD m256, ymm

; VADDPS/VSUBPS/VMULPS/VDIVPS - Packed single arithmetic
; VADDPS ymm, ymm, ymm | VADDPS ymm, ymm, m256
; VSUBPS ymm, ymm, ymm | VSUBPS ymm, ymm, m256
; VMULPS ymm, ymm, ymm | VMULPS ymm, ymm, m256
; VDIVPS ymm, ymm, ymm | VDIVPS ymm, ymm, m256

; VADDPD/VSUBPD/VMULPD/VDIVPD - Packed double arithmetic
; VADDPD ymm, ymm, ymm | VADDPD ymm, ymm, m256
; VSUBPD ymm, ymm, ymm | VSUBPD ymm, ymm, m256
; VMULPD ymm, ymm, ymm | VMULPD ymm, ymm, m256
; VDIVPD ymm, ymm, ymm | VDIVPD ymm, ymm, m256

; VADDSS/VSUBSS/VMULSS/VDIVSS - Scalar single arithmetic
; VADDSS xmm, xmm, xmm | VADDSS xmm, xmm, m32
; VSUBSS xmm, xmm, xmm | VSUBSS xmm, xmm, m32
; VMULSS xmm, xmm, xmm | VMULSS xmm, xmm, m32
; VDIVSS xmm, xmm, xmm | VDIVSS xmm, xmm, m32

; VADDSD/VSUBSD/VMULSD/VDIVSD - Scalar double arithmetic
; VADDSD xmm, xmm, xmm | VADDSD xmm, xmm, m64
; VSUBSD xmm, xmm, xmm | VSUBSD xmm, xmm, m64
; VMULSD xmm, xmm, xmm | VMULSD xmm, xmm, m64
; VDIVSD xmm, xmm, xmm | VDIVSD xmm, xmm, m64

; VANDPS/VANDPD/VORPS/VORPD/VXORPS/VXORPD - Bitwise logical
; VANDPS ymm, ymm, ymm | VANDPS ymm, ymm, m256
; VANDPD ymm, ymm, ymm | VANDPD ymm, ymm, m256
; VORPS ymm, ymm, ymm | VORPS ymm, ymm, m256
; VORPD ymm, ymm, ymm | VORPD ymm, ymm, m256
; VXORPS ymm, ymm, ymm | VXORPS ymm, ymm, m256
; VXORPD ymm, ymm, ymm | VXORPD ymm, ymm, m256

; VSHUFPS/VSHUFPD - Shuffle packed
; VSHUFPS ymm, ymm, ymm, imm8 | VSHUFPS ymm, ymm, m256, imm8
; VSHUFPD ymm, ymm, ymm, imm8 | VSHUFPD ymm, ymm, m256, imm8

; VUNPCKLPS/VUNPCKHPS/VUNPCKLPD/VUNPCKHPD - Unpack and interleave
; VUNPCKLPS ymm, ymm, ymm | VUNPCKLPS ymm, ymm, m256
; VUNPCKHPS ymm, ymm, ymm | VUNPCKHPS ymm, ymm, m256
; VUNPCKLPD ymm, ymm, ymm | VUNPCKLPD ymm, ymm, m256
; VUNPCKHPD ymm, ymm, ymm | VUNPCKHPD ymm, ymm, m256

; VPERMILPS/VPERMILPD - Permute in-lane
; VPERMILPS ymm, ymm, imm8 | VPERMILPS ymm, m256, imm8
; VPERMILPD ymm, ymm, imm8 | VPERMILPD ymm, m256, imm8

; VPERM2F128 - Permute two 128-bit lanes
; VPERM2F128 ymm, ymm, ymm, imm8 | VPERM2F128 ymm, ymm, m256, imm8

; VBROADCASTSS/VBROADCASTSD/VBROADCASTF128 - Broadcast
; VBROADCASTSS ymm, m32 | VBROADCASTSS xmm, m32
; VBROADCASTSD ymm, m64
; VBROADCASTF128 ymm, m128

; VEXTRACTF128 - Extract 128-bit lane
; VEXTRACTF128 xmm, ymm, imm8 | VEXTRACTF128 m128, ymm, imm8

; VINSERTF128 - Insert 128-bit lane
; VINSERTF128 ymm, ymm, xmm, imm8 | VINSERTF128 ymm, ymm, m128, imm8

; VCVTPS2PD/VCVTPD2PS - Convert packed single/double
; VCVTPS2PD ymm, xmm | VCVTPS2PD ymm, m128
; VCVTPD2PS xmm, ymm | VCVTPD2PS xmm, m256

; VCVTDQ2PS/VCVTPS2DQ - Convert packed integer/single
; VCVTDQ2PS ymm, ymm | VCVTDQ2PS ymm, m256
; VCVTPS2DQ ymm, ymm | VCVTPS2DQ ymm, m256

; VCVTTPS2DQ - Convert with truncation
; VCVTTPS2DQ ymm, ymm | VCVTTPS2DQ ymm, m256

;=============================================================================
; SECTION 14: AVX2 INSTRUCTIONS (256-bit integer)
;=============================================================================

; VMOVDQA/VMOVDQU - Move aligned/unaligned double quadword
; VMOVDQA ymm, ymm | VMOVDQA ymm, m256 | VMOVDQA m256, ymm
; VMOVDQU ymm, ymm | VMOVDQU ymm, m256 | VMOVDQU m256, ymm

; VPADDW/VPADDD/VPADDQ - Packed add
; VPADDW ymm, ymm, ymm | VPADDW ymm, ymm, m256
; VPADDD ymm, ymm, ymm | VPADDD ymm, ymm, m256
; VPADDQ ymm, ymm, ymm | VPADDQ ymm, ymm, m256

; VPSUBW/VPSUBD/VPSUBQ - Packed subtract
; VPSUBW ymm, ymm, ymm | VPSUBW ymm, ymm, m256
; VPSUBD ymm, ymm, ymm | VPSUBD ymm, ymm, m256
; VPSUBQ ymm, ymm, ymm | VPSUBQ ymm, ymm, m256

; VPMULLW/VPMULHW/VPMULLD - Packed multiply
; VPMULLW ymm, ymm, ymm | VPMULLW ymm, ymm, m256
; VPMULHW ymm, ymm, ymm | VPMULHW ymm, ymm, m256
; VPMULLD ymm, ymm, ymm | VPMULLD ymm, ymm, m256

; VPSLLW/VPSLLD/VPSLLQ - Packed shift left
; VPSLLW ymm, ymm, imm8 | VPSLLW ymm, ymm, xmm
; VPSLLD ymm, ymm, imm8 | VPSLLD ymm, ymm, xmm
; VPSLLQ ymm, ymm, imm8 | VPSLLQ ymm, ymm, xmm

; VPSRLW/VPSRLD/VPSRLQ - Packed shift right logical
; VPSRLW ymm, ymm, imm8 | VPSRLW ymm, ymm, xmm
; VPSRLD ymm, ymm, imm8 | VPSRLD ymm, ymm, xmm
; VPSRLQ ymm, ymm, imm8 | VPSRLQ ymm, ymm, xmm

; VPSRAW/VPSRAD - Packed shift right arithmetic
; VPSRAW ymm, ymm, imm8 | VPSRAW ymm, ymm, xmm
; VPSRAD ymm, ymm, imm8 | VPSRAD ymm, ymm, xmm

; VPAND/VPANDN/VPOR/VPXOR - Packed logical
; VPAND ymm, ymm, ymm | VPAND ymm, ymm, m256
; VPANDN ymm, ymm, ymm | VPANDN ymm, ymm, m256
; VPOR ymm, ymm, ymm | VPOR ymm, ymm, m256
; VPXOR ymm, ymm, ymm | VPXOR ymm, ymm, m256

; VPCMPEQB/VPCMPEQW/VPCMPEQD/VPCMPEQQ - Packed compare equal
; VPCMPEQB ymm, ymm, ymm | VPCMPEQB ymm, ymm, m256
; VPCMPEQW ymm, ymm, ymm | VPCMPEQW ymm, ymm, m256
; VPCMPEQD ymm, ymm, ymm | VPCMPEQD ymm, ymm, m256
; VPCMPEQQ ymm, ymm, ymm | VPCMPEQQ ymm, ymm, m256

; VPCMPGTB/VPCMPGTW/VPCMPGTD/VPCMPGTQ - Packed compare greater than
; VPCMPGTB ymm, ymm, ymm | VPCMPGTB ymm, ymm, m256
; VPCMPGTW ymm, ymm, ymm | VPCMPGTW ymm, ymm, m256
; VPCMPGTD ymm, ymm, ymm | VPCMPGTD ymm, ymm, m256
; VPCMPGTQ ymm, ymm, ymm | VPCMPGTQ ymm, ymm, m256

; VPERMD - Perute doublewords
; VPERMD ymm, ymm, ymm | VPERMD ymm, ymm, m256

; VPERMPS - Perute single precision
; VPERMPS ymm, ymm, ymm | VPERMPS ymm, ymm, m256

; VPERMQ/VPERMPD - Perute quadwords/double precision
; VPERMQ ymm, ymm, imm8 | VPERMQ ymm, m256, imm8
; VPERMPD ymm, ymm, imm8 | VPERMPD ymm, m256, imm8

; VPMOVMSKB - Move byte mask
; VPMOVMSKB r32, xmm | VPMOVMSKB r64, ymm

; VPMOVSXBW/VPMOVSXBD/VPMOVSXBQ - Packed move with sign extension
; VPMOVSXBW ymm, xmm | VPMOVSXBW ymm, m128
; VPMOVSXBD ymm, xmm | VPMOVSXBD ymm, m64
; VPMOVSXBQ ymm, xmm | VPMOVSXBQ ymm, m32

; VPMOVZXBW/VPMOVZXBD/VPMOVZXBQ - Packed move with zero extension
; VPMOVZXBW ymm, xmm | VPMOVZXBW ymm, m128
; VPMOVZXBD ymm, xmm | VPMOVZXBD ymm, m64
; VPMOVZXBQ ymm, xmm | VPMOVZXBQ ymm, m32

; VGATHERPS/VGATHERPD - Gather packed single/double
; VGATHERPS ymm, ymm, ymm | VGATHERPS ymm, m256, ymm
; VGATHERPD ymm, ymm, ymm | VGATHERPD ymm, m256, ymm

; VPGATHERDD/VPGATHERDQ - Gather packed doublewords/quadwords
; VPGATHERDD ymm, ymm, ymm | VPGATHERDD ymm, m256, ymm
; VPGATHERDQ ymm, ymm, ymm | VPGATHERDQ ymm, m256, ymm

;=============================================================================
; SECTION 15: AVX-512 INSTRUCTIONS (512-bit)
;=============================================================================

; VMOVAPS/VMOVUPS - Move aligned/unaligned packed single (512-bit)
; VMOVAPS zmm, zmm | VMOVAPS zmm, m512 | VMOVAPS m512, zmm
; VMOVUPS zmm, zmm | VMOVUPS zmm, m512 | VMOVUPS m512, zmm

; VMOVAPD/VMOVUPD - Move aligned/unaligned packed double (512-bit)
; VMOVAPD zmm, zmm | VMOVAPD zmm, m512 | VMOVAPD m512, zmm
; VMOVUPD zmm, zmm | VMOVUPD zmm, m512 | VMOVUPD m512, zmm

; VADDPS/VSUBPS/VMULPS/VDIVPS - Packed single arithmetic (512-bit)
; VADDPS zmm, zmm, zmm | VADDPS zmm, zmm, m512
; VSUBPS zmm, zmm, zmm | VSUBPS zmm, zmm, m512
; VMULPS zmm, zmm, zmm | VMULPS zmm, zmm, m512
; VDIVPS zmm, zmm, zmm | VDIVPS zmm, zmm, m512

; VADDPD/VSUBPD/VMULPD/VDIVPD - Packed double arithmetic (512-bit)
; VADDPD zmm, zmm, zmm | VADDPD zmm, zmm, m512
; VSUBPD zmm, zmm, zmm | VSUBPD zmm, zmm, m512
; VMULPD zmm, zmm, zmm | VMULPD zmm, zmm, m512
; VDIVPD zmm, zmm, zmm | VDIVPD zmm, zmm, m512

; VFMADD132PS/VFMADD213PS/VFMADD231PS - Fused multiply-add packed single
; VFMADD132PS zmm, zmm, zmm | VFMADD132PS zmm, zmm, m512
; VFMADD213PS zmm, zmm, zmm | VFMADD213PS zmm, zmm, m512
; VFMADD231PS zmm, zmm, zmm | VFMADD231PS zmm, zmm, m512

; VFMADD132PD/VFMADD213PD/VFMADD231PD - Fused multiply-add packed double
; VFMADD132PD zmm, zmm, zmm | VFMADD132PD zmm, zmm, m512
; VFMADD213PD zmm, zmm, zmm | VFMADD213PD zmm, zmm, m512
; VFMADD231PD zmm, zmm, zmm | VFMADD231PD zmm, zmm, m512

; VPADDW/VPADDD/VPADDQ - Packed add (512-bit)
; VPADDW zmm, zmm, zmm | VPADDW zmm, zmm, m512
; VPADDD zmm, zmm, zmm | VPADDD zmm, zmm, m512
; VPADDQ zmm, zmm, zmm | VPADDQ zmm, zmm, m512

; VPSUBW/VPSUBD/VPSUBQ - Packed subtract (512-bit)
; VPSUBW zmm, zmm, zmm | VPSUBW zmm, zmm, m512
; VPSUBD zmm, zmm, zmm | VPSUBD zmm, zmm, m512
; VPSUBQ zmm, zmm, zmm | VPSUBQ zmm, zmm, m512

; VPMULLW/VPMULLD - Packed multiply (512-bit)
; VPMULLW zmm, zmm, zmm | VPMULLW zmm, zmm, m512
; VPMULLD zmm, zmm, zmm | VPMULLD zmm, zmm, m512

; VPERMD - Perute doublewords (512-bit)
; VPERMD zmm, zmm, zmm | VPERMD zmm, zmm, m512

; VPERMQ - Perute quadwords (512-bit)
; VPERMQ zmm, zmm, imm8 | VPERMQ zmm, m512, imm8

; VEXTRACTF64X4 - Extract 256-bit lane
; VEXTRACTF64X4 ymm, zmm, imm8 | VEXTRACTF64X4 m256, zmm, imm8

; VINSERTF64X4 - Insert 256-bit lane
; VINSERTF64X4 zmm, zmm, ymm, imm8 | VINSERTF64X4 zmm, zmm, m256, imm8

; VBROADCASTSS/VBROADCASTSD - Broadcast (512-bit)
; VBROADCASTSS zmm, m32
; VBROADCASTSD zmm, m64

; VPBROADCASTD/VPBROADCASTQ - Broadcast integer
; VPBROADCASTD zmm, m32 | VPBROADCASTD zmm, xmm
; VPBROADCASTQ zmm, m64 | VPBROADCASTQ zmm, xmm

; VPCMPD/VPCMPQ - Compare packed integers
; VPCMPD k1, zmm, zmm, imm8 | VPCMPD k1, zmm, m512, imm8
; VPCMPQ k1, zmm, zmm, imm8 | VPCMPQ k1, zmm, m512, imm8

; VPMOVMSKB - Move byte mask to mask register
; VPMOVMSKB k1, zmm

; KANDW/KANDD/KANDQ - Mask register AND
; KANDW k1, k2, k3
; KANDD k1, k2, k3
; KANDQ k1, k2, k3

; KORW/KORD/KORQ - Mask register OR
; KORW k1, k2, k3
; KORD k1, k2, k3
; KORQ k1, k2, k3

; KXORW/KXORD/KXORQ - Mask register XOR
; KXORW k1, k2, k3
; KXORD k1, k2, k3
; KXORQ k1, k2, k3

; KNOTW/KNOTD/KNOTQ - Mask register NOT
; KNOTW k1, k2
; KNOTD k1, k2
; KNOTQ k1, k2

; KMOVW/KMOVD/KMOVQ - Move to/from mask register
; KMOVW k1, k2 | KMOVW k1, m16 | KMOVW m16, k1
; KMOVD k1, k2 | KMOVD k1, m32 | KMOVD m32, k1
; KMOVQ k1, k2 | KMOVQ k1, m64 | KMOVQ m64, k1

;=============================================================================
; SECTION 16: BMI1/BMI2 INSTRUCTIONS
;=============================================================================

; ANDN - AND NOT
; ANDN r64, r64, r64 | ANDN r64, r64, m64

; BLSI - Extract lowest set bit
; BLSI r64, r64 | BLSI r64, m64

; BLSMSK - Get mask up to lowest set bit
; BLSMSK r64, r64 | BLSMSK r64, m64

; BLSR - Reset lowest set bit
; BLSR r64, r64 | BLSR r64, m64

; BZHI - Zero high bits
; BZHI r64, r64, r64 | BZHI r64, m64, r64

; BEXTR - Bit field extract
; BEXTR r64, r64, r64 | BEXTR r64, m64, r64

; BLSFILL - Fill from lowest set bit
; BLSFILL r64, r64 | BLSFILL r64, m64

; TZCNT - Count trailing zeros
; TZCNT r64, r64 | TZCNT r64, m64

; LZCNT - Count leading zeros
; LZCNT r64, r64 | LZCNT r64, m64

; POPCNT - Count set bits
; POPCNT r64, r64 | POPCNT r64, m64

; PDEP - Parallel bits deposit
; PDEP r64, r64, r64 | PDEP r64, r64, m64

; PEXT - Parallel bits extract
; PEXT r64, r64, r64 | PEXT r64, r64, m64

; MULX - Unsigned multiply without affecting flags
; MULX r64, r64, r64 | MULX r64, r64, m64

; RORX - Rotate right without affecting flags
; RORX r64, r64, imm8 | RORX r64, m64, imm8

; SARX - Shift arithmetic right without affecting flags
; SARX r64, r64, r64 | SARX r64, m64, r64

; SHLX - Shift left without affecting flags
; SHLX r64, r64, r64 | SHLX r64, m64, r64

; SHRX - Shift right logical without affecting flags
; SHRX r64, r64, r64 | SHRX r64, m64, r64

;=============================================================================
; SECTION 17: SYSTEM INSTRUCTIONS
;=============================================================================

; CPUID - CPU identification
; CPUID

; RDTSC - Read time-stamp counter
; RDTSC

; RDTSCP - Read time-stamp counter and processor ID
; RDTSCP

; RDPMC - Read performance-monitoring counters
; RDPMC

; RDMSR - Read model-specific register
; RDMSR

; WRMSR - Write model-specific register
; WRMSR

; RDTSCP - Read time-stamp counter and processor ID
; RDTSCP

; INVLPG - Invalidate TLB entry
; INVLPG m

; INVD - Invalidate internal caches
; INVD

; WBINVD - Write back and invalidate cache
; WBINVD

; WBINVD - Write back and invalidate cache (with TLB)
; WBINVD

; CLFLUSH - Flush cache line
; CLFLUSH m8

; CLFLUSHOPT - Flush cache line optimized
; CLFLUSHOPT m8

; CLWB - Cache line write back
; CLWB m8

; CLZERO - Zero cache line
; CLZERO

; LFENCE - Load fence
; LFENCE

; MFENCE - Memory fence
; MFENCE

; SFENCE - Store fence
; SFENCE

; PREFETCH - Prefetch data
; PREFETCHT0 m8 | PREFETCHT1 m8 | PREFETCHT2 m8 | PREFETCHNTA m8

; PREFETCHW - Prefetch with intent to write
; PREFETCHW m8

; PREFETCHWT1 - Prefetch with intent to write and temporal hint
; PREFETCHWT1 m8

; HLT - Halt
; HLT

; PAUSE - Spin loop hint
; PAUSE

; NOP - No operation
; NOP

; UD2 - Undefined instruction
; UD2

;=============================================================================
; SECTION 18: FMA INSTRUCTIONS (Fused Multiply-Add)
;=============================================================================

; VFMADD132PS/VFMADD213PS/VFMADD231PS - FMA packed single
; VFMADD132PS ymm, ymm, ymm | VFMADD132PS ymm, ymm, m256
; VFMADD213PS ymm, ymm, ymm | VFMADD213PS ymm, ymm, m256
; VFMADD231PS ymm, ymm, ymm | VFMADD231PS ymm, ymm, m256

; VFMADD132PD/VFMADD213PD/VFMADD231PD - FMA packed double
; VFMADD132PD ymm, ymm, ymm | VFMADD132PD ymm, ymm, m256
; VFMADD213PD ymm, ymm, ymm | VFMADD213PD ymm, ymm, m256
; VFMADD231PD ymm, ymm, ymm | VFMADD231PD ymm, ymm, m256

; VFMADD132SS/VFMADD213SS/VFMADD231SS - FMA scalar single
; VFMADD132SS xmm, xmm, xmm | VFMADD132SS xmm, xmm, m32
; VFMADD213SS xmm, xmm, xmm | VFMADD213SS xmm, xmm, m32
; VFMADD231SS xmm, xmm, xmm | VFMADD231SS xmm, xmm, m32

; VFMADD132SD/VFMADD213SD/VFMADD231SD - FMA scalar double
; VFMADD132SD xmm, xmm, xmm | VFMADD132SD xmm, xmm, m64
; VFMADD213SD xmm, xmm, xmm | VFMADD213SD xmm, xmm, m64
; VFMADD231SD xmm, xmm, xmm | VFMADD231SD xmm, xmm, m64

; VFMSUB132PS/VFMSUB213PS/VFMSUB231PS - FMS packed single
; VFMSUB132PS ymm, ymm, ymm | VFMSUB132PS ymm, ymm, m256
; VFMSUB213PS ymm, ymm, ymm | VFMSUB213PS ymm, ymm, m256
; VFMSUB231PS ymm, ymm, ymm | VFMSUB231PS ymm, ymm, m256

; VFMSUB132PD/VFMSUB213PD/VFMSUB231PD - FMS packed double
; VFMSUB132PD ymm, ymm, ymm | VFMSUB132PD ymm, ymm, m256
; VFMSUB213PD ymm, ymm, ymm | VFMSUB213PD ymm, ymm, m256
; VFMSUB231PD ymm, ymm, ymm | VFMSUB231PD ymm, ymm, m256

; VFNMSUB132PS/VFNMSUB213PS/VFNMSUB231PS - FNMA packed single
; VFNMSUB132PS ymm, ymm, ymm | VFNMSUB132PS ymm, ymm, m256
; VFNMSUB213PS ymm, ymm, ymm | VFNMSUB213PS ymm, ymm, m256
; VFNMSUB231PS ymm, ymm, ymm | VFNMSUB231PS ymm, ymm, m256

; VFNMSUB132PD/VFNMSUB213PD/VFNMSUB231PD - FNMA packed double
; VFNMSUB132PD ymm, ymm, ymm | VFNMSUB132PD ymm, ymm, m256
; VFNMSUB213PD ymm, ymm, ymm | VFNMSUB213PD ymm, ymm, m256
; VFNMSUB231PD ymm, ymm, ymm | VFNMSUB231PD ymm, ymm, m256

;=============================================================================
; SECTION 19: MISCELLANEOUS INSTRUCTIONS
;=============================================================================

; LEA - Load effective address
; LEA r64, m | LEA r32, m

; NOP - No operation
; NOP | NOP m16 | NOP r16 | NOP r32 | NOP r64

; CBW/CWDE/CDQE - Sign extend accumulator
; CBW | CWDE | CDQE

; CWD/CDQ/CQO - Sign extend accumulator to DX:RAX
; CWD | CDQ | CQO

; LAHF - Load flags into AH
; LAHF

; SAHF - Store AH into flags
; SAHF

; XLAT/XLATB - Table lookup translation
; XLAT | XLATB

; IN/OUT - Port I/O
; IN AL, imm8 | IN AX, imm8 | IN EAX, imm8
; IN AL, DX | IN AX, DX | IN EAX, DX
; OUT imm8, AL | OUT imm8, AX | OUT imm8, EAX
; OUT DX, AL | OUT DX, AX | OUT DX, EAX

; INS/OUTS - String port I/O
; INSB | INSW | INSD
; OUTSB | OUTSW | OUTSD

; BOUND - Check array bounds (legacy)
; BOUND r16, m16 | BOUND r32, m32

; ENTER/LEAVE - Stack frame
; ENTER imm16, imm8
; LEAVE

; ARPL - Adjust RPL field (legacy)
; ARPL r16, r16 | ARPL m16, r16

; LAR/LSL - Load access/rights limit
; LAR r16, r16 | LAR r32, r32
; LSL r16, r16 | LSL r32, r32

; SGDT/SIDT/LGDT/LIDT - Descriptor table
; SGDT m | SIDT m | LGDT m | LIDT m

; SLDT/LLDT/STR/LTR - Local/task descriptor
; SLDT r16 | SLDT m16 | LLDT r16 | LLDT m16
; STR r16 | STR m16 | LTR r16 | LTR m16

; VERR/VERW - Verify segment
; VERR r16 | VERR m16 | VERW r16 | VERW m16

; CLTS - Clear task-switched flag
; CLTS

; CLD/STD - Clear/set direction flag
; CLD | STD

; CLI/STI - Clear/set interrupt flag
; CLI | STI

; LOCK - Lock prefix
; LOCK <instruction>

; WAIT/FWAIT - Wait for FPU
; WAIT | FWAIT

;=============================================================================
; END OF x64 INSTRUCTION SET
;=============================================================================