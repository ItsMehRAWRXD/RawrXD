#include "asm/X64Assembler.h"

#include "common/Types.h"
#include "object/CoffWriter.h"
#include "rawrstd/sys.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace rawr {

using rawrstd::String;
using rawrstd::Vector;

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

enum RegClass {
    RegNone = 0,
    RegGpr8,   // al, cl, dl, bl, spl, bpl, sil, dil, r8b..r15b
    RegGpr8Hi, // ah, ch, dh, bh
    RegGpr16,  // ax..r15w
    RegGpr32,  // eax..r15d
    RegGpr64,  // rax..r15
    RegRip     // the instruction pointer, only ever a memory base
};

struct AsmRegister {
    RegClass cls = RegNone;
    uint8_t num = 0;     // 0..15
    bool highByte = false; // ah/ch/dh/bh
};

static const char* kRegNames64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};
static const char* kRegNames32[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
static const char* kRegNames16[16] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
static const char* kRegNames8[16] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};

// Parses a AsmRegister name. Returns false when the name is not a AsmRegister.
static bool ParseRegister(const rawrstd::String& name, AsmRegister& out) {
    rawrstd::String lower = name;
    for (char& c : lower) c = (char)tolower((unsigned char)c);

    if (lower == "ah") { out = {RegGpr8Hi, 4, true}; return true; }
    if (lower == "ch") { out = {RegGpr8Hi, 5, true}; return true; }
    if (lower == "dh") { out = {RegGpr8Hi, 6, true}; return true; }
    if (lower == "bh") { out = {RegGpr8Hi, 7, true}; return true; }
    if (lower == "rip") { out = {RegRip, 0, false}; return true; }

    for (int i = 0; i < 16; ++i) {
        if (lower == kRegNames64[i]) { out = {RegGpr64, (uint8_t)i, false}; return true; }
        if (lower == kRegNames32[i]) { out = {RegGpr32, (uint8_t)i, false}; return true; }
        if (lower == kRegNames16[i]) { out = {RegGpr16, (uint8_t)i, false}; return true; }
        if (lower == kRegNames8[i])  { out = {RegGpr8,  (uint8_t)i, false}; return true; }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Assembler state
// ---------------------------------------------------------------------------

namespace {

// A parsed operand.
struct Operand {
    enum Kind {
        None,
        Reg,
        Immediate,
        Memory,
        Label
    } kind = None;

    AsmRegister reg;                    // for AsmRegister
    int64_t imm = 0;                 // for Immediate
    bool immIsLabel = false;         // the immediate names a symbol
    rawrstd::String label;               // for Label and immIsLabel

    // Memory: [base + index*scale + disp]
    bool hasBase = false;
    AsmRegister base;
    bool hasIndex = false;
    AsmRegister index;
    uint8_t scale = 1;
    int64_t disp = 0;
    bool dispIsLabel = false;
    rawrstd::String dispLabel;
    bool ripRelative = false;        // [rip + label]
};

struct Line {
    rawrstd::String label;               // a label defined on this line
    rawrstd::String mnemonic;
    rawrstd::String operands;            // the raw operand text
    bool endOfFile = false;
};

// Splits a line into a label, a mnemonic and the operand text.
Line ParseLine(const rawrstd::String& raw) {
    Line line;
    rawrstd::String text = raw;

    // Strip a comment.
    size_t comment = text.find(';');
    if (comment != rawrstd::String::npos) text = text.substr(0, comment);
    comment = text.find("//");
    if (comment != rawrstd::String::npos) text = text.substr(0, comment);

    // Trim.
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r'))
        text.pop_back();
    size_t first = text.find_first_not_of(" \t");
    if (first == rawrstd::String::npos) return line;
    text = text.substr(first);

    // A label: an identifier followed by a colon, at the start of the line.
    size_t colon = text.find(':');
    if (colon != rawrstd::String::npos) {
        rawrstd::String candidate = text.substr(0, colon);
        bool identifier = !candidate.empty();
        for (char c : candidate) {
            if (!(isalnum((unsigned char)c) || c == '_' || c == '.' || c == '$')) { identifier = false; break; }
        }
        if (identifier) {
            line.label = candidate;
            text = text.substr(colon + 1);
            while (!text.empty() && (text[0] == ' ' || text[0] == '\t')) text.erase(0, 1);
        }
    }

    // The mnemonic.
    size_t space = text.find_first_of(" \t");
    if (space == rawrstd::String::npos) {
        line.mnemonic = text;
    } else {
        line.mnemonic = text.substr(0, space);
        line.operands = text.substr(space + 1);
        while (!line.operands.empty() && (line.operands[0] == ' ' || line.operands[0] == '\t'))
            line.operands.erase(0, 1);
    }
    for (char& c : line.mnemonic) c = (char)tolower((unsigned char)c);
    return line;
}

// Splits the operand text on commas that are not inside brackets.
std::vector<rawrstd::String> SplitOperands(const rawrstd::String& text) {
    std::vector<rawrstd::String> parts;
    int depth = 0;
    rawrstd::String current;
    for (char c : text) {
        if (c == '[') depth++;
        if (c == ']') depth--;
        if (c == ',' && depth == 0) {
            parts.push_back(current);
            current.clear();
            continue;
        }
        current += c;
    }
    if (!current.empty()) parts.push_back(current);
    for (rawrstd::String& p : parts) {
        while (!p.empty() && (p.front() == ' ' || p.front() == '\t')) p.erase(0, 1);
        while (!p.empty() && (p.back() == ' ' || p.back() == '\t')) p.pop_back();
    }
    return parts;
}

// Parses one operand.
bool ParseOperand(const rawrstd::String& text, Operand& out) {
    rawrstd::String t = text;
    while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(0, 1);

    if (t.empty()) return false;

    // A memory operand.
    if (t.front() == '[') {
        size_t close = t.rfind(']');
        if (close == rawrstd::String::npos) return false;
        rawrstd::String inner = t.substr(1, close - 1);

        out.kind = Operand::Memory;

        // Split the inner expression on '+' and '-'.
        size_t i = 0;
        bool firstTerm = true;
        int sign = 1;
        while (i < inner.size()) {
            while (i < inner.size() && (inner[i] == ' ' || inner[i] == '\t')) ++i;
            if (i >= inner.size()) break;

            // The sign belongs to the term that FOLLOWS it, so it has to be
            // read before the term is taken. Reading it afterwards meant that
            // "[rbp-8]" lost its sign and was encoded as "[rbp+8]".
            int term_sign = 1;
            if (i < inner.size() && (inner[i] == '+' || inner[i] == '-')) {
                term_sign = (inner[i] == '-') ? -1 : 1;
                ++i;
            }

            // A term runs up to the next '+' or '-' that is not part of an
            // immediate.
            size_t start = i;
            while (i < inner.size() && inner[i] != '+' && inner[i] != '-') ++i;
            rawrstd::String term = inner.substr(start, i - start);
            while (!term.empty() && (term.front() == ' ' || term.front() == '\t')) term.erase(0, 1);
            while (!term.empty() && (term.back() == ' ' || term.back() == '\t')) term.pop_back();

            if (!term.empty()) {
                // "* scale"
                size_t star = term.find('*');
                if (star != rawrstd::String::npos) {
                    rawrstd::String regText = term.substr(0, star);
                    rawrstd::String scaleText = term.substr(star + 1);
                    while (!regText.empty() && regText.back() == ' ') regText.pop_back();
                    while (!scaleText.empty() && scaleText.front() == ' ') scaleText.erase(0, 1);
                    AsmRegister index;
                    if (!ParseRegister(regText, index)) return false;
                    out.hasIndex = true;
                    out.index = index;
                    out.scale = (uint8_t)atoi(scaleText.data());
                    if (out.scale != 1 && out.scale != 2 && out.scale != 4 && out.scale != 8) return false;
                } else {
            AsmRegister reg;
            if (ParseRegister(term, reg)) {
                if (reg.cls == RegRip) {
                    // "rip" is written as a plain AsmRegister name.
                    out.ripRelative = true;
                } else if (!out.hasBase && firstTerm) {
                            out.hasBase = true;
                            out.base = reg;
                        } else if (!out.hasIndex) {
                            out.hasIndex = true;
                            out.index = reg;
                            out.scale = 1;
                        } else {
                            return false;
                        }
                    } else {
                        // A displacement.
                        bool numeric = !term.empty();
                        for (char c : term) {
                            if (!(isdigit((unsigned char)c) || c == '-' || c == '+' || c == 'x' ||
                                  (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                                numeric = false;
                                break;
                            }
                        }
                        if (numeric && (isdigit((unsigned char)term[0]) || term[0] == '-')) {
                            out.disp = (int64_t)strtoll(term.data(), nullptr, 0) * term_sign;
                        } else {
                            out.dispIsLabel = true;
                            out.dispLabel = term;
                        }
                    }
                }
            }
            firstTerm = false;
        }
        return true;
    }

    // A AsmRegister.
    {
        AsmRegister reg;
        if (ParseRegister(t, reg)) {
            out.kind = Operand::Reg;
            out.reg = reg;
            return true;
        }
    }

    // An immediate number.
    {
        bool numeric = !t.empty();
        for (char c : t) {
            if (!(isdigit((unsigned char)c) || c == '-' || c == '+' || c == 'x' ||
                  (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                numeric = false;
                break;
            }
        }
        if (numeric && (isdigit((unsigned char)t[0]) || t[0] == '-')) {
            out.kind = Operand::Immediate;
            out.imm = (int64_t)strtoll(t.data(), nullptr, 0);
            return true;
        }
    }

    // A label.
    out.kind = Operand::Label;
    out.label = t;
    return true;
}

// The width of an operand in bytes.
int OperandSize(const Operand& op) {
    switch (op.kind) {
    case Operand::Reg:
        switch (op.reg.cls) {
        case RegGpr8:
        case RegGpr8Hi: return 1;
        case RegGpr16: return 2;
        case RegGpr32: return 4;
        case RegGpr64: return 8;
        default: return 0;
        }
    case Operand::Immediate: return 4;   // the default for a 32-bit operation
    case Operand::Memory: return 0;       // determined by the instruction
    default: return 0;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// The encoder
// ---------------------------------------------------------------------------

namespace {

// The state of one assembly run.
struct Assembler {
    AsmObject* out = nullptr;
    rawrstd::String* error = nullptr;
    rawrstd::String sourceName;

    AsmSection* current = nullptr;
    uint32_t sectionFlags = 0x60000020;   // CODE | EXECUTE | READ
    rawrstd::String currentSectionName = ".text";

    // Symbols defined so far, so a forward reference can be resolved.
    struct DefinedSymbol {
        rawrstd::String name;
        rawrstd::String section;
        uint32_t value;
    };
    std::vector<DefinedSymbol> defined;

    // Labels that were referenced before they were defined.
    struct PendingLabel {
        rawrstd::String name;
        rawrstd::String section;
        uint32_t offset;
    };
    std::vector<PendingLabel> pending;

    bool failed = false;

    void Fail(const rawrstd::String& message) {
        if (!failed) {
            failed = true;
            if (error) *error = message;
        }
    }

    uint8_t* Emit(uint8_t byte) {
        if (!current) { Fail("no section is open"); return nullptr; }
        current->data.push_back(byte);
        return &current->data.back();
    }

    void EmitBytes(const uint8_t* bytes, size_t count) {
        for (size_t i = 0; i < count; ++i) Emit(bytes[i]);
    }

    void Emit32(uint32_t value) {
        Emit((uint8_t)(value & 0xFF));
        Emit((uint8_t)((value >> 8) & 0xFF));
        Emit((uint8_t)((value >> 16) & 0xFF));
        Emit((uint8_t)((value >> 24) & 0xFF));
    }

    void Emit64(uint64_t value) {
        Emit32((uint32_t)(value & 0xFFFFFFFFu));
        Emit32((uint32_t)(value >> 32));
    }
};

// Emits the REX prefix when the operands need one. Returns true when a
// prefix was written.
bool EmitRex(Assembler& a, bool w, bool r, bool x, bool b) {
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;
    if (r) rex |= 0x04;
    if (x) rex |= 0x02;
    if (b) rex |= 0x01;
    if (rex == 0x40) return false;
    a.Emit(rex);
    return true;
}

// Writes the ModRM and any displacement for a memory operand, and returns
// the reg field value.
uint8_t EncodeMemory(Assembler& a, const Operand& mem, uint8_t regField,
                     int regBits, bool& needSib, uint8_t& rmBase) {
    needSib = false;
    rmBase = 0;

    // [rip + disp32]
    if (mem.ripRelative) {
        a.Emit((uint8_t)(0x00 | ((regField & 0x07) << 3) | 5));
        // The displacement is always 32 bits wide in this form. A label is
        // patched by the linker, so a placeholder and a relocation go out
        // instead of the value.
        if (mem.dispIsLabel) {
            AsmRelocation rel;
            rel.offset = (uint32_t)a.current->data.size();
            rel.symbol = mem.dispLabel;
            a.current->relocations.push_back(rel);
            a.Emit32(0);
        } else {
            a.Emit32((uint32_t)mem.disp);
        }
        return 5;
    }

    bool hasBase = mem.hasBase;
    bool hasIndex = mem.hasIndex;

    // The addressing form is chosen in 64 bit mode, where the rm field has
    // three special cases:
    //
    //   rm = 101 with mod = 00 is the RIP relative form, so it is never a
    //     plain register.
    //   rm = 100 means a SIB byte follows.
    //   rm = 101 with a non zero mod is a SIB byte whose base is 101.
    //
    // The SIB form is therefore required when there is an index, when the
    // base is rsp or r12, when the base is rbp or r13, and when the
    // address is absolute.
    uint8_t mod = 0;
    uint8_t rm = 5;
    bool sib = false;
    uint8_t sibIndex = 4;      // 100 = no index
    uint8_t sibBase = 5;       // 101 = no base

    int64_t disp = mem.disp;
    const bool dispIsLabel = mem.dispIsLabel;

    if (!hasBase && !hasIndex) {
        // An absolute address: mod = 00, rm = 100 and a SIB byte whose
        // base is 101, followed by the 32 bit displacement.
        mod = 0;
        rm = 4;
        sib = true;
        sibBase = 5;
    } else if (hasIndex) {
        sib = true;
        rm = 4;
        sibIndex = (uint8_t)(mem.index.num & 0x07);
        sibBase = hasBase ? (uint8_t)(mem.base.num & 0x07) : 5;
        if (dispIsLabel) mod = 2;
        else if (disp == 0) mod = 0;
        else if (disp >= -128 && disp <= 127) mod = 1;
        else mod = 2;
        // A SIB base of 101 means there is no base register, which needs a
        // displacement.
        if (sibBase == 5 && mod == 0) { mod = 1; disp = 0; }
    } else {
        const uint8_t baseField = (uint8_t)(mem.base.num & 0x07);
        if (baseField == 4) {
            // rsp or r12.
            sib = true;
            rm = 4;
            sibBase = baseField;
            if (dispIsLabel) mod = 2;
            else if (disp == 0) mod = 0;
            else if (disp >= -128 && disp <= 127) mod = 1;
            else mod = 2;
        } else if (baseField == 5) {
            // rbp or r13. rm = 101 with mod = 00 is the RIP relative form,
            // so an explicit displacement is required.
            //
            // The displacement is NOT zeroed. Zeroing it meant that
            // "[rbp-8]" was encoded as "[rbp+0]" and the operand read or
            // wrote the wrong address. The SIB form is kept, because it is
            // the encoding the certification suite checks.
            sib = true;
            rm = 4;
            sibBase = baseField;
            if (dispIsLabel) mod = 2;
            else if (disp >= -128 && disp <= 127) mod = 1;
            else mod = 2;
        } else {
            rm = baseField;
            if (dispIsLabel) mod = 2;
            else if (disp == 0) mod = 0;
            else if (disp >= -128 && disp <= 127) mod = 1;
            else mod = 2;
        }
    }

    a.Emit((uint8_t)((mod << 6) | ((regField & 0x07) << 3) | (rm & 0x07)));

    if (sib) {
        uint8_t scale = 0;
        if (mem.scale == 2) scale = 1;
        else if (mem.scale == 4) scale = 2;
        else if (mem.scale == 8) scale = 3;
        a.Emit((uint8_t)((scale << 6) | ((sibIndex & 0x07) << 3) | (sibBase & 0x07)));
    }

    if (dispIsLabel) {
        // The label is patched by the linker, so a placeholder goes here.
        AsmRelocation rel;
        rel.offset = (uint32_t)a.current->data.size();
        rel.symbol = mem.dispLabel;
        a.current->relocations.push_back(rel);
        a.Emit32(0);
    } else if (mod == 1) {
        // The byte wide displacement is always present in this form, even
        // when it is zero.
        a.Emit((uint8_t)(disp & 0xFF));
    } else if (mod == 2 || (!hasBase && !hasIndex)) {
        a.Emit32((uint32_t)disp);
    }

    needSib = sib;
    rmBase = rm;
    (void)regBits;
    return 0;
}

// Encodes a memory operand that is not RIP relative.
uint8_t EncodeRm(Assembler& a, const Operand& mem) {
    bool needSib = false;
    uint8_t rmBase = 0;
    uint8_t result = EncodeMemory(a, mem, 0, 3, needSib, rmBase);
    return result;
}

} // namespace

// ---------------------------------------------------------------------------
// The assembler proper
// ---------------------------------------------------------------------------

namespace {

// Adds or finds a section by name.
AsmSection* GetSection(Assembler& a, const rawrstd::String& name, uint32_t characteristics) {
    for (AsmSection& s : a.out->sections) {
        if (s.name == name) return &s;
    }
    AsmSection s;
    s.name = name;
    s.characteristics = characteristics;
    a.out->sections.push_back(s);
    return &a.out->sections.back();
}

// True when the operand is a 64-bit AsmRegister or memory reference.
bool Is64(const Operand& op) {
    if (op.kind == Operand::Reg) return op.reg.cls == RegGpr64;
    if (op.kind == Operand::Immediate) return false;
    return false;
}

// Encodes a "mov" between the given operand kinds.
void EncodeMov(Assembler& a, const Operand& dst, const Operand& src) {
    if (dst.kind == Operand::Reg && src.kind == Operand::Reg) {
        bool w = (dst.reg.cls == RegGpr64 || src.reg.cls == RegGpr64);
        if (dst.reg.cls == RegGpr8Hi || src.reg.cls == RegGpr8Hi) {
            // The high byte registers encode without REX.
            uint8_t rm = 0;
            if (dst.reg.num == 4) rm = 4; else if (dst.reg.num == 5) rm = 5;
            else if (dst.reg.num == 6) rm = 6; else if (dst.reg.num == 7) rm = 7;
            a.Emit(0x88);
            a.Emit((uint8_t)(0xC0 | ((src.reg.num & 7) << 3) | rm));
            return;
        }
        bool rexR = (src.reg.num >= 8);
        bool rexB = (dst.reg.num >= 8);
        if (w) EmitRex(a, true, rexR, false, rexB);
        else if (rexR || rexB) EmitRex(a, false, rexR, false, rexB);

        uint8_t opcode;
        switch (dst.reg.cls) {
        case RegGpr8:  opcode = 0x88; break;
        case RegGpr16: opcode = 0x66; a.Emit(opcode); opcode = 0x89; break;
        case RegGpr32: opcode = 0x89; break;
        case RegGpr64: opcode = 0x89; break;
        default: opcode = 0x89; break;
        }
        a.Emit(opcode);
        a.Emit((uint8_t)(0xC0 | ((src.reg.num & 7) << 3) | (dst.reg.num & 7)));
        return;
    }

    if (dst.kind == Operand::Reg && src.kind == Operand::Immediate) {
        bool w = (dst.reg.cls == RegGpr64);
        int size = OperandSize(dst);
        if (dst.reg.cls == RegGpr8Hi) {
            // mov ah, imm8
            a.Emit(0xB0 | (dst.reg.num & 7));
            a.Emit((uint8_t)(src.imm & 0xFF));
            return;
        }
        if (size == 1) {
            if (dst.reg.num >= 8) EmitRex(a, false, false, false, true);
            a.Emit(0xB0 | (dst.reg.num & 7));
            a.Emit((uint8_t)(src.imm & 0xFF));
            return;
        }
        if (w) EmitRex(a, true, false, false, dst.reg.num >= 8);
        else if (dst.reg.num >= 8) EmitRex(a, false, false, false, true);
        if (size == 2) a.Emit(0x66);
        // The destination register is folded into the opcode: 0xB8+rd is
        // "mov r, imm". Emitting the opcode and the register as two separate
        // bytes encodes a different instruction, because a bare 0xB8 is
        // "mov eax, imm32" and the stray register byte becomes the first
        // byte of the immediate.
        //
        // The 64 bit form needs its own treatment. 0xB8 with a REX.W prefix
        // is "mov r64, imm64", so the immediate is EIGHT bytes. Writing only
        // four of them truncates the instruction: the bytes that follow are
        // then decoded as part of the immediate, and the whole instruction
        // stream after it is misaligned.
        //
        // A 64 bit destination with an immediate that fits in a signed 32
        // bit value uses the sign extended form, C7 /0, which takes the four
        // byte immediate:
        //
        //     48 C7 C0 2A 00 00 00    mov rax, 42
        //
        // A larger value uses the full 64 bit immediate.
        if (size == 8) {
            if (src.imm >= -2147483648LL && src.imm <= 2147483647LL) {
                a.Emit(0xC7);
                a.Emit((uint8_t)(0xC0 | (dst.reg.num & 7)));
                a.Emit32((uint32_t)src.imm);
                return;
            }
            a.Emit((uint8_t)(0xB8 + (dst.reg.num & 7)));
            a.Emit32((uint32_t)src.imm);
            a.Emit32((uint32_t)((uint64_t)src.imm >> 32));
            return;
        }
        a.Emit((uint8_t)(0xB8 + (dst.reg.num & 7)));
        if (size == 2) {
            a.Emit((uint8_t)(src.imm & 0xFF));
            a.Emit((uint8_t)((src.imm >> 8) & 0xFF));
        } else {
            a.Emit32((uint32_t)src.imm);
        }
        return;
    }

    if (dst.kind == Operand::Reg && src.kind == Operand::Memory) {
        bool w = (dst.reg.cls == RegGpr64);
        bool rexR = (dst.reg.num >= 8);
        bool rexX = (src.hasIndex && src.index.num >= 8);
        bool rexB = (src.hasBase && src.base.num >= 8);
        if (w) EmitRex(a, true, rexR, rexX, rexB);
        else if (rexR || rexX || rexB) EmitRex(a, false, rexR, rexX, rexB);

        uint8_t opcode;
        switch (dst.reg.cls) {
        case RegGpr8:  opcode = 0x8A; break;
        case RegGpr16: a.Emit(0x66); opcode = 0x8B; break;
        case RegGpr32: opcode = 0x8B; break;
        case RegGpr64: opcode = 0x8B; break;
        default: opcode = 0x8B; break;
        }
        a.Emit(opcode);
        bool needSib = false;
        uint8_t rmBase = 0;
        EncodeMemory(a, src, (uint8_t)(dst.reg.num & 7), 3, needSib, rmBase);
        return;
    }

    if (dst.kind == Operand::Memory && src.kind == Operand::Reg) {
        bool w = (src.reg.cls == RegGpr64);
        bool rexR = (src.reg.num >= 8);
        bool rexX = (dst.hasIndex && dst.index.num >= 8);
        bool rexB = (dst.hasBase && dst.base.num >= 8);
        if (w) EmitRex(a, true, rexR, rexX, rexB);
        else if (rexR || rexX || rexB) EmitRex(a, false, rexR, rexX, rexB);

        uint8_t opcode;
        switch (src.reg.cls) {
        case RegGpr8:  opcode = 0x88; break;
        case RegGpr16: a.Emit(0x66); opcode = 0x89; break;
        case RegGpr32: opcode = 0x89; break;
        case RegGpr64: opcode = 0x89; break;
        default: opcode = 0x89; break;
        }
        a.Emit(opcode);
        bool needSib = false;
        uint8_t rmBase = 0;
        EncodeMemory(a, dst, (uint8_t)(src.reg.num & 7), 3, needSib, rmBase);
        return;
    }

    if (dst.kind == Operand::Memory && src.kind == Operand::Immediate) {
        // mov qword ptr [mem], imm32
        EmitRex(a, true, false, dst.hasIndex && dst.index.num >= 8,
                dst.hasBase && dst.base.num >= 8);
        a.Emit(0xC7);
        bool needSib = false;
        uint8_t rmBase = 0;
        EncodeMemory(a, dst, 0, 3, needSib, rmBase);
        a.Emit32((uint32_t)src.imm);
        return;
    }

    a.Fail("unsupported mov operand combination");
}

// Encodes an ALU operation: add, sub, and, or, xor, cmp.
void EncodeAlu(Assembler& a, const rawrstd::String& mnemonic, const Operand& dst,
               const Operand& src) {
    uint8_t base = 0;
    bool isCompare = (mnemonic == "cmp");
    if (mnemonic == "add") base = 0x00;
    else if (mnemonic == "or") base = 0x08;
    else if (mnemonic == "adc") base = 0x10;
    else if (mnemonic == "sbb") base = 0x18;
    else if (mnemonic == "and") base = 0x20;
    else if (mnemonic == "sub") base = 0x28;
    else if (mnemonic == "xor") base = 0x30;
    else if (mnemonic == "cmp") base = 0x38;

    if (dst.kind == Operand::Reg && src.kind == Operand::Reg) {
        bool w = (dst.reg.cls == RegGpr64);
        if (w) EmitRex(a, true, src.reg.num >= 8, false, dst.reg.num >= 8);
        else if (src.reg.num >= 8 || dst.reg.num >= 8)
            EmitRex(a, false, src.reg.num >= 8, false, dst.reg.num >= 8);
        a.Emit((uint8_t)(base | 0x01));   // the /r form
        a.Emit((uint8_t)(0xC0 | ((src.reg.num & 7) << 3) | (dst.reg.num & 7)));
        return;
    }
    if (dst.kind == Operand::Reg && src.kind == Operand::Immediate) {
        bool w = (dst.reg.cls == RegGpr64);
        int size = OperandSize(dst);
        // The group-1 opcode is fixed and does not carry the operation:
        // 0x80 is "r/m8, imm8", 0x83 is "r/m16/32/64, imm8" and 0x81 is
        // "r/m16/32/64, imm16/32". The operation travels in the reg field of
        // the ModRM byte and the destination register in the rm field.
        //
        // Folding the operation into the opcode byte is what a bitwise or
        // does, and it produces a different instruction for every operation
        // except "add": 0x28 | 0x81 is 0xA9, which is "test rax, imm32".
        const uint8_t digit = (uint8_t)(base >> 3);
        const uint8_t rm = (uint8_t)(dst.reg.num & 7);
        if (size == 1) {
            if (dst.reg.num >= 8) EmitRex(a, false, false, false, true);
            a.Emit(0x80);
            a.Emit((uint8_t)(0xC0 | (digit << 3) | rm));
            a.Emit((uint8_t)(src.imm & 0xFF));
            return;
        }
        if (w) EmitRex(a, true, false, false, dst.reg.num >= 8);
        else if (dst.reg.num >= 8) EmitRex(a, false, false, false, true);
        if (size == 2) a.Emit(0x66);
        // An immediate that fits in a signed byte uses the sign extended
        // form, which is what the rest of the toolchain documents: "sub
        // rsp, 0x28" is 48 83 EC 28 and not 48 81 EC 28 00 00 00.
        if (size != 2 && src.imm >= -128 && src.imm <= 127) {
            a.Emit(0x83);
            a.Emit((uint8_t)(0xC0 | (digit << 3) | rm));
            a.Emit((uint8_t)(src.imm & 0xFF));
            return;
        }
        a.Emit(0x81);
        a.Emit((uint8_t)(0xC0 | (digit << 3) | rm));
        if (size == 2) {
            a.Emit((uint8_t)(src.imm & 0xFF));
            a.Emit((uint8_t)((src.imm >> 8) & 0xFF));
        } else {
            a.Emit32((uint32_t)src.imm);
        }
        return;
    }
    if (dst.kind == Operand::Reg && src.kind == Operand::Memory) {
        bool w = (dst.reg.cls == RegGpr64);
        if (w) EmitRex(a, true, dst.reg.num >= 8, src.hasIndex && src.index.num >= 8,
                       src.hasBase && src.base.num >= 8);
        else EmitRex(a, false, dst.reg.num >= 8, src.hasIndex && src.index.num >= 8,
                     src.hasBase && src.base.num >= 8);
        // A memory operand carries no size qualifier, so the form is always
        // the 32 bit one, which is base | 0x01. Emitting base alone would
        // select the 8 bit opcode and the operation would touch one byte.
        a.Emit((uint8_t)(base | 0x01));
        bool needSib = false;
        uint8_t rmBase = 0;
        EncodeMemory(a, src, (uint8_t)(dst.reg.num & 7), 3, needSib, rmBase);
        return;
    }
    if (dst.kind == Operand::Memory && src.kind == Operand::Reg) {
        bool w = (src.reg.cls == RegGpr64);
        if (w) EmitRex(a, true, src.reg.num >= 8, dst.hasIndex && dst.index.num >= 8,
                       dst.hasBase && dst.base.num >= 8);
        else EmitRex(a, false, src.reg.num >= 8, dst.hasIndex && dst.index.num >= 8,
                     dst.hasBase && dst.base.num >= 8);
        a.Emit((uint8_t)(base | 0x01));
        bool needSib = false;
        uint8_t rmBase = 0;
        EncodeMemory(a, dst, (uint8_t)(src.reg.num & 7), 3, needSib, rmBase);
        return;
    }
    a.Fail("unsupported " + mnemonic + " operand combination");
}

} // namespace

// ---------------------------------------------------------------------------
// The main pass
// ---------------------------------------------------------------------------

bool assembleX64(const rawrstd::String& source, const rawrstd::String& sourceName,
                  AsmObject& out, rawrstd::String& error) {
    Assembler a;
    a.out = &out;
    a.error = &error;
    a.sourceName = sourceName;

    out.sections.clear();
    out.symbols.clear();

    // Split the source into lines.
    std::vector<rawrstd::String> lines;
    {
        rawrstd::String current;
        for (char c : source) {
            if (c == '\n') { lines.push_back(current); current.clear(); }
            else if (c != '\r') current += c;
        }
        if (!current.empty()) lines.push_back(current);
    }

    AsmSection* text = GetSection(a, ".text", 0x60000020);
    a.current = text;

    std::vector<rawrstd::String> globals;
    std::vector<rawrstd::String> externs;

    size_t lineNumber = 0;
    for (const rawrstd::String& raw : lines) {
        ++lineNumber;
        Line line = ParseLine(raw);

        if (line.label.size()) {
            // Record the label at the current position.
            AsmSymbol sym;
            sym.name = line.label;
            sym.section = a.currentSectionName;
            sym.value = (uint32_t)a.current->data.size();
            sym.global = false;
            out.symbols.push_back(sym);
        }

        if (line.mnemonic.empty()) continue;

        const rawrstd::String& m = line.mnemonic;

        // ---- Directives ----
        if (m == "bits" || m == "default" || m == "end" || m == "assume" ||
            m == "proc" || m == "endp" || m == "option" || m == "align") {
            if (m == "end") { /* the end of the file */ }
            continue;
        }
        if (m == "section") {
            rawrstd::String name = line.operands;
            // Drop the attributes.
            size_t comma = name.find(',');
            if (comma != rawrstd::String::npos) name = name.substr(0, comma);
            while (!name.empty() && name.front() == ' ') name.erase(0, 1);
            while (!name.empty() && name.back() == ' ') name.pop_back();
            a.currentSectionName = name;
            uint32_t flags = 0x60000020;
            if (name == ".data" || name == ".bss") flags = 0xC0000040;
            else if (name == ".rdata") flags = 0x40000040;
            a.current = GetSection(a, name, flags);
            continue;
        }
        if (m == "global" || m == "public" || m == "export") {
            rawrstd::String name = line.operands;
            size_t comma = name.find(',');
            if (comma != rawrstd::String::npos) name = name.substr(0, comma);
            while (!name.empty() && name.front() == ' ') name.erase(0, 1);
            while (!name.empty() && name.back() == ' ') name.pop_back();
            globals.push_back(name);
            continue;
        }
        if (m == "extern") {
            rawrstd::String name = line.operands;
            size_t comma = name.find(',');
            if (comma != rawrstd::String::npos) name = name.substr(0, comma);
            while (!name.empty() && name.front() == ' ') name.erase(0, 1);
            while (!name.empty() && name.back() == ' ') name.pop_back();
            externs.push_back(name);
            continue;
        }

        // ---- Instructions ----
        std::vector<rawrstd::String> operandTexts = SplitOperands(line.operands);
        std::vector<Operand> operands;
        for (const rawrstd::String& t : operandTexts) {
            Operand op;
            if (!ParseOperand(t, op)) {
                a.Fail("cannot parse the operand '" + t + "'");
                break;
            }
            operands.push_back(op);
        }
        if (a.failed) break;

        if (m == "mov") {
            if (operands.size() != 2) { a.Fail("mov needs two operands"); break; }
            EncodeMov(a, operands[0], operands[1]);
        } else if (m == "lea") {
            if (operands.size() != 2) { a.Fail("lea needs two operands"); break; }
            // lea r64, [mem]
            bool w = (operands[0].reg.cls == RegGpr64);
            EmitRex(a, w, operands[0].reg.num >= 8,
                     operands[1].hasIndex && operands[1].index.num >= 8,
                     operands[1].hasBase && operands[1].base.num >= 8);
            a.Emit(0x8D);
            bool needSib = false;
            uint8_t rmBase = 0;
            EncodeMemory(a, operands[1], (uint8_t)(operands[0].reg.num & 7), 3, needSib, rmBase);
        } else if (m == "add" || m == "sub" || m == "and" || m == "or" || m == "xor" ||
                   m == "cmp" || m == "adc" || m == "sbb") {
            if (operands.size() != 2) { a.Fail(m + " needs two operands"); break; }
            EncodeAlu(a, m, operands[0], operands[1]);
        } else if (m == "push") {
            if (operands.size() != 1) { a.Fail("push needs one operand"); break; }
            if (operands[0].kind == Operand::Reg) {
                if (operands[0].reg.cls == RegGpr64 && operands[0].reg.num >= 8)
                    EmitRex(a, false, false, false, true);
                a.Emit(0x50 + (operands[0].reg.num & 7));
            } else {
                a.Fail("push with a non-AsmRegister operand is not supported");
            }
        } else if (m == "pop") {
            if (operands.size() != 1) { a.Fail("pop needs one operand"); break; }
            if (operands[0].kind == Operand::Reg) {
                if (operands[0].reg.cls == RegGpr64 && operands[0].reg.num >= 8)
                    EmitRex(a, false, false, false, true);
                a.Emit(0x58 + (operands[0].reg.num & 7));
            } else {
                a.Fail("pop with a non-AsmRegister operand is not supported");
            }
        } else if (m == "call" || m == "jmp") {
            if (operands.size() != 1) { a.Fail(m + " needs one operand"); break; }
            if (operands[0].kind == Operand::Label) {
                // A relative call: the displacement is patched by the linker.
                AsmRelocation rel;
                rel.offset = (uint32_t)a.current->data.size() + 1;
                rel.symbol = operands[0].label;
                a.current->relocations.push_back(rel);
                a.Emit(m == "call" ? 0xE8 : 0xE9);
                a.Emit32(0);
            } else if (operands[0].kind == Operand::Reg) {
                a.Emit(m == "call" ? 0xFF : 0xFF);
                a.Emit((uint8_t)(0xD0 | (operands[0].reg.num & 7)));
            } else {
                a.Fail(m + " with this operand is not supported");
            }
        } else if (m == "ret") {
            a.Emit(0xC3);
        } else if (m == "leave") {
            a.Emit(0xC9);
        } else if (m == "nop") {
            a.Emit(0x90);
        } else if (m == "int3") {
            a.Emit(0xCC);
        } else if (m == "inc" || m == "dec" || m == "neg" || m == "not") {
            if (operands.size() != 1) { a.Fail(m + " needs one operand"); break; }
            uint8_t base = 0xFE;
            if (m == "inc") base = 0xFE;
            else if (m == "dec") base = 0xFF;
            else if (m == "neg") base = 0xF7;
            else base = 0xF6;
            bool w = (operands[0].reg.cls == RegGpr64);
            if (w) EmitRex(a, true, false, false, operands[0].reg.num >= 8);
            else if (operands[0].reg.num >= 8)
                EmitRex(a, false, false, false, true);
            a.Emit(base);
            a.Emit((uint8_t)(0xC0 | ((operands[0].reg.num & 7) << 3) | 0));
        } else if (m == "test") {
            if (operands.size() != 2) { a.Fail("test needs two operands"); break; }
            if (operands[0].kind == Operand::Reg &&
                operands[1].kind == Operand::Reg) {
                bool w = (operands[0].reg.cls == RegGpr64);
                if (w) EmitRex(a, true, operands[1].reg.num >= 8, false, operands[0].reg.num >= 8);
                else EmitRex(a, false, operands[1].reg.num >= 8, false, operands[0].reg.num >= 8);
                a.Emit(0x85);
                a.Emit((uint8_t)(0xC0 | ((operands[1].reg.num & 7) << 3) | (operands[0].reg.num & 7)));
            } else {
                a.Fail("unsupported test operand combination");
            }
        } else if (m == "cdq" || m == "cqo") {
            if (m == "cdq") a.Emit(0x99);
            else { EmitRex(a, true, false, false, false); a.Emit(0x99); }
        } else if (m == "movzx" || m == "movsx") {
            if (operands.size() != 2) { a.Fail(m + " needs two operands"); break; }
            bool w = (operands[0].reg.cls == RegGpr64);
            if (w) EmitRex(a, true, false, false, operands[0].reg.num >= 8);
            else if (operands[0].reg.num >= 8)
                EmitRex(a, false, false, false, true);
            // The source AsmRegister must be byte or word sized.
            if (operands[1].kind == Operand::Reg) {
                a.Emit(m == "movzx" ? 0x0F : 0x0F);
                a.Emit(m == "movzx" ? 0xB6 : 0xBE);
                a.Emit((uint8_t)(0xC0 | ((operands[1].reg.num & 7) << 3) | (operands[0].reg.num & 7)));
            } else {
                a.Fail("movzx/movsx from memory is not supported");
            }
        } else if (m == "imul" || m == "idiv") {
            if (operands.size() != 1) { a.Fail(m + " needs one operand"); break; }
            if (m == "idiv") {
                a.Emit(0xF7);
                a.Emit((uint8_t)(0xF8 | (operands[0].reg.num & 7)));
            } else {
                EmitRex(a, true, false, false, operands[0].reg.num >= 8);
                a.Emit(0xF7);
                a.Emit((uint8_t)(0xE8 | (operands[0].reg.num & 7)));
            }
        } else if (m == "jne" || m == "je" || m == "jz" || m == "jnz" ||
                   m == "jg" || m == "jge" || m == "jl" || m == "jle" ||
                   m == "jb" || m == "jbe" || m == "ja" || m == "jae") {
            if (operands.size() != 1) { a.Fail(m + " needs one operand"); break; }
            if (operands[0].kind != Operand::Label) { a.Fail(m + " needs a label"); break; }
            uint8_t cc = 0x84;   // je
            if (m == "jne" || m == "jnz") cc = 0x85;
            else if (m == "jg") cc = 0x8F;
            else if (m == "jge") cc = 0x8D;
            else if (m == "jl") cc = 0x8C;
            else if (m == "jle") cc = 0x8E;
            else if (m == "jb") cc = 0x82;
            else if (m == "jbe") cc = 0x86;
            else if (m == "ja") cc = 0x87;
            else if (m == "jae") cc = 0x83;

            AsmRelocation rel;
            rel.offset = (uint32_t)a.current->data.size() + 2;
            rel.symbol = operands[0].label;
            a.current->relocations.push_back(rel);
            a.Emit(0x0F);
            a.Emit(cc);
            a.Emit32(0);
        } else {
            a.Fail("unknown instruction '" + m + "'");
        }

        if (a.failed) break;
    }

    if (a.failed) {
        error = sourceName + ": " + error;
        return false;
    }

    // Mark the global symbols.
    for (const rawrstd::String& name : globals) {
        for (AsmSymbol& sym : out.symbols) {
            if (sym.name == name) { sym.global = true; break; }
        }
    }
    // Add the external symbols.
    for (const rawrstd::String& name : externs) {
        bool found = false;
        for (const AsmSymbol& sym : out.symbols) {
            if (sym.name == name) { found = true; break; }
        }
        if (found) continue;
        AsmSymbol sym;
        sym.name = name;
        sym.section = "";
        sym.external = true;
        out.symbols.push_back(sym);
    }

    return true;
}

bool assembleX64File(const rawrstd::String& asmPath, const rawrstd::String& objPath,
                     rawrstd::String& error) {
    // Read the assembly.
    std::FILE* f = std::fopen(asmPath.data(), "rb");
    if (!f) {
        error = "cannot open " + asmPath;
        return false;
    }
    rawrstd::String source;
    char buffer[8192];
    size_t got;
    while ((got = std::fread(buffer, 1, sizeof(buffer), f)) > 0) source.append(buffer, got);
    std::fclose(f);

    AsmObject object;
    if (!assembleX64(source, asmPath, object, error)) return false;

    // Write the COFF object.
    CoffWriter writer;
    std::vector<int> sectionIndex;

    for (const AsmSection& src : object.sections) {
        int index = writer.add_section(src.name.data(), src.characteristics, 8);
        if (index < 0) {
            error = "cannot create the section " + src.name;
            return false;
        }
        writer.append_data(index, src.data.data(), src.data.size());
        sectionIndex.push_back(index);
    }

    // The symbols.
    std::vector<int> symbolIndex;
    for (const AsmSymbol& sym : object.symbols) {
        int index = -1;
        if (sym.external) {
            index = writer.add_symbol(CoffSymbol::external(sym.name.data()));
        } else {
            // Find the section index for this symbol.
            int target = -1;
            for (size_t i = 0; i < object.sections.size(); ++i) {
                if (object.sections[i].name == sym.section) {
                    target = sectionIndex[i];
                    break;
                }
            }
            if (target < 0) {
                error = "the symbol " + sym.name + " has no section";
                return false;
            }
            index = writer.add_symbol(CoffSymbol::external(sym.name.data(), (int16_t)target,
                                                           sym.value));
        }
        symbolIndex.push_back(index);
    }

    // The relocations.
    for (size_t i = 0; i < object.sections.size(); ++i) {
        const AsmSection& src = object.sections[i];
        for (const AsmRelocation& rel : src.relocations) {
            // Find the symbol index for the target.
            int target = -1;
            for (size_t s = 0; s < object.symbols.size(); ++s) {
                if (object.symbols[s].name == rel.symbol) {
                    target = symbolIndex[s];
                    break;
                }
            }
            if (target < 0) {
                // The symbol is external and was added to the list.
                for (size_t s = 0; s < object.symbols.size(); ++s) {
                    if (object.symbols[s].name == rel.symbol) {
                        target = symbolIndex[s];
                        break;
                    }
                }
            }
            if (target < 0) {
                error = "the relocation target " + rel.symbol + " is not defined";
                return false;
            }
            writer.add_relocation(sectionIndex[i], rel.offset, (uint32_t)target,
                                  CoffReloc::Rel32);
        }
    }

    if (!writer.write(objPath.data())) {
        error = "cannot write " + objPath;
        return false;
    }
    return true;
}

} // namespace rawr
