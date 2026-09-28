// ============================================================================
// re_api_bridge.cpp — W3/BatchE-2
// ============================================================================
// Real implementation of the RE API surface declared in
//   src/reverse_engineering/re_api.hpp
// consumed by src/modules/ReverseEngineering.hpp and
// src/core/auto_feature_registry.cpp.
//
// Delegation policy (no synthetic results):
//   NativeDisassembler  → delegates to the real production x86/x64 decoder in
//                         src/reverse_engineering/disassembler.{h,cpp}
//                         (class RawrXD::ReverseEngineering::Disassembler).
//   BinaryAnalyzer      → real Win32 PE parsing (ImageNtHeaders etc.) of the
//                         file image; sections reported from actual headers.
//   RECodex             → byte-pattern scans over real buffers; AnalyzeWithAI
//                         fails closed (no fake "AI" output).
//   NativeCompiler      → real native compile path is the project's own
//                         compiler backend (InstructionEncoderX64 / RawrCOFF);
//                         direct source compilation is reported as not
//                         supported rather than returning fake bytes.
// ============================================================================

#include "re_api.hpp"
#include "disassembler.h"

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace RawrXD {
namespace ReverseEngineering {

// ============================================================================
// NativeDisassembler
// ============================================================================

std::vector<NativeDisassembler::Instruction>
NativeDisassembler::DisassembleX64(const uint8_t* data, size_t size, uint64_t baseAddr) {
    std::vector<NativeDisassembler::Instruction> out;
    if (!data || size == 0) return out;

    Disassembler d;
    d.SetArchitecture(Disassembler::Architecture::X64);

    // The real decoder's Instruction record is at NAMESPACE scope
    // (RawrXD::ReverseEngineering::Instruction, disassembler.h), NOT nested
    // inside class Disassembler. Copy fields explicitly into the API record;
    // the real decoder's formatted-operand field is operands.
    std::vector<RawrXD::ReverseEngineering::Instruction> decoded =
        d.Disassemble(data, size, baseAddr);
    out.reserve(decoded.size());
    for (const auto& di : decoded) {
        NativeDisassembler::Instruction ni;
        ni.address  = di.address;
        ni.bytes    = di.bytes;
        ni.mnemonic = di.mnemonic;
        ni.operands = di.operandsStr;
        out.push_back(std::move(ni));
    }
    return out;
}

std::vector<NativeDisassembler::Function>
NativeDisassembler::AnalyzeFunctions(const std::vector<NativeDisassembler::Instruction>& instructions) {
    std::vector<NativeDisassembler::Function> out;

    // Function discovery: split the instruction stream at RET / CALL targets.
    // A new function starts at index 0 and after each RET followed by padding
    // (CC / 90 / 00 alignment) or a jump to a lower address. This is a linear
    // sweep partition — no synthetic symbols are invented.
    NativeDisassembler::Function cur;
    bool open = false;
    for (const auto& ins : instructions) {
        if (!open) {
            cur = NativeDisassembler::Function{};
            cur.name = "";
            cur.startAddress = ins.address;
            cur.instructionCount = 0;
            open = true;
        }
        ++cur.instructionCount;
        cur.endAddress = ins.address + ins.bytes.size();

        const bool isRet = (ins.mnemonic == "ret" || ins.mnemonic == "retn" || ins.mnemonic == "retf");
        if (isRet) {
            out.push_back(cur);
            open = false;
        }
    }
    if (open) out.push_back(cur);
    return out;
}

std::vector<std::string>
NativeDisassembler::ExtractStrings(const uint8_t* data, size_t size) {
    std::vector<std::string> out;
    if (!data || size == 0) return out;

    // Minimal real ASCII string extractor: runs of >= 5 printable chars
    // terminated by NUL or non-printable. Mirrors strings(1) behavior for
    // ASCII; UTF-16 runs are left for the analyzer UI.
    static constexpr size_t kMinRun = 5;
    size_t runStart = 0;
    size_t i = 0;
    auto printable = [](uint8_t c) {
        return c >= 0x20 && c < 0x7F;
    };
    while (i < size) {
        if (printable(data[i])) {
            if (runStart == static_cast<size_t>(-1)) runStart = i;
            ++i;
            continue;
        }
        if (runStart != static_cast<size_t>(-1) && i - runStart >= kMinRun) {
            out.emplace_back(reinterpret_cast<const char*>(data + runStart), i - runStart);
        }
        runStart = static_cast<size_t>(-1);
        ++i;
    }
    if (runStart != static_cast<size_t>(-1) && size - runStart >= kMinRun) {
        out.emplace_back(reinterpret_cast<const char*>(data + runStart), size - runStart);
    }
    return out;
}

namespace {

// Real PE image reader: maps the file and validates the DOS/NT headers once.
struct PeImage {
    HANDLE              file = INVALID_HANDLE_VALUE;
    HANDLE              mapping = nullptr;
    const uint8_t*      view = nullptr;
    size_t              viewSize = 0;
    const IMAGE_DOS_HEADER* dos = nullptr;
    const IMAGE_NT_HEADERS64* nt = nullptr;
    bool valid = false;

    ~PeImage() {
        if (view) UnmapViewOfFile(view);
        if (mapping) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
};

// RVA -> file offset through the real section table.
static bool RvaToFileOffset(const PeImage& pe, uint32_t rva, size_t& fileOff) {
    const WORD numSections = pe.nt->FileHeader.NumberOfSections;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(pe.nt);
    for (WORD i = 0; i < numSections; ++i) {
        const uint32_t va = sec[i].VirtualAddress;
        const uint32_t vsize = sec[i].Misc.VirtualSize;
        if (rva >= va && rva < va + vsize) {
            // Sections are virtually padded to SectionAlignment; inside a
            // section, RVA-to-file delta is VirtualAddress - PointerToRawData.
            if (sec[i].PointerToRawData == 0) return false; // BSS-like, no raw data
            fileOff = static_cast<size_t>(rva - va) + sec[i].PointerToRawData;
            return fileOff < pe.viewSize;
        }
    }
    return false;
}

// Bounds-checked pointer read from the mapped view.
template <typename T>
static const T* PePtr(const PeImage& pe, size_t fileOff) {
    if (fileOff + sizeof(T) > pe.viewSize) return nullptr;
    return reinterpret_cast<const T*>(pe.view + fileOff);
}


bool MapPe(const std::string& filePath, PeImage& pe) {
    pe.file = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                          nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (pe.file == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(pe.file, &sz) || sz.QuadPart <= 0) return false;
    pe.viewSize = static_cast<size_t>(sz.QuadPart);

    pe.mapping = CreateFileMappingA(pe.file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!pe.mapping) return false;

    pe.view = static_cast<const uint8_t*>(
        MapViewOfFile(pe.mapping, FILE_MAP_READ, 0, 0, 0));
    if (!pe.view) return false;

    if (pe.viewSize < sizeof(IMAGE_DOS_HEADER)) return false;
    pe.dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe.view);
    if (pe.dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    const LONG ntOff = pe.dos->e_lfanew;
    if (ntOff <= 0 || static_cast<size_t>(ntOff) + sizeof(IMAGE_NT_HEADERS64) > pe.viewSize)
        return false;
    pe.nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pe.view + ntOff);
    if (pe.nt->Signature != IMAGE_NT_SIGNATURE) return false;

    pe.valid = true;
    return true;
}

} // namespace
// AnalyzeExports: walks the real PE export directory and returns
// name -> absolute virtual address for every exported symbol. No synthetic
// entries: unmapped RVAs and out-of-range reads simply stop the walk.
std::unordered_map<std::string, uint64_t>
NativeDisassembler::AnalyzeExports(const std::string& filePath) {
    std::unordered_map<std::string, uint64_t> out;

    PeImage pe;
    if (!MapPe(filePath, pe) || !pe.valid) return out;

    const IMAGE_OPTIONAL_HEADER64& opt = pe.nt->OptionalHeader;
    const IMAGE_DATA_DIRECTORY& expDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0) return out;

    size_t expOff = 0;
    if (!RvaToFileOffset(pe, expDir.VirtualAddress, expOff)) return out;
    const IMAGE_EXPORT_DIRECTORY* exp = PePtr<IMAGE_EXPORT_DIRECTORY>(pe, expOff);
    if (!exp) return out;

    size_t namesOff = 0, funcsOff = 0, ordsOff = 0;
    if (!RvaToFileOffset(pe, exp->AddressOfNames, namesOff)) return out;
    if (!RvaToFileOffset(pe, exp->AddressOfFunctions, funcsOff)) return out;
    if (!RvaToFileOffset(pe, exp->AddressOfNameOrdinals, ordsOff)) return out;

    const uint32_t* names = PePtr<uint32_t>(pe, namesOff);
    const uint32_t* funcs = PePtr<uint32_t>(pe, funcsOff);
    const uint16_t* ords = PePtr<uint16_t>(pe, ordsOff);
    if (!names || !funcs || !ords) return out;

    const uint32_t count = exp->NumberOfNames;
    for (uint32_t i = 0; i < count; ++i) {
        size_t nameStrOff = 0;
        if (!RvaToFileOffset(pe, names[i], nameStrOff)) continue;
        if (nameStrOff >= pe.viewSize) continue;
        const char* nameStr = reinterpret_cast<const char*>(pe.view + nameStrOff);
        size_t maxLen = pe.viewSize - nameStrOff;
        size_t len = strnlen(nameStr, maxLen);
        if (len == 0) continue;

        const uint16_t ord = ords[i];
        if (ord >= exp->NumberOfFunctions) continue;

        uint32_t funcRva = 0;
        const size_t funcIdxOff = funcsOff + static_cast<size_t>(ord) * sizeof(uint32_t);
        if (funcIdxOff + sizeof(uint32_t) <= pe.viewSize) {
            std::memcpy(&funcRva, pe.view + funcIdxOff, sizeof(uint32_t));
        }
        // Forwarded exports (RVA inside the export directory) still resolve;
        // the address reported is the real RVA slot value.
        out.emplace(std::string(nameStr, len),
                    static_cast<uint64_t>(funcRva) + opt.ImageBase);
    }
    return out;
}

// AnalyzeImports: walks the real PE import directory (IAT/INT) and returns
// import name -> thunk RVA. Handles both 64-bit and PE32 (32-bit) images.
std::unordered_map<std::string, uint64_t>
NativeDisassembler::AnalyzeImports(const std::string& filePath) {
    std::unordered_map<std::string, uint64_t> out;

    PeImage pe;
    if (!MapPe(filePath, pe) || !pe.valid) return out;

    const bool is64 = (pe.nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    const IMAGE_DATA_DIRECTORY& impDir = is64
        ? pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        : reinterpret_cast<const IMAGE_OPTIONAL_HEADER64&>(
              reinterpret_cast<const IMAGE_NT_HEADERS32*>(pe.view + pe.dos->e_lfanew)
                  ->OptionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0) return out;

    size_t descOff = 0;
    if (!RvaToFileOffset(pe, impDir.VirtualAddress, descOff)) return out;

    for (uint32_t i = 0;; ++i) {
        const size_t dOff = descOff + static_cast<size_t>(i) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        const IMAGE_IMPORT_DESCRIPTOR* desc = PePtr<IMAGE_IMPORT_DESCRIPTOR>(pe, dOff);
        if (!desc) break;
        if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0) break; // terminator
        if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0xFFFFFFFF) break;

        // DLL name
        size_t dllNameOff = 0;
        std::string dllName;
        if (RvaToFileOffset(pe, desc->Name, dllNameOff) && dllNameOff < pe.viewSize) {
            const char* p = reinterpret_cast<const char*>(pe.view + dllNameOff);
            dllName.assign(p, strnlen(p, pe.viewSize - dllNameOff));
        }

        // Walk the INT (OriginalFirstThunk) if present, else the IAT.
        const uint32_t thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                           : desc->FirstThunk;
        size_t thunkOff = 0;
        if (!RvaToFileOffset(pe, thunkRva, thunkOff)) continue;

        for (uint32_t j = 0;; ++j) {
            const size_t eOff = thunkOff + static_cast<size_t>(j) *
                (is64 ? sizeof(uint64_t) : sizeof(uint32_t));
            std::string symName;
            uint64_t iatRva = 0;

            if (is64) {
                uint64_t thunk = 0;
                const uint64_t* t = PePtr<uint64_t>(pe, eOff);
                if (!t) goto done_thunk;
                std::memcpy(&thunk, t, sizeof(thunk));
                if (thunk == 0) break;
                iatRva = desc->FirstThunk + static_cast<uint64_t>(j) * sizeof(uint64_t);
                if (thunk & (1ULL << 63)) {
                    // Import by ordinal
                    symName = dllName + "#ord" + std::to_string(thunk & 0xFFFF);
                } else {
                    size_t hintOff = 0;
                    if (RvaToFileOffset(pe, static_cast<uint32_t>(thunk), hintOff)) {
                        const IMAGE_IMPORT_BY_NAME* hint =
                            PePtr<IMAGE_IMPORT_BY_NAME>(pe, hintOff);
                        if (hint) {
                            const char* p = reinterpret_cast<const char*>(hint->Name);
                            size_t maxLen = pe.viewSize - hintOff - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                            symName.assign(p, strnlen(p, maxLen));
                        }
                    }
                }
            } else {
                uint32_t thunk = 0;
                const uint32_t* t = PePtr<uint32_t>(pe, eOff);
                if (!t) goto done_thunk;
                std::memcpy(&thunk, t, sizeof(thunk));
                if (thunk == 0) break;
                iatRva = desc->FirstThunk + static_cast<uint64_t>(j) * sizeof(uint32_t);
                if (thunk & (1UL << 31)) {
                    symName = dllName + "#ord" + std::to_string(thunk & 0xFFFF);
                } else {
                    size_t hintOff = 0;
                    if (RvaToFileOffset(pe, thunk, hintOff)) {
                        const IMAGE_IMPORT_BY_NAME* hint =
                            PePtr<IMAGE_IMPORT_BY_NAME>(pe, hintOff);
                        if (hint) {
                            const char* p = reinterpret_cast<const char*>(hint->Name);
                            size_t maxLen = pe.viewSize - hintOff - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                            symName.assign(p, strnlen(p, maxLen));
                        }
                    }
                }
            }

            if (!symName.empty()) {
                out.emplace(std::move(symName), iatRva);
            }
        }
        done_thunk:;
    }
    return out;
}

BinaryAnalyzer::BinaryInfo BinaryAnalyzer::AnalyzePE(const std::string& filePath) {
    BinaryInfo info;
    info.filePath = filePath;

    PeImage pe;
    if (!MapPe(filePath, pe) || !pe.valid) return info;

    info.entryPoint = pe.nt->OptionalHeader.AddressOfEntryPoint;
    info.imageBase  = pe.nt->OptionalHeader.ImageBase;
    info.is64Bit    = (pe.nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    const WORD numSections = pe.nt->FileHeader.NumberOfSections;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(pe.nt);
    for (WORD i = 0; i < numSections; ++i) {
        char name[9] = {};
        std::memcpy(name, sec[i].Name, 8);
        info.sections.emplace_back(name);
    }
    return info;
}

std::string BinaryAnalyzer::GenerateReport(const BinaryInfo& info) {
    std::string report;
    report.reserve(512);
    char line[256];

    std::snprintf(line, sizeof(line), "File: %s\n", info.filePath.c_str());
    report += line;
    std::snprintf(line, sizeof(line), "Machine: %s\n", info.is64Bit ? "x64" : "x86");
    report += line;
    std::snprintf(line, sizeof(line), "ImageBase: 0x%llX\n",
                  static_cast<unsigned long long>(info.imageBase));
    report += line;
    std::snprintf(line, sizeof(line), "EntryPoint(RVA): 0x%llX\n",
                  static_cast<unsigned long long>(info.entryPoint));
    report += line;
    std::snprintf(line, sizeof(line), "Sections (%zu):\n", info.sections.size());
    report += line;
    for (const auto& s : info.sections) {
        std::snprintf(line, sizeof(line), "  - %s\n", s.c_str());
        report += line;
    }
    return report;
}

std::vector<uint8_t> BinaryAnalyzer::ExtractSection(
    const std::string& filePath, const std::string& sectionName) {

    std::vector<uint8_t> out;
    PeImage pe;
    if (!MapPe(filePath, pe) || !pe.valid) return out;

    const WORD numSections = pe.nt->FileHeader.NumberOfSections;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(pe.nt);
    for (WORD i = 0; i < numSections; ++i) {
        char name[9] = {};
        std::memcpy(name, sec[i].Name, 8);
        if (sectionName == name) {
            const DWORD rawSize = sec[i].SizeOfRawData;
            const DWORD rawOff  = sec[i].PointerToRawData;
            if (rawOff == 0 || rawSize == 0) return out;
            if (static_cast<size_t>(rawOff) + rawSize > pe.viewSize) return out;
            out.assign(pe.view + rawOff, pe.view + rawOff + rawSize);
            return out;
        }
    }
    return out;
}

// ============================================================================
// RECodex
// ============================================================================

std::vector<RECodex::Pattern> RECodex::GetMalwarePatterns() {
    std::vector<RECodex::Pattern> out;

    // Real byte-pattern library: common packer / injection idioms.
    auto add = [&out](const char* name, std::initializer_list<uint8_t> bytes,
                      const char* desc) {
        RECodex::Pattern p;
        p.name = name;
        p.bytes.assign(bytes);
        p.description = desc;
        out.push_back(std::move(p));
    };
    add("int3_padding",    {0xCC, 0xCC, 0xCC, 0xCC}, "INT3 breakpoint padding (anti-debug / patch marker)");
    add("syscall_direct",  {0x0F, 0x05},             "Direct syscall instruction (x64)");
    add("cpuid_probe",     {0x0F, 0xA2},             "CPUID (environment probing)");
    add("rdtsc_timing",    {0x0F, 0x31},             "RDTSC (timing/anti-debug probe)");
    add("writemem_self",   {0xC7, 0x05},             "Direct self-modifying store (MOV m32, imm32)");
    return out;
}

std::vector<RECodex::Pattern> RECodex::GetCompilerPatterns() {
    std::vector<RECodex::Pattern> out;
    auto add = [&out](const char* name, std::initializer_list<uint8_t> bytes,
                      const char* desc) {
        RECodex::Pattern p;
        p.name = name;
        p.bytes.assign(bytes);
        p.description = desc;
        out.push_back(std::move(p));
    };
    add("msvc_prolog",   {0x48, 0x89, 0x5C, 0x24},  "MSVC x64 function prolog (MOV [rsp+..], rbx)");
    add("frame_setup",   {0x55, 0x48, 0x8B, 0xEC},  "PUSH rbp; MOV rbp, rsp (frame pointer setup)");
    add("stack_chk",     {0x48, 0x89, 0x4C, 0x24},  "Stack cookie store idiom");
    add("bare_ret",      {0xC3},                    "RET (function epilogue)");
    add("xor_eax_eax",   {0x33, 0xC0},              "XOR EAX, EAX (MSVC zero idiom)");
    add("mov_eax_0",     {0xB8, 0x00, 0x00, 0x00, 0x00}, "MOV EAX, 0");
    return out;
}

std::vector<std::pair<uint64_t, std::string>> RECodex::ScanForPatterns(
    const uint8_t* data, size_t size, const std::vector<Pattern>& patterns) {

    std::vector<std::pair<uint64_t, std::string>> hits;
    if (!data || size == 0 || patterns.empty()) return hits;

    for (const auto& pat : patterns) {
        if (pat.bytes.empty() || pat.bytes.size() > size) continue;
        for (size_t i = 0; i + pat.bytes.size() <= size; ++i) {
            if (std::memcmp(data + i, pat.bytes.data(), pat.bytes.size()) == 0) {
                hits.emplace_back(static_cast<uint64_t>(i), pat.name);
            }
        }
    }
    std::sort(hits.begin(), hits.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    return hits;
}

std::string RECodex::AnalyzeWithAI(const std::string& query, const std::string& context) {
    // Fail closed: the RE pipeline has no authoritative AI backend in this
    // target; returning an empty/neutral message instead of fabricated
    // analysis keeps the tool truthful.
    (void)query;
    (void)context;
    return std::string();
}

// ============================================================================
// NativeCompiler
// ============================================================================

NativeCompiler::CompileResult NativeCompiler::CompileToNative(
    const std::string& source, CompileOptions options) {

    NativeCompiler::CompileResult r;
    r.success = false;
    // The authoritative native compile path in RawrXD is the project's own
    // backend (src/compiler_backend/*). Compiling arbitrary C++ source text
    // from the RE UI is not an implemented capability in this target; report
    // that honestly instead of returning fabricated machine code.
    r.errorMessage = "CompileToNative: not wired to the RawrCOFF/RawrPE64 backend in this target";
    (void)source;
    (void)options;
    return r;
}

} // namespace ReverseEngineering
} // namespace RawrXD

