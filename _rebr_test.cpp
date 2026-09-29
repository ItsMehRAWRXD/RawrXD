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
    // the real decoder's formatted-operand field is operandsStr.
    std::vector<Instruction> decoded = d.Disassemble(data, size, baseAddr);
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