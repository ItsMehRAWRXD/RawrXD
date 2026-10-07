#pragma once
// ImportSpace68.hpp
// Dependency-free Win32 PE import-table receipt generator.
// Scope: imports of the current executable image only.
// It does NOT prove absence of statically linked code or runtime-loaded code.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace Deep2Cert {

static constexpr uint32_t IMPORT_SPACE_CAP = 68;

struct ImportSpace68Receipt {
    bool parseOk = false;
    bool overflow = false;
    uint32_t dllCount = 0;
    uint32_t symbolCount = 0;
    uint32_t forbiddenHits = 0;
    uint32_t networkCapableHits = 0;
    uint32_t evidenceUsed = 0;

    struct Hit {
        char dll[96]{};
        char symbol[128]{};
        char rule[48]{};
    };
    Hit evidence[IMPORT_SPACE_CAP]{};
};

static inline bool IsAsciiIEqual(char a, char b) {
    if (a >= 'A' && a <= 'Z') a = char(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = char(b - 'A' + 'a');
    return a == b;
}

static inline bool ContainsI(const char* s, const char* needle) {
    if (!s || !needle || !*needle) return false;
    for (; *s; ++s) {
        const char* a = s;
        const char* b = needle;
        while (*a && *b && IsAsciiIEqual(*a, *b)) {
            ++a;
            ++b;
        }
        if (!*b) return true;
    }
    return false;
}

static inline bool RvaRangeValid(uint32_t rva, uint64_t bytes, uint32_t imageSize) {
    if (rva == 0) return false;
    const uint64_t end = uint64_t(rva) + bytes;
    return rva < imageSize && end <= imageSize && end >= rva;
}

static inline void CopyField(char* dst, size_t cap, const char* src) {
    if (!dst || cap == 0) return;
    dst[0] = '\0';
    if (!src) return;
#if defined(_MSC_VER)
    strncpy_s(dst, cap, src, _TRUNCATE);
#else
    std::strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
#endif
}

static inline void RecordHit(ImportSpace68Receipt& r,
                             const char* dll,
                             const char* symbol,
                             const char* rule,
                             bool forbidden,
                             bool networkCapable) {
    if (forbidden) ++r.forbiddenHits;
    if (networkCapable) ++r.networkCapableHits;

    if (r.evidenceUsed >= IMPORT_SPACE_CAP) {
        r.overflow = true;
        return;
    }

    auto& h = r.evidence[r.evidenceUsed++];
    CopyField(h.dll, sizeof(h.dll), dll ? dll : "");
    CopyField(h.symbol, sizeof(h.symbol), symbol ? symbol : "");
    CopyField(h.rule, sizeof(h.rule), rule ? rule : "");
}

static inline bool IsForbiddenDll(const char* dll, const char** rule) {
    static const char* const tokens[] = {
        "ollama",
        "llama",
        "ggml",
        nullptr
    };
    for (uint32_t i = 0; tokens[i]; ++i) {
        if (ContainsI(dll, tokens[i])) {
            if (rule) *rule = tokens[i];
            return true;
        }
    }
    return false;
}

static inline bool IsForbiddenSymbol(const char* sym, const char** rule) {
    static const char* const tokens[] = {
        "ollama",
        "llama_",
        "ggml_",
        nullptr
    };
    for (uint32_t i = 0; tokens[i]; ++i) {
        if (ContainsI(sym, tokens[i])) {
            if (rule) *rule = tokens[i];
            return true;
        }
    }
    return false;
}

static inline bool IsNetworkCapableImport(const char* dll,
                                          const char* sym,
                                          const char** rule) {
    // Informational only. These imports are not forbidden by this scanner.
    static const char* const dllTokens[] = {
        "winhttp",
        "wininet",
        "ws2_32",
        "urlmon",
        "libcurl",
        "curl",
        nullptr
    };
    static const char* const symTokens[] = {
        "WinHttp",
        "InternetOpen",
        "InternetConnect",
        "HttpSendRequest",
        "WSAStartup",
        "connect",
        "send",
        "recv",
        "URLDownloadToFile",
        "curl_",
        nullptr
    };

    for (uint32_t i = 0; dllTokens[i]; ++i) {
        if (ContainsI(dll, dllTokens[i])) {
            if (rule) *rule = dllTokens[i];
            return true;
        }
    }
    for (uint32_t i = 0; symTokens[i]; ++i) {
        if (ContainsI(sym, symTokens[i])) {
            if (rule) *rule = symTokens[i];
            return true;
        }
    }
    return false;
}

static inline ImportSpace68Receipt ScanCurrentExeImports68() {
    ImportSpace68Receipt out{};

    auto* base = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    if (!base) return out;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return out;

    const uint32_t ntOff = static_cast<uint32_t>(dos->e_lfanew);

#ifdef _WIN64
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + ntOff);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return out;
    const uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    const IMAGE_DATA_DIRECTORY dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
#else
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + ntOff);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return out;
    const uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    const IMAGE_DATA_DIRECTORY dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
#endif

    if (imageSize == 0) return out;

    // No import directory is a valid scan result.
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        out.parseOk = true;
        return out;
    }

    if (!RvaRangeValid(dir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR), imageSize))
        return out;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    const uint32_t maxDesc =
        (dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) + 1u;

    for (uint32_t di = 0; di < maxDesc; ++di, ++desc) {
        if (desc->Name == 0 && desc->FirstThunk == 0 &&
            desc->OriginalFirstThunk == 0)
            break;

        if (!RvaRangeValid(desc->Name, 1, imageSize))
            return out;

        const char* dll = reinterpret_cast<const char*>(base + desc->Name);
        ++out.dllCount;

        const char* dllRule = nullptr;
        if (IsForbiddenDll(dll, &dllRule))
            RecordHit(out, dll, "", dllRule, true, false);

        uint32_t thunkRva =
            desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

        if (!RvaRangeValid(thunkRva,
#ifdef _WIN64
                           sizeof(IMAGE_THUNK_DATA64),
#else
                           sizeof(IMAGE_THUNK_DATA32),
#endif
                           imageSize))
            return out;

#ifdef _WIN64
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + thunkRva);
        for (uint32_t ti = 0; ; ++ti, ++thunk) {
            const uint64_t u = thunk->u1.AddressOfData;
            if (u == 0) break;
            ++out.symbolCount;

            if (IMAGE_SNAP_BY_ORDINAL64(u)) {
                continue;
            }

            const uint32_t ibnRva = static_cast<uint32_t>(u);
            if (!RvaRangeValid(ibnRva, sizeof(IMAGE_IMPORT_BY_NAME), imageSize))
                return out;

            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + ibnRva);
            const char* sym = reinterpret_cast<const char*>(ibn->Name);

            const char* rule = nullptr;
            if (IsForbiddenSymbol(sym, &rule))
                RecordHit(out, dll, sym, rule, true, false);

            const char* netRule = nullptr;
            if (IsNetworkCapableImport(dll, sym, &netRule))
                RecordHit(out, dll, sym, netRule, false, true);
        }
#else
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA32*>(base + thunkRva);
        for (uint32_t ti = 0; ; ++ti, ++thunk) {
            const uint32_t u = thunk->u1.AddressOfData;
            if (u == 0) break;
            ++out.symbolCount;

            if (IMAGE_SNAP_BY_ORDINAL32(u)) {
                continue;
            }

            const uint32_t ibnRva = u;
            if (!RvaRangeValid(ibnRva, sizeof(IMAGE_IMPORT_BY_NAME), imageSize))
                return out;

            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + ibnRva);
            const char* sym = reinterpret_cast<const char*>(ibn->Name);

            const char* rule = nullptr;
            if (IsForbiddenSymbol(sym, &rule))
                RecordHit(out, dll, sym, rule, true, false);

            const char* netRule = nullptr;
            if (IsNetworkCapableImport(dll, sym, &netRule))
                RecordHit(out, dll, sym, netRule, false, true);
        }
#endif
    }

    out.parseOk = true;
    return out;
}

static inline void EmitImportSpace68Receipt(FILE* f,
                                            const ImportSpace68Receipt& r) {
    if (!f) return;

    std::fprintf(f,
        "IMPORT_SPACE_68=1 "
        "IMPORT_SCAN=%s "
        "IMPORT_DLLS=%u "
        "IMPORT_SYMBOLS=%u "
        "IMPORT_FORBIDDEN_HITS=%u "
        "IMPORT_NETWORK_CAPABLE_HITS=%u "
        "IMPORT_SPACE_USED=%u "
        "IMPORT_SPACE_CAP=%u "
        "IMPORT_SPACE_OVERFLOW=%u\n",
        r.parseOk ? "PASS" : "FAIL",
        r.dllCount,
        r.symbolCount,
        r.forbiddenHits,
        r.networkCapableHits,
        r.evidenceUsed,
        IMPORT_SPACE_CAP,
        r.overflow ? 1u : 0u);

    for (uint32_t i = 0; i < r.evidenceUsed; ++i) {
        const auto& h = r.evidence[i];
        std::fprintf(f,
            "IMPORT_EVIDENCE_%02u DLL=%s SYMBOL=%s RULE=%s\n",
            i,
            h.dll[0] ? h.dll : "-",
            h.symbol[0] ? h.symbol : "-",
            h.rule[0] ? h.rule : "-");
    }

    const bool certPass =
        r.parseOk &&
        !r.overflow &&
        r.forbiddenHits == 0;

    std::fprintf(f,
        "IMPORT_CERT_DISPOSITION=%s "
        "IMPORT_CERT_BLOCKED_AT=%s\n",
        certPass ? "PASS" : "BLOCKED",
        certPass ? "NONE" :
        (!r.parseOk ? "PE_IMPORT_PARSE" :
         r.overflow ? "IMPORT_SPACE_OVERFLOW" :
                      "FORBIDDEN_IMPORT"));
}

static inline bool ImportSpace68CertPass(const ImportSpace68Receipt& r) {
    return r.parseOk && !r.overflow && r.forbiddenHits == 0;
}

} // namespace Deep2Cert
