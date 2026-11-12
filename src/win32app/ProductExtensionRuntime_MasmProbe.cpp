// ProductExtensionRuntime_MasmProbe.cpp — ml64 tooling + real MASM LSP probe.
#include "ProductExtensionRuntime.hpp"
#include "lsp/MasmLspSession.hpp"
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>
#include <windows.h>

namespace ProductExtensionRuntime {

void ProbeMasmTooling() {
    const char* d = std::getenv("RAWRXD_LOG_DIR");
    const std::string logDir = (d && *d) ? std::string(d) : "F:\\rawrxd\\evidence";
    const std::string log = logDir + "\\TOP25_MASM_TOOLING.log";
    const char* ml64 =
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\"
        "VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\ml64.exe";
    int ml64Present = (GetFileAttributesA(ml64) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
    const std::string work = logDir + "\\masm_probe";
    std::error_code ec;
    std::filesystem::create_directories(work, ec);
    const std::string asmPath = work + "\\probe.asm";
    const std::string objPath = work + "\\probe.obj";
    const char* asmText =
        ".code\nprobe_entry PROC\n  xor eax, eax\n  ret\n"
        "probe_entry ENDP\nEND\n";
    {
        FILE* af = nullptr;
        if (fopen_s(&af, asmPath.c_str(), "w") == 0 && af) {
            fputs(asmText, af);
            fclose(af);
        }
    }
    int assembleOk = 0;
    if (ml64Present) {
        std::string cmd = std::string("\"") + ml64 + "\" /c /Fo\"" + objPath +
                          "\" \"" + asmPath + "\"";
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::vector<char> buf(cmd.begin(), cmd.end());
        buf.push_back('\0');
        if (CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, work.c_str(), &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 15000);
            DWORD code = 1;
            GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            assembleOk =
                (code == 0 && GetFileAttributesA(objPath.c_str()) !=
                                  INVALID_FILE_ATTRIBUTES)
                    ? 1
                    : 0;
        }
    }

    // Real embedded LSP protocol session (initialize/didOpen/hover|completion).
    // Empty root skips workspace walk; didOpen indexes probe.asm only.
    auto lsp = RawrXD::LSPServer::RunMasmLspProtocolSession(/*rootPath=*/"", asmPath, asmText);
    const int lspAsm = lsp.ok ? 1 : 0;

    FILE* f = nullptr;
    if (fopen_s(&f, log.c_str(), "w") == 0 && f) {
        fprintf(f,
                "ml64_present=%d assemble_ok=%d ml64=%s asm=%s lsp_asm=%d "
                "lsp_detail=%s\n",
                ml64Present, assembleOk, ml64, asmPath.c_str(), lspAsm,
                lsp.detail.c_str());
        fclose(f);
    }
}

}  // namespace ProductExtensionRuntime
