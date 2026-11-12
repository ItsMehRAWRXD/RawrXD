// CLI LSP product path (C36/C37/C38) — real clangd JSON-RPC, no stubs.
#include <windows.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace rawr_lsp {

struct Proc {
    HANDLE proc = nullptr;
    HANDLE stdinWr = nullptr;
    HANDLE stdoutRd = nullptr;
    ~Proc() {
        if (stdinWr) CloseHandle(stdinWr);
        if (stdoutRd) CloseHandle(stdoutRd);
        if (proc) {
            TerminateProcess(proc, 1);
            CloseHandle(proc);
        }
    }
};

static std::string findClangd() {
    const char* env = std::getenv("RAWRXD_CLANGD");
    if (env && *env && GetFileAttributesA(env) != INVALID_FILE_ATTRIBUTES)
        return env;
    const char* cands[] = {
        "C:\\Program Files\\LLVM\\bin\\clangd.exe",
        "C:\\Program Files (x86)\\LLVM\\bin\\clangd.exe",
        "clangd.exe",
        "clangd"};
    for (const char* c : cands) {
        if (GetFileAttributesA(c) != INVALID_FILE_ATTRIBUTES) return c;
        char buf[MAX_PATH]{};
        if (SearchPathA(nullptr, c, nullptr, MAX_PATH, buf, nullptr)) return buf;
    }
    return {};
}

static bool spawn(Proc& p, const std::string& exe) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE inR = nullptr, outW = nullptr;
    if (!CreatePipe(&inR, &p.stdinWr, &sa, 0)) return false;
    if (!CreatePipe(&p.stdoutRd, &outW, &sa, 0)) {
        CloseHandle(inR);
        CloseHandle(p.stdinWr);
        p.stdinWr = nullptr;
        return false;
    }
    SetHandleInformation(p.stdinWr, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(p.stdoutRd, HANDLE_FLAG_INHERIT, 0);
    // Keep stderr off stdout — clangd logs otherwise break Content-Length.
    HANDLE hNul = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = inR;
    si.hStdOutput = outW;
    si.hStdError = (hNul != INVALID_HANDLE_VALUE) ? hNul : outW;
    PROCESS_INFORMATION pi{};
    std::string cmd = "\"" + exe + "\" --background-index=false --header-insertion=never";
    std::vector<char> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back('\0');
    const BOOL ok = CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(inR);
    CloseHandle(outW);
    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    p.proc = pi.hProcess;
    return true;
}

static bool writeAll(HANDLE h, const char* data, DWORD n) {
    DWORD left = n;
    while (left) {
        DWORD w = 0;
        if (!WriteFile(h, data + (n - left), left, &w, nullptr) || w == 0) return false;
        left -= w;
    }
    return true;
}

static bool sendRpc(Proc& p, int id, const std::string& method, const std::string& paramsJson) {
    std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                       ",\"method\":\"" + method + "\",\"params\":" + paramsJson + "}";
    std::string frame = "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    return writeAll(p.stdinWr, frame.data(), static_cast<DWORD>(frame.size()));
}

static bool sendNotify(Proc& p, const std::string& method, const std::string& paramsJson) {
    std::string body = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method +
                       "\",\"params\":" + paramsJson + "}";
    std::string frame = "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    return writeAll(p.stdinWr, frame.data(), static_cast<DWORD>(frame.size()));
}

static bool readMessage(Proc& p, std::string& out, DWORD timeoutMs) {
    out.clear();
    std::string buf;
    const DWORD deadline = GetTickCount() + timeoutMs;
    while (GetTickCount() < deadline) {
        DWORD avail = 0;
        if (!PeekNamedPipe(p.stdoutRd, nullptr, 0, nullptr, &avail, nullptr)) return false;
        if (avail == 0) {
            Sleep(20);
            continue;
        }
        char tmp[4096];
        DWORD got = 0;
        const DWORD n = (avail > sizeof(tmp)) ? sizeof(tmp) : avail;
        if (!ReadFile(p.stdoutRd, tmp, n, &got, nullptr) || got == 0) return false;
        buf.append(tmp, tmp + got);
        auto hdr = buf.find("\r\n\r\n");
        if (hdr == std::string::npos) continue;
        size_t len = 0;
        auto cl = buf.find("Content-Length:");
        if (cl == std::string::npos || cl > hdr) continue;
        len = static_cast<size_t>(std::atoi(buf.c_str() + cl + 15));
        const size_t bodyStart = hdr + 4;
        if (buf.size() < bodyStart + len) continue;
        out = buf.substr(bodyStart, len);
        buf.erase(0, bodyStart + len);
        return true;
    }
    return false;
}

// Drain until response with matching id (skip notifications / unmatched).
static bool readResponseId(Proc& p, int id, std::string& out, DWORD timeoutMs) {
    const DWORD deadline = GetTickCount() + timeoutMs;
    const std::string idKey = "\"id\":" + std::to_string(id);
    while (GetTickCount() < deadline) {
        const DWORD left = deadline - GetTickCount();
        std::string msg;
        if (!readMessage(p, msg, left > 50 ? left : 50)) return false;
        if (msg.find(idKey) != std::string::npos &&
            msg.find("\"result\"") != std::string::npos)
        {
            out = msg;
            return true;
        }
        // notifications / other ids ignored
    }
    return false;
}

static int countOccurrences(const std::string& s, const char* needle) {
    int n = 0;
    size_t pos = 0;
    const size_t len = std::strlen(needle);
    while ((pos = s.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += len;
    }
    return n;
}

// Returns 0 on C36 path success (init + hover|completion|definition).
int ProbeClangd(const std::string& workspaceRoot, std::string& outLine) {
    const std::string clangd = findClangd();
    if (clangd.empty()) {
        outLine = "LSP_PROBE server=missing initialized=0 hover=0 rename=0 "
                  "completion=0 definition=0 diagnostics=0";
        return 1;
    }
    Proc p;
    if (!spawn(p, clangd)) {
        outLine = "LSP_PROBE server=" + clangd + " spawn=0 initialized=0";
        return 1;
    }
    auto toUri = [](std::string path) {
        for (char& c : path)
            if (c == '\\') c = '/';
        return "file:///" + path;
    };
    const std::string probePath = workspaceRoot + "\\evidence\\TOP25_CLI_LSP_PROBE.cpp";
    const std::string probeSrc =
        "int add(int a, int b) { return a + b; }\n"
        "int main() { return add(1, 2); }\n";
    {
        std::ofstream out(probePath, std::ios::trunc);
        if (out) out << probeSrc;
    }
    const std::string rootUri = toUri(workspaceRoot);
    const std::string initParams =
        "{\"processId\":null,\"rootUri\":\"" + rootUri +
        "\",\"capabilities\":{\"textDocument\":{\"hover\":{},\"rename\":{},"
        "\"completion\":{},\"definition\":{},\"publishDiagnostics\":{}}}}";
    if (!sendRpc(p, 1, "initialize", initParams)) {
        outLine = "LSP_PROBE server=" + clangd + " initialize_send=0";
        return 1;
    }
    std::string msg;
    int initialized = 0;
    if (readResponseId(p, 1, msg, 12000)) initialized = 1;
    if (!initialized) {
        outLine = "LSP_PROBE server=" + clangd + " initialized=0 hover=0 rename=0 "
                  "completion=0 definition=0 diagnostics=0";
        return 1;
    }
    sendNotify(p, "initialized", "{}");
    const std::string uri = toUri(probePath);
    const std::string openParams =
        "{\"textDocument\":{\"uri\":\"" + uri +
        "\",\"languageId\":\"cpp\",\"version\":1,\"text\":\"" +
        "int add(int a, int b) { return a + b; }\\n"
        "int main() { return add(1, 2); }\\n\"}}";
    sendNotify(p, "textDocument/didOpen", openParams);
    // Collect publishDiagnostics while clangd indexes the buffer.
    int diagnostics = 0;
    {
        const DWORD dline = GetTickCount() + 1500;
        while (GetTickCount() < dline) {
            std::string nmsg;
            if (!readMessage(p, nmsg, 200)) continue;
            if (nmsg.find("publishDiagnostics") != std::string::npos)
                diagnostics = countOccurrences(nmsg, "\"severity\"");
        }
    }
    sendRpc(p, 2, "textDocument/hover",
            "{\"textDocument\":{\"uri\":\"" + uri +
                "\"},\"position\":{\"line\":1,\"character\":18}}");
    int hover = 0;
    if (readResponseId(p, 2, msg, 10000) && msg.find("null") == std::string::npos &&
        msg.find("\"contents\"") != std::string::npos)
        hover = 1;
    sendRpc(p, 3, "textDocument/completion",
            "{\"textDocument\":{\"uri\":\"" + uri +
                "\"},\"position\":{\"line\":1,\"character\":20}}");
    int completion = 0;
    if (readResponseId(p, 3, msg, 10000)) {
        completion = countOccurrences(msg, "\"label\"");
        if (completion == 0 && msg.find("\"items\"") != std::string::npos) completion = 1;
    }
    sendRpc(p, 4, "textDocument/definition",
            "{\"textDocument\":{\"uri\":\"" + uri +
                "\"},\"position\":{\"line\":1,\"character\":18}}");
    int definition = 0;
    if (readResponseId(p, 4, msg, 10000) &&
        (msg.find("\"uri\"") != std::string::npos ||
         msg.find("\"range\"") != std::string::npos))
        definition = 1;
    sendRpc(p, 5, "textDocument/rename",
            "{\"textDocument\":{\"uri\":\"" + uri +
                "\"},\"position\":{\"line\":0,\"character\":4},\"newName\":\"sum\"}");
    int rename = 0;
    if (readResponseId(p, 5, msg, 10000) && msg.find("\"changes\"") != std::string::npos)
        rename = 1;
    outLine = "LSP_PROBE server=" + clangd +
              " initialized=" + std::to_string(initialized) +
              " hover=" + std::to_string(hover) +
              " rename=" + std::to_string(rename) +
              " completion=" + std::to_string(completion) +
              " definition=" + std::to_string(definition) +
              " diagnostics=" + std::to_string(diagnostics) +
              " backend=clangd";
    // C36: init + at least one of hover/completion/definition.
    return (initialized && (hover || completion > 0 || definition)) ? 0 : 1;
}

}  // namespace rawr_lsp
