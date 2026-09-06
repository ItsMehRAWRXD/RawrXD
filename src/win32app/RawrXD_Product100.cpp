#include "RawrXD_Product100.hpp"
#include "RawrXD_Product100_x64.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <sstream>
#include <string>
#include <vector>

namespace {

P100_Context g_ctx = {};
CRITICAL_SECTION g_lock;
bool g_lock_ready = false;
bool g_ready = false;
uint64_t g_next_approval = 1;
std::vector<P100_ApprovalV1> g_approvals;

void CopyWide(wchar_t* dst, uint32_t cch, const wchar_t* src) {
    if (!dst || cch == 0) return;
    dst[0] = 0;
    if (!src) return;
    wcsncpy_s(dst, cch, src, _TRUNCATE);
}

std::wstring W(const wchar_t* s) {
    return s ? std::wstring(s) : std::wstring();
}

std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    wchar_t last = a[a.size() - 1];
    if (last == L'\\' || last == L'/') return a + b;
    return a + L"\\" + b;
}

bool ExistsDir(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool IsAbsolutePath(const std::wstring& path) {
    if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) return true;
    if (path.size() >= 2 && ((path[0] == L'\\' && path[1] == L'\\') || (path[0] == L'/' && path[1] == L'/'))) return true;
    return false;
}

bool EnsureDir(const std::wstring& path) {
    if (path.empty()) return false;
    if (ExistsDir(path)) return true;

    std::wstring cur;
    for (size_t i = 0; i < path.size(); ++i) {
        wchar_t ch = path[i];
        cur.push_back(ch);
        if (ch != L'\\' && ch != L'/') continue;
        if (cur.size() <= 3) continue;
        if (!ExistsDir(cur)) {
            CreateDirectoryW(cur.c_str(), nullptr);
        }
    }

    if (!CreateDirectoryW(path.c_str(), nullptr)) {
        return GetLastError() == ERROR_ALREADY_EXISTS && ExistsDir(path);
    }
    return true;
}

std::wstring StateDir() {
    std::wstring base = g_ctx.evidence_dir[0] ? W(g_ctx.evidence_dir) : JoinPath(W(g_ctx.workspace), L"evidence\\IDE_PRODUCT_FINISH_BATCH_085");
    if (!base.empty() && !IsAbsolutePath(base) && g_ctx.workspace[0]) {
        base = JoinPath(W(g_ctx.workspace), base);
    }
    EnsureDir(base);
    return base;
}

std::wstring StateFile(const wchar_t* leaf) {
    return JoinPath(StateDir(), leaf);
}

std::wstring ResolveRepoPath(const wchar_t* path) {
    std::wstring p = W(path);
    if (p.empty() || IsAbsolutePath(p) || !g_ctx.workspace[0]) return p;
    return JoinPath(W(g_ctx.workspace), p);
}

void Sink(const wchar_t* channel, const std::wstring& text) {
    if (g_ctx.sink) {
        g_ctx.sink(channel ? channel : L"product100", text.c_str(), g_ctx.sink_user);
    }
}

bool HasCap(uint64_t required) {
    return P100_CapAllows(g_ctx.capabilities, required) != 0;
}

std::string Utf8FromWide(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int bytes = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return std::string();
    std::string out((size_t)bytes, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &out[0], bytes, nullptr, nullptr);
    return out;
}

std::wstring WideFromBytes(const char* p, size_t n) {
    if (!p || n == 0) return std::wstring();
    int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, (int)n, nullptr, 0);
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (chars <= 0) {
        cp = CP_ACP;
        flags = 0;
        chars = MultiByteToWideChar(cp, flags, p, (int)n, nullptr, 0);
    }
    if (chars <= 0) return std::wstring();
    std::wstring out((size_t)chars, L'\0');
    MultiByteToWideChar(cp, flags, p, (int)n, &out[0], chars);
    return out;
}

std::wstring WideFromUtf8(const std::string& s) {
    return WideFromBytes(s.data(), s.size());
}

std::string LowerAscii(std::string s) {
    for (char& ch : s) {
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
    }
    return s;
}

std::wstring QuoteArg(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";
    bool needs_quotes = false;
    for (wchar_t ch : arg) {
        if (ch == L' ' || ch == L'\t' || ch == L'"') {
            needs_quotes = true;
            break;
        }
    }
    if (!needs_quotes) return arg;

    std::wstring out = L"\"";
    size_t slash_count = 0;
    for (wchar_t ch : arg) {
        if (ch == L'\\') {
            ++slash_count;
        } else if (ch == L'"') {
            out.append(slash_count * 2 + 1, L'\\');
            out.push_back(ch);
            slash_count = 0;
        } else {
            out.append(slash_count, L'\\');
            slash_count = 0;
            out.push_back(ch);
        }
    }
    out.append(slash_count * 2, L'\\');
    out.push_back(L'"');
    return out;
}

std::wstring BuildCommandLine(const wchar_t* exe, const std::vector<std::wstring>& args) {
    std::wstring cmd = QuoteArg(exe ? exe : L"");
    for (const auto& arg : args) {
        cmd.push_back(L' ');
        cmd += QuoteArg(arg);
    }
    return cmd;
}

int32_t CopyResultText(const std::wstring& src, wchar_t* out_text, uint32_t out_cch) {
    if (out_text && out_cch) CopyWide(out_text, out_cch, src.c_str());
    if (out_text && out_cch && src.size() >= out_cch) return P100_E_BUFFER_TOO_SMALL;
    return P100_OK;
}

bool WriteUtf8File(const std::wstring& path, const std::wstring& text) {
    std::string bytes = Utf8FromWide(text);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = TRUE;
    if (!bytes.empty()) ok = WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
    CloseHandle(h);
    return ok && written == bytes.size();
}

bool AppendUtf8File(const std::wstring& path, const std::wstring& text) {
    std::string bytes = Utf8FromWide(text);
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = TRUE;
    if (!bytes.empty()) ok = WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
    CloseHandle(h);
    return ok && written == bytes.size();
}

std::wstring NowStamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    wchar_t buf[64] = {};
    swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

int32_t RunProcessCapture(
    const wchar_t* exe,
    const std::vector<std::wstring>& args,
    const std::wstring& cwd,
    DWORD timeout_ms,
    std::wstring* out_text,
    P100_RunResult* result) {

    if (result) *result = {};
    if (!exe || !exe[0]) return P100_E_INVALID_ARG;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) return P100_E_IO;
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    std::wstring cmd = BuildCommandLine(exe, args);
    std::vector<wchar_t> mutable_cmd(cmd.begin(), cmd.end());
    mutable_cmd.push_back(0);

    BOOL ok = CreateProcessW(
        nullptr,
        mutable_cmd.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        cwd.empty() ? nullptr : cwd.c_str(),
        &si,
        &pi);

    CloseHandle(write_pipe);
    if (!ok) {
        CloseHandle(read_pipe);
        return P100_E_PROCESS_FAILED;
    }

    std::string captured;
    char buffer[4096];
    DWORD start = GetTickCount();
    bool timed_out = false;

    for (;;) {
        DWORD available = 0;
        while (PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr) && available > 0) {
            DWORD to_read = available > sizeof(buffer) ? sizeof(buffer) : available;
            DWORD got = 0;
            if (!ReadFile(read_pipe, buffer, to_read, &got, nullptr) || got == 0) break;
            captured.append(buffer, buffer + got);
            Sink(L"process", WideFromBytes(buffer, got));
        }

        DWORD wait = WaitForSingleObject(pi.hProcess, 25);
        if (wait == WAIT_OBJECT_0) break;
        if (timeout_ms && (GetTickCount() - start) > timeout_ms) {
            timed_out = true;
            TerminateProcess(pi.hProcess, 124);
            WaitForSingleObject(pi.hProcess, 5000);
            break;
        }
    }

    for (;;) {
        DWORD got = 0;
        if (!ReadFile(read_pipe, buffer, sizeof(buffer), &got, nullptr) || got == 0) break;
        captured.append(buffer, buffer + got);
    }

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(read_pipe);

    if (out_text) *out_text = WideFromUtf8(captured);
    if (result) {
        result->exit_code = (int32_t)exit_code;
        result->timed_out = timed_out ? 1u : 0u;
        result->stdout_bytes = (uint64_t)captured.size();
        result->stderr_bytes = 0;
        result->seal64 = P100_Fnv1a64(captured.data(), (uint64_t)captured.size());
    }

    return timed_out ? P100_E_PROCESS_FAILED : (exit_code == 0 ? P100_OK : P100_E_PROCESS_FAILED);
}

int32_t GitCapture(const std::vector<std::wstring>& args, uint64_t required_cap, wchar_t* out_text, uint32_t out_cch, P100_RunResult* result) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!HasCap(required_cap)) return P100_E_ACCESS_DENIED;

    std::wstring output;
    int32_t rc = RunProcessCapture(L"git.exe", args, W(g_ctx.workspace), 60000, &output, result);
    if (out_text && out_cch) CopyWide(out_text, out_cch, output.c_str());
    if (rc != P100_OK) {
        AppendUtf8File(StateFile(L"GIT_LANE.log"), NowStamp() + L" FAIL " + output + L"\n");
    }
    return rc;
}

bool ReadSmallFile(const std::wstring& path, std::vector<char>& bytes) {
    bytes.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 || size.QuadPart > 2 * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }
    bytes.resize((size_t)size.QuadPart);
    DWORD got = 0;
    BOOL ok = TRUE;
    if (!bytes.empty()) ok = ReadFile(h, bytes.data(), (DWORD)bytes.size(), &got, nullptr);
    CloseHandle(h);
    if (!ok || got != bytes.size()) {
        bytes.clear();
        return false;
    }
    if (std::find(bytes.begin(), bytes.end(), '\0') != bytes.end()) {
        bytes.clear();
        return false;
    }
    return true;
}

bool ShouldSkipDir(const std::wstring& name) {
    std::wstring n = name;
    std::transform(n.begin(), n.end(), n.begin(), [](wchar_t ch) { return (wchar_t)towlower(ch); });
    return n == L"." || n == L".." || n == L".git" || n == L".vs" || n == L"build" ||
           n == L"build_p1pra_win32ide" || n == L"x64" || n == L"debug" || n == L"release";
}

bool ShouldSearchFile(const std::wstring& name) {
    std::wstring n = name;
    std::transform(n.begin(), n.end(), n.begin(), [](wchar_t ch) { return (wchar_t)towlower(ch); });
    const wchar_t* blocked[] = {
        L".exe", L".dll", L".lib", L".obj", L".pdb", L".ilk", L".png", L".jpg",
        L".jpeg", L".gif", L".zip", L".7z", L".gguf", L".bin", L".onnx"
    };
    for (auto ext : blocked) {
        size_t elen = wcslen(ext);
        if (n.size() >= elen && n.compare(n.size() - elen, elen, ext) == 0) return false;
    }
    return true;
}

void FillHitPreview(const std::wstring& rel, const std::string& bytes, size_t index, P100_SearchHit* hit) {
    CopyWide(hit->path, P100_PATH_CCH, rel.c_str());
    uint32_t line = 1;
    uint32_t col = 1;
    size_t line_start = 0;
    for (size_t i = 0; i < index && i < bytes.size(); ++i) {
        if (bytes[i] == '\n') {
            ++line;
            col = 1;
            line_start = i + 1;
        } else {
            ++col;
        }
    }
    size_t line_end = bytes.find('\n', index);
    if (line_end == std::string::npos) line_end = bytes.size();
    size_t take_start = line_start;
    if (line_end > take_start && line_end - take_start > 700) {
        take_start = index > 120 ? index - 120 : line_start;
    }
    size_t take = std::min<size_t>(line_end - take_start, 700);
    std::wstring preview = WideFromBytes(bytes.data() + take_start, take);
    hit->line = line;
    hit->column = col;
    CopyWide(hit->preview, P100_PREVIEW_CCH, preview.c_str());
    hit->seal64 = P100_Fnv1a64(bytes.data() + index, (uint64_t)std::min<size_t>(64, bytes.size() - index));
}

bool LooksLikeSymbolLine(const std::string& line, const std::string& sym) {
    if (line.find(sym) == std::string::npos) return false;
    static const char* hints[] = {
        "class ", "struct ", "enum ", "namespace ", "void ", "int ", "bool ",
        "uint32_t ", "uint64_t ", "HRESULT ", "LRESULT ", "auto ", "::"
    };
    for (auto h : hints) {
        if (line.find(h) != std::string::npos) return true;
    }
    std::string call = sym + "(";
    return line.find(call) != std::string::npos;
}

void SearchFileLiteral(
    const std::wstring& full,
    const std::wstring& rel,
    const std::string& needle,
    bool case_insensitive,
    bool symbol_mode,
    uint32_t max_hits,
    uint32_t* hit_count,
    P100_SearchHitSink sink,
    void* user) {

    if (*hit_count >= max_hits) return;
    std::vector<char> raw;
    if (!ReadSmallFile(full, raw)) return;
    std::string hay(raw.begin(), raw.end());
    std::string hay_find = case_insensitive ? LowerAscii(hay) : hay;
    std::string needle_find = case_insensitive ? LowerAscii(needle) : needle;
    if (needle_find.empty()) return;

    size_t pos = 0;
    while (*hit_count < max_hits && pos <= hay_find.size()) {
        int64_t found = -1;
        if (!case_insensitive) {
            found = P100_FindByteSpan(hay_find.data() + pos, (uint64_t)(hay_find.size() - pos), needle_find.data(), (uint64_t)needle_find.size());
            if (found >= 0) found += (int64_t)pos;
        } else {
            size_t p = hay_find.find(needle_find, pos);
            if (p != std::string::npos) found = (int64_t)p;
        }
        if (found < 0) break;

        size_t f = (size_t)found;
        if (symbol_mode) {
            size_t ls = hay.rfind('\n', f);
            ls = (ls == std::string::npos) ? 0 : ls + 1;
            size_t le = hay.find('\n', f);
            if (le == std::string::npos) le = hay.size();
            if (!LooksLikeSymbolLine(hay.substr(ls, le - ls), needle)) {
                pos = f + needle_find.size();
                continue;
            }
        }

        P100_SearchHit hit = {};
        FillHitPreview(rel, hay, f, &hit);
        ++(*hit_count);
        if (sink && sink(&hit, user) == 0) return;
        pos = f + std::max<size_t>(needle_find.size(), 1);
    }
}

void WalkSearch(
    const std::wstring& root,
    const std::wstring& rel,
    const std::string& needle,
    bool case_insensitive,
    bool symbol_mode,
    uint32_t max_hits,
    uint32_t* hit_count,
    P100_SearchHitSink sink,
    void* user) {

    if (*hit_count >= max_hits) return;
    std::wstring dir = rel.empty() ? root : JoinPath(root, rel);
    std::wstring pattern = JoinPath(dir, L"*");
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring name = fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!ShouldSkipDir(name)) {
                WalkSearch(root, rel.empty() ? name : JoinPath(rel, name), needle, case_insensitive, symbol_mode, max_hits, hit_count, sink, user);
            }
        } else if (ShouldSearchFile(name)) {
            std::wstring child_rel = rel.empty() ? name : JoinPath(rel, name);
            SearchFileLiteral(JoinPath(root, child_rel), child_rel, needle, case_insensitive, symbol_mode, max_hits, hit_count, sink, user);
        }
    } while (*hit_count < max_hits && FindNextFileW(h, &fd));
    FindClose(h);
}

std::wstring PlanStatesToString(const P100_SessionV1* s) {
    std::wstringstream ss;
    uint32_t count = std::min<uint32_t>(s->plan_step_count, P100_PLAN_MAX);
    for (uint32_t i = 0; i < count; ++i) {
        if (i) ss << L",";
        ss << s->plan_states[i];
    }
    return ss.str();
}

void ParsePlanStates(const wchar_t* text, P100_SessionV1* s) {
    if (!text || !s) return;
    std::wstring t = text;
    uint32_t idx = 0;
    size_t start = 0;
    while (idx < P100_PLAN_MAX && start <= t.size()) {
        size_t comma = t.find(L',', start);
        std::wstring part = t.substr(start, comma == std::wstring::npos ? std::wstring::npos : comma - start);
        s->plan_states[idx++] = (uint32_t)_wtoi(part.c_str());
        if (comma == std::wstring::npos) break;
        start = comma + 1;
    }
    s->plan_step_count = idx;
}

void IniWrite(const std::wstring& file, const wchar_t* sec, const wchar_t* key, const std::wstring& val) {
    WritePrivateProfileStringW(sec, key, val.c_str(), file.c_str());
}

void IniRead(const std::wstring& file, const wchar_t* sec, const wchar_t* key, wchar_t* out, uint32_t cch, const wchar_t* def = L"") {
    if (!out || cch == 0) return;
    GetPrivateProfileStringW(sec, key, def, out, cch, file.c_str());
}

std::wstring SmokeLine(const wchar_t* name, const wchar_t* state, int32_t rc) {
    std::wstringstream ss;
    ss << NowStamp() << L" " << name << L" " << state << L" rc=" << rc << L"\n";
    return ss.str();
}

bool FileContains(const std::wstring& path, const std::string& needle) {
    std::vector<char> bytes;
    if (!ReadSmallFile(path, bytes)) return false;
    std::string s(bytes.begin(), bytes.end());
    return s.find(needle) != std::string::npos;
}

} // namespace

P100_API int32_t P100_CALL P100_Init(const P100_Context* ctx) {
    if (!ctx || ctx->size < sizeof(P100_Context)) return P100_E_INVALID_ARG;
    if (!g_lock_ready) {
        InitializeCriticalSection(&g_lock);
        g_lock_ready = true;
    }
    EnterCriticalSection(&g_lock);
    g_ctx = *ctx;
    g_ready = true;
    EnsureDir(StateDir());
    uint64_t seal = P100_Fnv1a64("P100", 4);
    LeaveCriticalSection(&g_lock);
    if (seal == 0) return P100_E_MASM_NOT_LINKED;
    AppendUtf8File(StateFile(L"PRODUCT100.log"), NowStamp() + L" INIT seal64=" + std::to_wstring(seal) + L"\n");
    return P100_OK;
}

P100_API int32_t P100_CALL P100_Shutdown(void) {
    if (!g_ready) return P100_OK;
    AppendUtf8File(StateFile(L"PRODUCT100.log"), NowStamp() + L" SHUTDOWN\n");
    if (g_lock_ready) {
        EnterCriticalSection(&g_lock);
        g_approvals.clear();
        g_ready = false;
        LeaveCriticalSection(&g_lock);
    }
    return P100_OK;
}

P100_API uint64_t P100_CALL P100_SourceSeal64(const void* data, uint64_t bytes) {
    return P100_Fnv1a64(data, bytes);
}

P100_API int32_t P100_CALL P100_DescribeError(int32_t status, const wchar_t* detail, wchar_t* out_text, uint32_t out_cch) {
    if (!out_text || out_cch == 0) return P100_E_INVALID_ARG;
    const wchar_t* action = L"Inspect the failing subsystem evidence and retry from the last safe checkpoint.";
    switch (status) {
    case P100_OK: action = L"No failure."; break;
    case P100_E_ACCESS_DENIED: action = L"Capability gate blocked the action. Open Agent Approval Center and approve only the exact pending action."; break;
    case P100_E_PROCESS_FAILED: action = L"Process failed. Review streamed stdout/stderr and exit code, then rerun after repair."; break;
    case P100_E_NOT_FOUND: action = L"Required file or executable was not found. Confirm workspace/model path and retry."; break;
    case P100_E_MISSING_CALLBACK: action = L"Smoke host callback is missing. Wire the existing IDE action; do not mark this as pass."; break;
    case P100_E_MASM_NOT_LINKED: action = L"x64 MASM Product100 object is not linked. Add RawrXD_Product100_x64.asm to the Win32IDE MASM sources."; break;
    case P100_E_SMOKE_FAILED: action = L"Product smoke matrix failed. Keep PRODUCT_100 on HOLD and inspect PRODUCT_100_SMOKE_MATRIX.txt."; break;
    default: break;
    }
    std::wstring msg = action;
    if (detail && detail[0]) {
        msg += L" Detail: ";
        msg += detail;
    }
    CopyWide(out_text, out_cch, msg.c_str());
    return P100_OK;
}

P100_API int32_t P100_CALL P100_GitStatus(wchar_t* out_text, uint32_t out_cch, P100_RunResult* result) {
    return GitCapture({ L"status", L"--short", L"--branch" }, P100_CAP_GIT_READ, out_text, out_cch, result);
}

P100_API int32_t P100_CALL P100_GitDiff(wchar_t* out_text, uint32_t out_cch, P100_RunResult* result) {
    return GitCapture({ L"diff", L"--", L"." }, P100_CAP_GIT_READ, out_text, out_cch, result);
}

P100_API int32_t P100_CALL P100_GitStage(const wchar_t* repo_relative_path, P100_RunResult* result) {
    if (!repo_relative_path || !repo_relative_path[0]) return P100_E_INVALID_ARG;
    return GitCapture({ L"add", L"--", repo_relative_path }, P100_CAP_GIT_WRITE, nullptr, 0, result);
}

P100_API int32_t P100_CALL P100_GitUnstage(const wchar_t* repo_relative_path, P100_RunResult* result) {
    if (!repo_relative_path || !repo_relative_path[0]) return P100_E_INVALID_ARG;
    return GitCapture({ L"restore", L"--staged", L"--", repo_relative_path }, P100_CAP_GIT_WRITE, nullptr, 0, result);
}

P100_API int32_t P100_CALL P100_GitCommit(const wchar_t* message, wchar_t* out_text, uint32_t out_cch, P100_RunResult* result) {
    if (!message || !message[0]) return P100_E_INVALID_ARG;
    return GitCapture({ L"commit", L"-m", message }, P100_CAP_GIT_WRITE, out_text, out_cch, result);
}

P100_API int32_t P100_CALL P100_SearchWorkspaceLiteral(const wchar_t* literal, uint32_t case_insensitive, uint32_t max_hits, P100_SearchHitSink sink, void* user) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!HasCap(P100_CAP_READ | P100_CAP_SEARCH)) return P100_E_ACCESS_DENIED;
    if (!literal || !literal[0] || !sink) return P100_E_INVALID_ARG;
    uint32_t hits = 0;
    WalkSearch(W(g_ctx.workspace), L"", Utf8FromWide(literal), case_insensitive != 0, false, max_hits ? max_hits : 128, &hits, sink, user);
    return hits ? P100_OK : P100_E_NOT_FOUND;
}

P100_API int32_t P100_CALL P100_SearchWorkspaceSymbol(const wchar_t* symbol, uint32_t max_hits, P100_SearchHitSink sink, void* user) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!HasCap(P100_CAP_READ | P100_CAP_SEARCH)) return P100_E_ACCESS_DENIED;
    if (!symbol || !symbol[0] || !sink) return P100_E_INVALID_ARG;
    uint32_t hits = 0;
    WalkSearch(W(g_ctx.workspace), L"", Utf8FromWide(symbol), false, true, max_hits ? max_hits : 128, &hits, sink, user);
    return hits ? P100_OK : P100_E_NOT_FOUND;
}

P100_API int32_t P100_CALL P100_SaveSettings(const P100_SettingsV1* settings) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!HasCap(P100_CAP_SETTINGS)) return P100_E_ACCESS_DENIED;
    if (!settings || settings->size < sizeof(P100_SettingsV1)) return P100_E_INVALID_ARG;
    std::wstring file = StateFile(L"settings.ini");
    IniWrite(file, L"engine", L"model_path", settings->model_path);
    IniWrite(file, L"engine", L"context_tokens", std::to_wstring(settings->context_tokens));
    IniWrite(file, L"engine", L"temperature", std::to_wstring(settings->temperature));
    IniWrite(file, L"engine", L"gpu_split", settings->gpu_split);
    IniWrite(file, L"engine", L"reasoning_control", std::to_wstring(settings->reasoning_control));
    IniWrite(file, L"engine", L"output_control", std::to_wstring(settings->output_control));
    return P100_OK;
}

P100_API int32_t P100_CALL P100_LoadSettings(P100_SettingsV1* settings) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!HasCap(P100_CAP_SETTINGS)) return P100_E_ACCESS_DENIED;
    if (!settings || settings->size < sizeof(P100_SettingsV1)) return P100_E_INVALID_ARG;
    std::wstring file = StateFile(L"settings.ini");
    wchar_t temp[128] = {};
    IniRead(file, L"engine", L"model_path", settings->model_path, P100_PATH_CCH);
    IniRead(file, L"engine", L"context_tokens", temp, 128, L"4096");
    settings->context_tokens = (uint32_t)_wtoi(temp);
    IniRead(file, L"engine", L"temperature", temp, 128, L"0.7");
    settings->temperature = (float)_wtof(temp);
    IniRead(file, L"engine", L"gpu_split", settings->gpu_split, P100_NAME_CCH);
    IniRead(file, L"engine", L"reasoning_control", temp, 128, L"0");
    settings->reasoning_control = (uint32_t)_wtoi(temp);
    IniRead(file, L"engine", L"output_control", temp, 128, L"0");
    settings->output_control = (uint32_t)_wtoi(temp);
    return P100_OK;
}

P100_API int32_t P100_CALL P100_SaveSession(const P100_SessionV1* session) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!HasCap(P100_CAP_PERSISTENCE)) return P100_E_ACCESS_DENIED;
    if (!session || session->size < sizeof(P100_SessionV1)) return P100_E_INVALID_ARG;
    std::wstring file = StateFile(L"session.ini");
    IniWrite(file, L"session", L"workspace", session->workspace);
    IniWrite(file, L"session", L"model_path", session->model_path);
    IniWrite(file, L"session", L"mode", session->mode);
    IniWrite(file, L"session", L"history_path", session->history_path);
    IniWrite(file, L"session", L"plan_path", session->plan_path);
    IniWrite(file, L"session", L"plan_step_count", std::to_wstring(session->plan_step_count));
    IniWrite(file, L"session", L"active_plan_step", std::to_wstring(session->active_plan_step));
    IniWrite(file, L"session", L"plan_states", PlanStatesToString(session));
    return P100_OK;
}

P100_API int32_t P100_CALL P100_LoadSession(P100_SessionV1* session) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!HasCap(P100_CAP_PERSISTENCE)) return P100_E_ACCESS_DENIED;
    if (!session || session->size < sizeof(P100_SessionV1)) return P100_E_INVALID_ARG;
    std::wstring file = StateFile(L"session.ini");
    wchar_t temp[1024] = {};
    IniRead(file, L"session", L"workspace", session->workspace, P100_PATH_CCH);
    IniRead(file, L"session", L"model_path", session->model_path, P100_PATH_CCH);
    IniRead(file, L"session", L"mode", session->mode, P100_NAME_CCH);
    IniRead(file, L"session", L"history_path", session->history_path, P100_PATH_CCH);
    IniRead(file, L"session", L"plan_path", session->plan_path, P100_PATH_CCH);
    IniRead(file, L"session", L"plan_step_count", temp, 1024, L"0");
    session->plan_step_count = (uint32_t)_wtoi(temp);
    IniRead(file, L"session", L"active_plan_step", temp, 1024, L"0");
    session->active_plan_step = (uint32_t)_wtoi(temp);
    IniRead(file, L"session", L"plan_states", temp, 1024, L"");
    ParsePlanStates(temp, session);
    return P100_OK;
}

P100_API int32_t P100_CALL P100_AddApproval(const P100_ApprovalV1* request, uint64_t* out_id) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!request || request->size < sizeof(P100_ApprovalV1)) return P100_E_INVALID_ARG;
    EnterCriticalSection(&g_lock);
    P100_ApprovalV1 item = *request;
    item.id = g_next_approval++;
    item.state = P100_APPROVAL_PENDING;
    item.seal64 = P100_Fnv1a64(&item, offsetof(P100_ApprovalV1, seal64));
    g_approvals.push_back(item);
    if (out_id) *out_id = item.id;
    LeaveCriticalSection(&g_lock);
    AppendUtf8File(StateFile(L"APPROVAL_CENTER.log"), NowStamp() + L" PENDING id=" + std::to_wstring(item.id) + L" verb=" + item.verb + L"\n");
    return P100_OK;
}

P100_API int32_t P100_CALL P100_ListApprovals(P100_ApprovalV1* out_items, uint32_t capacity, uint32_t* out_count) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    if (!out_count) return P100_E_INVALID_ARG;
    EnterCriticalSection(&g_lock);
    *out_count = (uint32_t)g_approvals.size();
    if (out_items && capacity) {
        uint32_t n = std::min<uint32_t>(capacity, (uint32_t)g_approvals.size());
        for (uint32_t i = 0; i < n; ++i) out_items[i] = g_approvals[i];
    }
    LeaveCriticalSection(&g_lock);
    return P100_OK;
}

P100_API int32_t P100_CALL P100_DecideApproval(uint64_t id, uint32_t approved) {
    if (!g_ready) return P100_E_NOT_INITIALIZED;
    EnterCriticalSection(&g_lock);
    for (auto& item : g_approvals) {
        if (item.id == id) {
            if (approved && !HasCap(item.required_capabilities)) {
                LeaveCriticalSection(&g_lock);
                return P100_E_ACCESS_DENIED;
            }
            item.state = approved ? P100_APPROVAL_APPROVED : P100_APPROVAL_DENIED;
            AppendUtf8File(StateFile(L"APPROVAL_CENTER.log"), NowStamp() + L" DECIDE id=" + std::to_wstring(id) + L" state=" + std::to_wstring(item.state) + L"\n");
            LeaveCriticalSection(&g_lock);
            return P100_OK;
        }
    }
    LeaveCriticalSection(&g_lock);
    return P100_E_NOT_FOUND;
}

P100_API int32_t P100_CALL P100_RunSmokeMatrix(const P100_SmokeHostV1* host, const wchar_t* evidence_dir) {
    if (!host || host->size < sizeof(P100_SmokeHostV1)) return P100_E_INVALID_ARG;
    std::wstring dir = evidence_dir && evidence_dir[0] ? evidence_dir : StateDir();
    EnsureDir(dir);
    std::wstring smoke = JoinPath(dir, L"PRODUCT_100_SMOKE_MATRIX.txt");
    WriteUtf8File(smoke, std::wstring(L"PRODUCT_100_SMOKE_MATRIX\nSTART=") + NowStamp() + L"\nSYNTHETIC_PASS=0\n");

    struct Step { const wchar_t* name; P100_SmokeStepFn fn; bool wave3; };
    Step steps[] = {
        { L"LOAD_GGUF", host->load_gguf, false },
        { L"ASK_SEND", host->ask_send, false },
        { L"PLAN_CHECKLIST", host->plan_checklist, false },
        { L"APPROVE_PLAN", host->approve_plan, false },
        { L"AGENT_READ_SEARCH", host->agent_read_search, true },
        { L"BUILD_EDIT_DIFF", host->build_edit_diff, false },
        { L"APPLY_EDIT", host->apply_edit, false },
        { L"TERMINAL_RUN", host->terminal_run, false },
        { L"AGENT_OBSERVE_REPAIR", host->agent_observe_repair, false },
        { L"GIT_DIFF_COMMIT", host->git_diff_commit, true },
        { L"STOP_CANCEL", host->stop_cancel, false },
        { L"RESTART_RESTORE", host->restart_restore, true }
    };

    bool all_pass = true;
    bool wave3_pass = true;
    for (const auto& step : steps) {
        if (!step.fn) {
            all_pass = false;
            if (step.wave3) wave3_pass = false;
            AppendUtf8File(smoke, SmokeLine(step.name, L"MISSING_CALLBACK", P100_E_MISSING_CALLBACK));
            continue;
        }
        int32_t rc = step.fn(step.name, host->user);
        bool pass = rc == 0;
        all_pass = all_pass && pass;
        if (step.wave3) wave3_pass = wave3_pass && pass;
        AppendUtf8File(smoke, SmokeLine(step.name, pass ? L"PASS" : L"FAIL", rc));
    }

    std::wstring wave3 = JoinPath(dir, L"WAVE_3_VERDICT.txt");
    std::wstring wave4 = JoinPath(dir, L"WAVE_4_VERDICT.txt");
    WriteUtf8File(wave3, std::wstring(L"WAVE=3\nVERDICT=") + (wave3_pass ? L"PASS" : L"HOLD") + L"\nSOURCE=PRODUCT_100_SMOKE_MATRIX.txt\n");
    WriteUtf8File(wave4, std::wstring(L"WAVE=4\nVERDICT=") + (all_pass ? L"PASS" : L"HOLD") + L"\nSOURCE=PRODUCT_100_SMOKE_MATRIX.txt\n");
    AppendUtf8File(smoke, std::wstring(L"FINAL=") + (all_pass ? L"PASS" : L"HOLD") + L"\nEND=" + NowStamp() + L"\n");
    return all_pass ? P100_OK : P100_E_SMOKE_FAILED;
}

P100_API int32_t P100_CALL P100_WriteFreezeManifest(const P100_FreezeInputV1* input, const wchar_t* evidence_dir) {
    if (!input || input->size < sizeof(P100_FreezeInputV1)) return P100_E_INVALID_ARG;
    std::wstring dir = evidence_dir && evidence_dir[0] ? evidence_dir : StateDir();
    EnsureDir(dir);
    bool final_ok = wcscmp(input->e2e_finalize, L"0") == 0;
    if (!final_ok && input->e2e_log_path[0]) {
        final_ok = FileContains(ResolveRepoPath(input->e2e_log_path), "FINALIZE=0");
    }
    bool wave1_ok = input->wave1_verdict[0] && FileContains(ResolveRepoPath(input->wave1_verdict), "PASS");
    bool wave2_ok = input->wave2_verdict[0] && FileContains(ResolveRepoPath(input->wave2_verdict), "PASS");
    bool wave3_ok = input->wave3_verdict[0] && FileContains(ResolveRepoPath(input->wave3_verdict), "PASS");
    bool wave4_ok = input->wave4_verdict[0] && FileContains(ResolveRepoPath(input->wave4_verdict), "PASS");
    bool product_ok = final_ok && wave1_ok && wave2_ok && wave3_ok && wave4_ok;

    std::wstring manifest = JoinPath(dir, L"PRODUCT_100_FREEZE_MANIFEST.txt");
    std::wstringstream ss;
    ss << L"PRODUCT=RawrXD-Win32IDE\n";
    ss << L"CLAIM=PRODUCT_100\n";
    ss << L"CREATED_UTC=" << NowStamp() << L"\n";
    ss << L"SYNTHETIC_FALLBACK=0\n";
    ss << L"NO_THIRD_PARTY_DEPS=1\n";
    ss << L"X64_MASM_LINK_REQUIRED=1\n";
    ss << L"EXE_SHA256=" << input->exe_sha256 << L"\n";
    ss << L"MODEL_PATH=" << input->model_path << L"\n";
    ss << L"E2E_LOG=" << input->e2e_log_path << L"\n";
    ss << L"E2E_FINALIZE=" << (final_ok ? L"0" : input->e2e_finalize) << L"\n";
    ss << L"WAVE_1_VERDICT=" << input->wave1_verdict << L"\n";
    ss << L"WAVE_2_VERDICT=" << input->wave2_verdict << L"\n";
    ss << L"WAVE_3_VERDICT=" << input->wave3_verdict << L"\n";
    ss << L"WAVE_4_VERDICT=" << input->wave4_verdict << L"\n";
    ss << L"WAVE_1_PASS=" << (wave1_ok ? L"1" : L"0") << L"\n";
    ss << L"WAVE_2_PASS=" << (wave2_ok ? L"1" : L"0") << L"\n";
    ss << L"WAVE_3_PASS=" << (wave3_ok ? L"1" : L"0") << L"\n";
    ss << L"WAVE_4_PASS=" << (wave4_ok ? L"1" : L"0") << L"\n";
    ss << L"KNOWN_GAPS=" << input->known_gaps << L"\n";
    ss << L"FINAL_VERDICT=" << (product_ok ? L"PASS" : L"HOLD") << L"\n";
    WriteUtf8File(manifest, ss.str());
    WriteUtf8File(JoinPath(dir, L"PRODUCT_100_VERDICT.txt"), std::wstring(L"VERDICT=") + (product_ok ? L"PASS" : L"HOLD") + L"\nSOURCE=PRODUCT_100_FREEZE_MANIFEST.txt\n");
    return product_ok ? P100_OK : P100_E_SMOKE_FAILED;
}
