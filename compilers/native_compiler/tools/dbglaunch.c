// Launch a program under the Windows debug API and report the first
// exception: the faulting address, the register state and the bytes at the
// instruction pointer.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static void dump_modules(DWORD pid, unsigned long long fault_addr) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            unsigned long long base = (unsigned long long)(ULONG_PTR)me.modBaseAddr;
            unsigned long long size = (unsigned long long)me.modBaseSize;
            if (fault_addr >= base && fault_addr < base + size) {
                wprintf(L"  FAULT MODULE: %ls  base=0x%llX  offset=0x%llX\n",
                        me.szExePath, base, fault_addr - base);
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { wprintf(L"usage: dbg <program> [args]\n"); return 2; }
    STARTUPINFOW si; ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof pi);
    wchar_t cmd[4096];
    swprintf(cmd, 4096, L"\"%ls\"", argv[1]);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS,
                        NULL, NULL, &si, &pi)) {
        wprintf(L"CreateProcess failed: %lu\n", GetLastError());
        return 3;
    }
    for (;;) {
        DEBUG_EVENT ev; DWORD pid, tid;
        if (!WaitForDebugEvent(&ev, 30000)) break;
        pid = ev.dwProcessId; tid = ev.dwThreadId;
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            wprintf(L"CREATE  base=0x%llX entry=0x%llX\n",
                    (unsigned long long)(ULONG_PTR)ev.u.CreateProcessInfo.lpBaseOfImage,
                    (unsigned long long)ev.u.CreateProcessInfo.lpStartAddress);
        } else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            EXCEPTION_RECORD* er = &ev.u.Exception.ExceptionRecord;
            CONTEXT ctx; ZeroMemory(&ctx, sizeof ctx);
            HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
            BOOL haveCtx = FALSE;
            if (th) {
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                haveCtx = GetThreadContext(th, &ctx);
                CloseHandle(th);
            }
            wprintf(L"EXCEPTION code=0x%08lX addr=0x%llX firstchance=%d\n",
                    er->ExceptionCode, (unsigned long long)er->ExceptionAddress,
                    ev.u.Exception.dwFirstChance);
            if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
                wprintf(L"  AV: operation=%llu address=0x%llX\n",
                        (unsigned long long)er->ExceptionInformation[0],
                        (unsigned long long)er->ExceptionInformation[1]);
            }
            if (haveCtx) {
                wprintf(L"  RIP=0x%llX RSP=0x%llX RBP=0x%llX\n",
                        (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rsp,
                        (unsigned long long)ctx.Rbp);
                wprintf(L"  RAX=0x%llX RCX=0x%llX RDX=0x%llX R8=0x%llX R9=0x%llX\n",
                        (unsigned long long)ctx.Rax, (unsigned long long)ctx.Rcx,
                        (unsigned long long)ctx.Rdx, (unsigned long long)ctx.R8,
                        (unsigned long long)ctx.R9);
                unsigned long long stack[12]; SIZE_T got = 0;
                if (ReadProcessMemory(pi.hProcess, (void*)ctx.Rsp, stack, sizeof stack, &got)) {
                    wprintf(L"  stack:");
                    for (SIZE_T i = 0; i < got / sizeof stack[0]; ++i)
                        wprintf(L" %llX", stack[i]);
                    wprintf(L"\n");
                }
                unsigned char code[16]; SIZE_T cg = 0;
                if (ReadProcessMemory(pi.hProcess, (void*)ctx.Rip, code, 16, &cg)) {
                    wprintf(L"  bytes@RIP:");
                    for (SIZE_T i = 0; i < cg; ++i) wprintf(L" %02X", code[i]);
                    wprintf(L"\n");
                }
                dump_modules(pid, (unsigned long long)ctx.Rip);
            }
            // A second-chance exception is the one that ends the process, so
            // it is reported to the operating system rather than swallowed.
            if (!ev.u.Exception.dwFirstChance) {
                ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
                continue;
            }
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            wprintf(L"EXIT   code=%lu\n", ev.u.ExitProcess.dwExitCode);
            break;
        }
        ContinueDebugEvent(pid, tid, DBG_CONTINUE);
    }
    return 0;
}