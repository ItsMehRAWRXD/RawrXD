/*==========================================================================
 * Phase 5a: Entry Point Stub - Fully Reverse Engineered
 *
 * Provides the default CRT entry point machine code that the linker
 * injects when no explicit entry point is found in the object files.
 *
 * The stub follows the Microsoft x64 CRT initialization pattern:
 *   1. Align stack to 16-byte boundary (sub rsp, 0x28)
 *   2. Call __security_init_cookie (if available)
 *   3. Call mainCRTStartup -> main()
 *   4. Call ExitProcess with return value
 *
 * For a minimal executable (no CRT), the stub simplifies to:
 *   sub rsp, 0x28          ; shadow space + alignment (kept through ExitProcess)
 *   call <main>            ; E8 rel32
 *   mov ecx, eax           ; exit code = return value
 *   call [rip+disp32]      ; FF 15 — ExitProcess via IAT (needs shadow space)
 *   int 3
 *
 * Machine code for x64:
 *   48 83 EC 28             sub rsp, 0x28
 *   E8 xx xx xx xx          call main            (disp @ +5; next @ +9)
 *   89 C1                   mov ecx, eax
 *   FF 15 xx xx xx xx       call [rip+disp]      (disp @ +0x0D; next @ +0x11)
 *   CC                      int 3
 *
 * Do NOT add rsp before ExitProcess: x64 ABI requires 32 bytes of caller
 * shadow space; ExitProcess writes into it and never returns.
 *=========================================================================*/
#include <stdint.h>
#include <stddef.h>

/*---- Primary entry stub: calls main then ExitProcess via IAT ----*/
uint8_t entry_stub_code[] = {
  /* 0x00 */ 0x48, 0x83, 0xEC, 0x28,             /* sub rsp, 0x28 */
  /* 0x04 */ 0xE8, 0x00, 0x00, 0x00, 0x00,       /* call main (rel32 @ 5) */
  /* 0x09 */ 0x89, 0xC1,                          /* mov ecx, eax */
  /* 0x0B */ 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, /* call [rip+disp] IAT (@ 0x0D) */
  /* 0x11 */ 0xCC,                                /* int 3 */
};

const size_t entry_stub_size = sizeof(entry_stub_code);

/* Patch sites: E8 disp @ 5; FF15 disp @ 0x0D */
const uint32_t entry_stub_main_reloc_offset = 0x05;
const uint32_t entry_stub_exitproc_reloc_offset = 0x0D;

/*---- Alternative stub: WinMain entry for GUI applications ----
 * Calls GetModuleHandleA(NULL) for hInstance, then WinMain(hInst, 0, "", SW_SHOW)
 */
uint8_t entry_stub_winmain[] = {
  /* Sub rsp for shadow space + alignment */
  0x48, 0x83, 0xEC, 0x48,                       /* sub rsp, 0x48 */
  /* GetModuleHandleA(NULL) */
  0x48, 0x31, 0xC9,                             /* xor rcx, rcx */
  0xE8, 0x00, 0x00, 0x00, 0x00,                 /* call GetModuleHandleA (patch) */
  /* WinMain(hInst=rax, hPrevInst=0, lpCmdLine="", nShowCmd=SW_SHOWDEFAULT) */
  0x48, 0x89, 0xC1,                             /* mov rcx, rax (hInstance) */
  0x48, 0x31, 0xD2,                             /* xor rdx, rdx (hPrevInstance) */
  0x4D, 0x31, 0xC0,                             /* xor r8, r8  (lpCmdLine) */
  0x41, 0xB9, 0x0A, 0x00, 0x00, 0x00,           /* mov r9d, 10 (SW_SHOWDEFAULT) */
  0xE8, 0x00, 0x00, 0x00, 0x00,                 /* call WinMain (patch) */
  /* ExitProcess(eax) */
  0x89, 0xC1,                                   /* mov ecx, eax */
  0x48, 0x83, 0xC4, 0x48,                       /* add rsp, 0x48 */
  0xE8, 0x00, 0x00, 0x00, 0x00,                 /* call ExitProcess (patch) */
  0xCC,                                          /* int 3 */
};

const size_t entry_stub_winmain_size = sizeof(entry_stub_winmain);

/*---- Minimal stub: just ret (for DLLs or testing) ----*/
uint8_t entry_stub_minimal[] = {
  0x48, 0x83, 0xEC, 0x28,  /* sub rsp, 0x28 */
  0xB8, 0x01, 0x00, 0x00, 0x00,  /* mov eax, 1 (TRUE for DllMain) */
  0x48, 0x83, 0xC4, 0x28,  /* add rsp, 0x28 */
  0xC3,                     /* ret */
};

const size_t entry_stub_minimal_size = sizeof(entry_stub_minimal);
