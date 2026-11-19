#include "../src/toolchain/linker/pe_writer.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static int write_case(const char *path, size_t text_size, int imports) {
  pe_builder_t *b = pe_builder_new(0x8664);
  if (!b) return 10;
  uint8_t *text = (uint8_t *)calloc(text_size, 1);
  if (!text) { pe_builder_free(b); return 11; }
  text[0] = 0xB8; text[1] = 42; text[2] = 0; text[3] = 0; text[4] = 0;
  text[5] = 0xC3;
  pe_builder_add_section(b, ".text", text, text_size, 0x60000020);
  free(text);
  if (imports) {
    pe_builder_add_import(b, "kernel32.dll", "ExitProcess");
    pe_builder_add_import(b, "kernel32.dll", "GetStdHandle");
    pe_builder_add_import(b, "user32.dll", "MessageBoxA");
    pe_builder_add_import(b, "kernel32.dll", "ExitProcess");
    if (pe_builder_add_base_relocation(b, 0x1008) != 0) { pe_builder_free(b); return 13; }
  }
  pe_builder_set_entry(b, 0x1000);
  int rc = pe_builder_write(b, path);
  pe_builder_free(b);
  return rc == 0 ? 0 : 12;
}

static int negative_cases(void) {
  pe_builder_t *b = pe_builder_new(0x8664);
  if (!b) return 20;
  static const uint8_t byte = 0xC3;
  pe_builder_add_section(b, ".text", &byte, 1, 0x60000020);
  if (pe_builder_write(b, "Z:\\path-that-does-not-exist\\out.exe") == 0) {
    pe_builder_free(b); return 21;
  }
  pe_builder_free(b);

  b = pe_builder_new(0x8664);
  if (!b) return 22;
  pe_builder_add_section(b, ".bad", NULL, 16, 0x40000040);
  if (pe_builder_write(b, "pe_writer_invalid_section.exe") == 0) {
    pe_builder_free(b); return 23;
  }
  pe_builder_free(b);

  for (int fail = 0; fail < 8; ++fail) {
    char value[16];
    sprintf(value, "%d", fail);
    _putenv_s("RAWRXD_PEWRITER_FAIL_ALLOC_AFTER", value);
    b = pe_builder_new(0x8664);
    if (b) {
      pe_builder_add_section(b, ".text", &byte, 1, 0x60000020);
      (void)pe_builder_write(b, "pe_writer_alloc_fault.exe");
      pe_builder_free(b);
    }
  }
  _putenv_s("RAWRXD_PEWRITER_FAIL_ALLOC_AFTER", "");
  return 0;
}

static int write_relocation_case(void) {
  pe_builder_t *b = pe_builder_new(0x8664);
  if (!b) return 30;
  uint8_t code[0x30] = {
    0x48, 0xB8, 0,0,0,0,0,0,0,0,       /* mov rax, image+0x2000 */
    0x80, 0x38, 0x2A,                   /* cmp byte ptr [rax], 42 */
    0x75, 0x0B,                         /* jne fail */
    0xB8, 0x2A, 0,0,0, 0xC3,           /* return 42 */
    0xB8, 0x01,0,0,0, 0xC3              /* fail: return 1 */
  };
  uint64_t target = UINT64_C(0x140000000) + 0x2000;
  memcpy(code + 2, &target, sizeof(target));
  const uint8_t data = 42;
  pe_builder_add_section(b, ".text", code, 0x30, 0x60000020);
  pe_builder_add_section(b, ".data", &data, 1, 0xC0000040);
  pe_builder_set_entry(b, 0x1000);
  if (pe_builder_add_base_relocation(b, 0x1002) != 0 ||
      pe_builder_write(b, "pe_writer_relocated.exe") != 0) {
    pe_builder_free(b); return 31;
  }
  pe_builder_free(b);
  return 0;
}

static int write_unwind_case(void) {
  pe_builder_t *b = pe_builder_new(0x8664);
  if (!b) return 40;
  const uint8_t code[] = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
                           0xCC, 0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3 };
  /* Version 1, no flags; prolog 8 bytes; two unwind codes:
   * PUSH_NONVOL RBP at offset 1 and ALLOC_SMALL 0x20 at offset 8. */
  const uint8_t xdata[] = { 0x01, 0x08, 0x02, 0x00, 0x08, 0x32, 0x01, 0x50 };
  uint8_t pdata[12] = { 0};
  uint32_t begin = 0x1000, end = 0x1000 + sizeof(code), unwind = 0;
  memcpy(pdata + 0, &begin, 4); memcpy(pdata + 4, &end, 4);
  memcpy(pdata + 8, &unwind, 4);
  pe_builder_add_section(b, ".text", code, sizeof(code), 0x60000020);
  pe_builder_add_section(b, ".pdata", pdata, sizeof(pdata), 0x40000040);
  pe_builder_add_section(b, ".xdata", xdata, sizeof(xdata), 0x40000040);
  pe_builder_set_entry(b, 0x1000);
  int rc = pe_builder_write(b, "pe_writer_unwind.exe");
  pe_builder_free(b);
  return rc == 0 ? 0 : 41;
}

static int run_forced_relocation(void) {
  SIZE_T bytes = 0;
  STARTUPINFOEXA si = {0};
  PROCESS_INFORMATION pi = {0};
  si.StartupInfo.cb = sizeof(si);
  InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
  si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, bytes);
  if (!si.lpAttributeList || !InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &bytes)) return 32;
  DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON;
  if (!UpdateProcThreadAttribute(si.lpAttributeList, 0,
      PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL)) return 33;
  char cmd[] = "pe_writer_relocated.exe";
  BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
      EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL,
      &si.StartupInfo, &pi);
  DeleteProcThreadAttributeList(si.lpAttributeList);
  HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
  if (!ok) return 34;
  typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
  } raw_process_basic_information;
  typedef LONG (WINAPI *nt_query_information_process_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  nt_query_information_process_fn nt_query =
      (nt_query_information_process_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                       "NtQueryInformationProcess");
  raw_process_basic_information pbi = {0};
  ULONG return_length = 0;
  PVOID actual_base = NULL;
  if (!nt_query || nt_query(pi.hProcess, 0, &pbi, sizeof(pbi), &return_length) < 0 ||
      !pbi.PebBaseAddress ||
      !ReadProcessMemory(pi.hProcess, (BYTE *)pbi.PebBaseAddress + 0x10,
                         &actual_base, sizeof(actual_base), NULL)) {
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 36;
  }
  const uint64_t preferred_base = UINT64_C(0x140000000);
  const int64_t delta = (int64_t)((uint64_t)(uintptr_t)actual_base - preferred_base);
  printf("RELOCATION preferred=0x%llx actual=0x%llx delta=%lld\n",
         (unsigned long long)preferred_base,
         (unsigned long long)(uintptr_t)actual_base,
         (long long)delta);
  if (delta == 0) {
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 37;
  }
  if (ResumeThread(pi.hThread) == (DWORD)-1) {
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 38;
  }
  WaitForSingleObject(pi.hProcess, 10000);
  DWORD exit_code = 0xFFFFFFFF;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
  printf("RELOCATION child_exit=%lu\n", (unsigned long)exit_code);
  return exit_code == 42 ? 0 : 35;
}

static int run_unwind_runtime(void) {
  HMODULE image = LoadLibraryExA("pe_writer_unwind.exe", NULL,
                                DONT_RESOLVE_DLL_REFERENCES);
  if (!image) { fprintf(stderr, "unwind: LoadLibraryEx failed=%lu\n", GetLastError()); return 50; }
  DWORD64 base = (DWORD64)(uintptr_t)image;
  PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(base + 0x1008, &base, NULL);
  if (!fn || fn->BeginAddress != 0x1000 || fn->UnwindData == 0) {
    fprintf(stderr, "unwind: lookup failed fn=%p begin=%lx data=%lx\n", (void*)fn,
            fn ? (unsigned long)fn->BeginAddress : 0,
            fn ? (unsigned long)fn->UnwindData : 0);
    FreeLibrary(image); return 51;
  }
  DWORD64 fakeStack[64] = {0};
  const DWORD64 savedRbp = UINT64_C(0x1122334455667788);
  const DWORD64 callerRip = UINT64_C(0x8877665544332211);
  DWORD64 *rsp = &fakeStack[16];
  rsp[4] = savedRbp;  /* saved RBP after sub rsp, 0x20 */
  rsp[5] = callerRip; /* caller return address */
  CONTEXT ctx = {0};
  ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  ctx.Rip = base + 0x1008;
  ctx.Rsp = (DWORD64)(uintptr_t)rsp;
  ctx.Rbp = 0;
  PVOID handlerData = NULL;
  DWORD64 establisher = 0;
  KNONVOLATILE_CONTEXT_POINTERS nv = {0};
  ULONG64 imageBase = base;
  DWORD64 controlPc = ctx.Rip;
  PVOID result = RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase,
                                    controlPc, fn, &ctx, &handlerData,
                                    &establisher, &nv);
  (void)result;
  int ok = ctx.Rip == callerRip && ctx.Rbp == savedRbp &&
           ctx.Rsp == (DWORD64)(uintptr_t)(rsp + 6);
  int caught = 0;
  __try {
    ((void (*)(void))((BYTE *)image + 0x1000))();
  } __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    caught = 1;
  }
  FreeLibrary(image);
  printf("UNWIND virtual_unwind=%s\n", ok ? "PASS" : "DIAGNOSTIC_MISMATCH");
  if (!ok) fprintf(stderr, "unwind: rip=%llx rbp=%llx rsp=%llx\n",
                   (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rbp,
                   (unsigned long long)ctx.Rsp);
  printf("UNWIND exception_propagation=%s\n", caught ? "PASS" : "FAIL");
  return caught ? 0 : 53;
}

int main(void) {
  if (write_case("pe_writer_minimal.exe", 0x100, 0) != 0) return 1;
  if (write_case("pe_writer_large_import.exe", 0x5000, 1) != 0) return 2;
  if (negative_cases() != 0) return 3;
  if (write_relocation_case() != 0 || run_forced_relocation() != 0) return 4;
  if (write_unwind_case() != 0) return 5;
  if (run_unwind_runtime() != 0) return 6;
  puts("PE_WRITER_E2E_GENERATED=PASS");
  return 0;
}
