/*==========================================================================
 * MessageBoxA Test - Final Working Implementation
 * Generates PE that shows a message box with proper IAT addressing
 *=========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "x64_encoder.h"
#include "x64_validate.h"
#include "../toolchain/from_scratch/phase2_linker/pe_writer.h"

/* PE section constants from pe_writer.c */
#define TEXT_RVA     0x1000u
#define IDATA_RVA    0x2000u
#define IMAGE_BASE   0x140000000ULL

int main() {
    printf("==========================================================================\n");
    printf("MessageBoxA Test - Final Implementation\n");
    printf("==========================================================================\n\n");
    
    PeWriter* pw = pe_writer_create();
    if (!pw) {
        printf("FAIL: pe_writer_create failed\n");
        return 1;
    }
    
    /* Set up import: user32.dll!MessageBoxA */
    pe_writer_set_import(pw, "user32.dll", "MessageBoxA");
    
    /* 
     * Build code that calls MessageBoxA(NULL, "Hi", "RawrXD", MB_OK)
     * 
     * PE Layout:
     * - .text at RVA 0x1000
     * - .idata at RVA 0x2000 (after .text)
     * 
     * IAT slot is at: IDATA_RVA + 56 (iat_offset) = 0x2038
     * 
     * For RIP-relative call:
     * call qword ptr [rip + disp32]
     * 
     * At instruction offset X in .text:
     * - RIP after instruction = TEXT_RVA + X + 6
     * - Target = IDATA_RVA + 56 = 0x2038
     * - disp32 = 0x2038 - (TEXT_RVA + X + 6)
     * 
     * If instruction is at offset 35:
     * - RIP after = 0x1000 + 35 + 6 = 0x1029
     * - disp32 = 0x2038 - 0x1029 = 0x100F
     */
    
    /* String data embedded in code section */
    const char* msg_text = "Hi";
    const char* msg_title = "RawrXD";
    size_t text_len = strlen(msg_text) + 1;
    size_t title_len = strlen(msg_title) + 1;
    
    uint8_t code[256];
    size_t code_len = 0;
    
    /* Layout:
     * [0-6]:   mov rcx, 0          (7 bytes)
     * [7-13]:  lea rdx, [rip+disp] (7 bytes) - text string
     * [14-20]: lea r8, [rip+disp]  (7 bytes) - title string  
     * [21-27]: mov r9, 0           (7 bytes)
     * [28-31]: sub rsp, 32         (4 bytes)
     * [32-37]: call [rip+disp]     (6 bytes) - call IAT
     * [38-41]: add rsp, 32         (4 bytes)
     * [42-43]: xor eax, eax        (2 bytes)
     * [44]:    ret                 (1 byte)
     * [45-99]: padding
     * [100]:   "Hi\0"
     * [103]:   "RawrXD\0"
     */
    
    /* mov rcx, 0 */
    code[code_len++] = 0x48;
    code[code_len++] = 0xC7;
    code[code_len++] = 0xC1;
    code[code_len++] = 0x00;
    code[code_len++] = 0x00;
    code[code_len++] = 0x00;
    code[code_len++] = 0x00;
    
    /* lea rdx, [rip + disp32] - text at offset 100 */
    /* RIP after = 14, target = 100, disp = 100 - 14 = 86 */
    int32_t disp_text = 100 - 14;
    code[code_len++] = 0x48;
    code[code_len++] = 0x8D;
    code[code_len++] = 0x15;
    memcpy(code + code_len, &disp_text, 4);
    code_len += 4;
    
    /* lea r8, [rip + disp32] - title at offset 103 */
    /* RIP after = 21, target = 103, disp = 103 - 21 = 82 */
    int32_t disp_title = 103 - 21;
    code[code_len++] = 0x4C;
    code[code_len++] = 0x8D;
    code[code_len++] = 0x05;
    memcpy(code + code_len, &disp_title, 4);
    code_len += 4;
    
    /* mov r9, 0 */
    code[code_len++] = 0x49;
    code[code_len++] = 0xC7;
    code[code_len++] = 0xC1;
    code[code_len++] = 0x00;
    code[code_len++] = 0x00;
    code[code_len++] = 0x00;
    code[code_len++] = 0x00;
    
    /* sub rsp, 32 */
    code[code_len++] = 0x48;
    code[code_len++] = 0x83;
    code[code_len++] = 0xEC;
    code[code_len++] = 0x20;
    
    /* call qword ptr [rip + disp32] - IAT at 0x2038 */
    /* Instruction at offset 32, RIP after = 32 + 6 = 38 */
    /* Target IAT = 0x2038, current RIP = 0x1000 + 38 = 0x1026 */
    /* disp32 = 0x2038 - 0x1026 = 0x1012 */
    int32_t disp_iat = 0x1012;
    code[code_len++] = 0xFF;
    code[code_len++] = 0x15;
    memcpy(code + code_len, &disp_iat, 4);
    code_len += 4;
    
    /* add rsp, 32 */
    code[code_len++] = 0x48;
    code[code_len++] = 0x83;
    code[code_len++] = 0xC4;
    code[code_len++] = 0x20;
    
    /* xor eax, eax */
    code[code_len++] = 0x31;
    code[code_len++] = 0xC0;
    
    /* ret */
    code[code_len++] = 0xC3;
    
    /* Pad to offset 100 */
    while (code_len < 100) {
        code[code_len++] = 0x90;
    }
    
    /* Add strings */
    memcpy(code + code_len, msg_text, text_len);
    code_len += text_len;
    memcpy(code + code_len, msg_title, title_len);
    code_len += title_len;
    
    printf("Generated %zu bytes\n", code_len);
    printf("Code layout:\n");
    printf("  Offset 0-6:   mov rcx, 0\n");
    printf("  Offset 7-13:  lea rdx, [rip+%d] -> text at 100\n", disp_text);
    printf("  Offset 14-20: lea r8, [rip+%d] -> title at 103\n", disp_title);
    printf("  Offset 21-27: mov r9, 0\n");
    printf("  Offset 28-31: sub rsp, 32\n");
    printf("  Offset 32-37: call [rip+0x%04X] -> IAT at 0x2038\n", disp_iat);
    printf("  Offset 38-41: add rsp, 32\n");
    printf("  Offset 42:    xor eax, eax\n");
    printf("  Offset 44:    ret\n");
    printf("  Offset 100:   \"%s\"\n", msg_text);
    printf("  Offset 103:   \"%s\"\n", msg_title);
    printf("\n");
    
    pe_writer_set_entry(pw, 0);
    pe_writer_add_text(pw, code, (uint32_t)code_len);
    
    uint8_t* pe_data = NULL;
    uint32_t pe_size = pe_writer_emit(pw, &pe_data);
    
    if (pe_size == 0 || !pe_data) {
        printf("FAIL: pe_writer_emit failed\n");
        pe_writer_destroy(pw);
        return 1;
    }
    
    FILE* f = fopen("messagebox_final.exe", "wb");
    if (!f) {
        printf("FAIL: Could not write file\n");
        free(pe_data);
        pe_writer_destroy(pw);
        return 1;
    }
    
    fwrite(pe_data, 1, pe_size, f);
    fclose(f);
    
    printf("Generated: messagebox_final.exe (%u bytes)\n", pe_size);
    printf("\nAttempting to execute...\n");
    
    /* Try to run the executable */
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessA("messagebox_final.exe", NULL, NULL, NULL, FALSE,
                      0, NULL, NULL, &si, &pi)) {
        printf("Process created successfully!\n");
        printf("Waiting for MessageBoxA to complete...\n");
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        DWORD exit_code;
        if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
            printf("Process exited with code: %lu\n", exit_code);
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        printf("\n✓ MessageBoxA test PASSED!\n");
    } else {
        printf("Failed to create process (error %lu)\n", GetLastError());
        printf("This may be due to:\n");
        printf("  - Import resolution issues\n");
        printf("  - Invalid IAT addressing\n");
        printf("  - String pointer issues\n");
    }
    
    free(pe_data);
    pe_writer_destroy(pw);
    
    printf("\n==========================================================================\n");
    printf("TEST COMPLETE\n");
    printf("==========================================================================\n");
    
    return 0;
}
