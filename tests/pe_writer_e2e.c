#include "../src/toolchain/linker/pe_writer.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

int main(void) {
  if (write_case("pe_writer_minimal.exe", 0x100, 0) != 0) return 1;
  if (write_case("pe_writer_large_import.exe", 0x5000, 1) != 0) return 2;
  if (negative_cases() != 0) return 3;
  puts("PE_WRITER_E2E_GENERATED=PASS");
  return 0;
}
