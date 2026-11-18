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
  }
  pe_builder_set_entry(b, 0x1000);
  int rc = pe_builder_write(b, path);
  pe_builder_free(b);
  return rc == 0 ? 0 : 12;
}

int main(void) {
  if (write_case("pe_writer_minimal.exe", 0x100, 0) != 0) return 1;
  if (write_case("pe_writer_large_import.exe", 0x5000, 1) != 0) return 2;
  puts("PE_WRITER_E2E_GENERATED=PASS");
  return 0;
}
