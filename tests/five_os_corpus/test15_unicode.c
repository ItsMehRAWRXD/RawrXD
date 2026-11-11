// Test 15: Unicode paths and text
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
int main(void) {
    setlocale(LC_ALL, "");
    wprintf(L"unicode_\xe4\xf6\xfc\n");  // German umlauts
    return 0;
}
