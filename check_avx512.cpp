#include <stdio.h>
#include <cpuid.h>

int main() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(7, &eax, &ebx, &ecx, &edx)) {
        bool avx512f = (ebx & (1 << 16)) != 0;
        printf("AVX-512F: %s\n", avx512f ? "YES" : "NO");
        
        // Check XCR0
        unsigned int xcr0_eax, xcr0_edx;
        __asm__ __volatile__("xgetbv" : "=a"(xcr0_eax), "=d"(xcr0_edx) : "c"(0));
        unsigned long long xcr0 = ((unsigned long long)xcr0_edx << 32) | xcr0_eax;
        printf("XCR0: 0x%llx\n", xcr0);
        printf("ZMM state: %s\n", (xcr0 & 0xE0) == 0xE0 ? "enabled" : "disabled");
    } else {
        printf("CPUID not supported\n");
    }
    return 0;
}
