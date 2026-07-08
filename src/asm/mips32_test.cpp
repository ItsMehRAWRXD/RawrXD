#include "d:\rawrxd\src\reverse_engineering\RawrCodex_Multi_v2.hpp"
#include "d:\rawrxd\src\reverse_engineering\abi_validator_simple.cpp"

int main() {
    TestResult result = TestMIPS32_Decode();
    printf("MIPS32 test result: %s - %s\n", result.passed ? "PASS" : "FAIL", result.error ? result.error : "No error");
    return 0;
}