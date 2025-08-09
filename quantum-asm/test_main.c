#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Declare our assembly functions
extern int test_masm_function(void);
extern int add_numbers(int a, int b);
extern void xor_encrypt(unsigned char* data, size_t length, unsigned char key);

// Test data
const char* test_string = "Hello, Quantum Assembly!";

int main() {
    printf("=== MinGW Assembly Test Program ===\n\n");
    
    // Test 1: Simple function
    printf("Test 1 - test_masm_function():\n");
    int result = test_masm_function();
    printf("  Expected: 42, Got: %d %s\n", result, (result == 42) ? "[PASS]" : "[FAIL]");
    
    // Test 2: Add numbers
    printf("\nTest 2 - add_numbers():\n");
    int sum = add_numbers(15, 27);
    printf("  15 + 27 = %d %s\n", sum, (sum == 42) ? "[PASS]" : "[FAIL]");
    
    // Test 3: XOR encryption
    printf("\nTest 3 - xor_encrypt():\n");
    char buffer[256];
    strcpy(buffer, test_string);
    size_t len = strlen(buffer);
    unsigned char key = 0x42;
    
    printf("  Original: %s\n", buffer);
    
    // Encrypt
    xor_encrypt((unsigned char*)buffer, len, key);
    printf("  Encrypted: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", (unsigned char)buffer[i]);
    }
    printf("\n");
    
    // Decrypt (XOR with same key)
    xor_encrypt((unsigned char*)buffer, len, key);
    printf("  Decrypted: %s %s\n", buffer, 
           (strcmp(buffer, test_string) == 0) ? "[PASS]" : "[FAIL]");
    
    printf("\n=== All tests completed ===\n");
    
    return 0;
}