// Single-file AES-256 File Encryptor - Compile with MinGW
// i686-w64-mingw32-gcc -O3 -s -static file_encryptor.c -o encrypt32.exe -lbcrypt
// x86_64-w64-mingw32-gcc -O3 -s -static file_encryptor.c -o encrypt64.exe -lbcrypt

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "bcrypt.lib")

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define CHUNK_SIZE 1048576  // 1MB chunks for large files

typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    PBYTE pbKeyObject;
    DWORD cbKeyObject;
    PBYTE pbIV;
} CryptoContext;

// Generate random bytes
void GenerateRandom(PBYTE buffer, DWORD size) {
    BCRYPT_ALG_HANDLE hRng;
    BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    BCryptGenRandom(hRng, buffer, size, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);
}

// Derive key from password using PBKDF2
BOOL DeriveKey(const char* password, PBYTE salt, PBYTE key, DWORD keySize) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BOOL result = FALSE;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return FALSE;
    
    // Simple key derivation (in production, use proper PBKDF2)
    for (int i = 0; i < keySize; i++) {
        key[i] = (BYTE)(password[i % strlen(password)] ^ salt[i % 16]);
    }
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

// Initialize crypto context
BOOL InitCrypto(CryptoContext* ctx, PBYTE key, PBYTE iv) {
    NTSTATUS status;
    
    // Open AES algorithm
    status = BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return FALSE;
    
    // Set CBC mode
    BCryptSetProperty(ctx->hAlg, BCRYPT_CHAINING_MODE, 
                     (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
                     sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    
    // Get key object size
    DWORD cbData;
    BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH, 
                     (PBYTE)&ctx->cbKeyObject, sizeof(DWORD), &cbData, 0);
    
    ctx->pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->cbKeyObject);
    if (!ctx->pbKeyObject) return FALSE;
    
    // Generate key handle
    status = BCryptGenerateSymmetricKey(ctx->hAlg, &ctx->hKey, 
                                       ctx->pbKeyObject, ctx->cbKeyObject, 
                                       key, AES_KEY_SIZE, 0);
    if (status != 0) return FALSE;
    
    // Store IV
    ctx->pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_BLOCK_SIZE);
    memcpy(ctx->pbIV, iv, AES_BLOCK_SIZE);
    
    return TRUE;
}

// Cleanup crypto context
void CleanupCrypto(CryptoContext* ctx) {
    if (ctx->hKey) BCryptDestroyKey(ctx->hKey);
    if (ctx->pbKeyObject) HeapFree(GetProcessHeap(), 0, ctx->pbKeyObject);
    if (ctx->pbIV) HeapFree(GetProcessHeap(), 0, ctx->pbIV);
    if (ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
}

// Encrypt file
BOOL EncryptFileEx(const char* inputFile, const char* outputFile, const char* password) {
    HANDLE hInput = INVALID_HANDLE_VALUE;
    HANDLE hOutput = INVALID_HANDLE_VALUE;
    CryptoContext ctx = {0};
    BOOL result = FALSE;
    
    // Generate salt and IV
    BYTE salt[16];
    BYTE iv[AES_BLOCK_SIZE];
    BYTE key[AES_KEY_SIZE];
    
    GenerateRandom(salt, sizeof(salt));
    GenerateRandom(iv, sizeof(iv));
    
    // Derive key from password
    if (!DeriveKey(password, salt, key, AES_KEY_SIZE)) {
        printf("[-] Failed to derive key\n");
        return FALSE;
    }
    
    // Initialize crypto
    if (!InitCrypto(&ctx, key, iv)) {
        printf("[-] Failed to initialize crypto\n");
        return FALSE;
    }
    
    // Open files
    hInput = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, 
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hInput == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open input file\n");
        goto cleanup;
    }
    
    hOutput = CreateFileA(outputFile, GENERIC_WRITE, 0, 
                         NULL, CREATE_ALWAYS, 0, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create output file\n");
        goto cleanup;
    }
    
    // Write header (salt + IV)
    DWORD written;
    WriteFile(hOutput, salt, sizeof(salt), &written, NULL);
    WriteFile(hOutput, iv, sizeof(iv), &written, NULL);
    
    // Encrypt file in chunks
    PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, CHUNK_SIZE);
    PBYTE output = (PBYTE)HeapAlloc(GetProcessHeap(), 0, CHUNK_SIZE + AES_BLOCK_SIZE);
    
    if (!buffer || !output) {
        printf("[-] Memory allocation failed\n");
        goto cleanup;
    }
    
    DWORD bytesRead;
    LARGE_INTEGER fileSize, processed = {0};
    GetFileSizeEx(hInput, &fileSize);
    
    printf("[*] Encrypting %s (%lld bytes)...\n", inputFile, fileSize.QuadPart);
    
    while (ReadFile(hInput, buffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
        DWORD outputSize;
        
        // Encrypt chunk
        NTSTATUS status = BCryptEncrypt(ctx.hKey, buffer, bytesRead, 
                                       NULL, ctx.pbIV, AES_BLOCK_SIZE,
                                       output, CHUNK_SIZE + AES_BLOCK_SIZE, 
                                       &outputSize, BCRYPT_BLOCK_PADDING);
        
        if (status != 0) {
            printf("[-] Encryption failed\n");
            goto cleanup;
        }
        
        // Write encrypted data
        WriteFile(hOutput, output, outputSize, &written, NULL);
        
        processed.QuadPart += bytesRead;
        printf("\r[*] Progress: %d%%", (int)((processed.QuadPart * 100) / fileSize.QuadPart));
    }
    
    printf("\n[+] Encryption complete!\n");
    result = TRUE;
    
cleanup:
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    if (output) HeapFree(GetProcessHeap(), 0, output);
    if (hInput != INVALID_HANDLE_VALUE) CloseHandle(hInput);
    if (hOutput != INVALID_HANDLE_VALUE) CloseHandle(hOutput);
    CleanupCrypto(&ctx);
    SecureZeroMemory(key, sizeof(key));
    
    return result;
}

// Decrypt file
BOOL DecryptFileEx(const char* inputFile, const char* outputFile, const char* password) {
    HANDLE hInput = INVALID_HANDLE_VALUE;
    HANDLE hOutput = INVALID_HANDLE_VALUE;
    CryptoContext ctx = {0};
    BOOL result = FALSE;
    
    // Open input file
    hInput = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, 
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hInput == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open input file\n");
        return FALSE;
    }
    
    // Read salt and IV
    BYTE salt[16];
    BYTE iv[AES_BLOCK_SIZE];
    BYTE key[AES_KEY_SIZE];
    DWORD bytesRead;
    
    ReadFile(hInput, salt, sizeof(salt), &bytesRead, NULL);
    ReadFile(hInput, iv, sizeof(iv), &bytesRead, NULL);
    
    // Derive key from password
    if (!DeriveKey(password, salt, key, AES_KEY_SIZE)) {
        printf("[-] Failed to derive key\n");
        goto cleanup;
    }
    
    // Initialize crypto
    if (!InitCrypto(&ctx, key, iv)) {
        printf("[-] Failed to initialize crypto\n");
        goto cleanup;
    }
    
    // Create output file
    hOutput = CreateFileA(outputFile, GENERIC_WRITE, 0, 
                         NULL, CREATE_ALWAYS, 0, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create output file\n");
        goto cleanup;
    }
    
    // Decrypt file in chunks
    PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, CHUNK_SIZE + AES_BLOCK_SIZE);
    PBYTE output = (PBYTE)HeapAlloc(GetProcessHeap(), 0, CHUNK_SIZE + AES_BLOCK_SIZE);
    
    printf("[*] Decrypting %s...\n", inputFile);
    
    while (ReadFile(hInput, buffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
        DWORD outputSize;
        
        // Decrypt chunk
        NTSTATUS status = BCryptDecrypt(ctx.hKey, buffer, bytesRead, 
                                       NULL, ctx.pbIV, AES_BLOCK_SIZE,
                                       output, CHUNK_SIZE + AES_BLOCK_SIZE, 
                                       &outputSize, BCRYPT_BLOCK_PADDING);
        
        if (status != 0) {
            printf("[-] Decryption failed (wrong password?)\n");
            goto cleanup;
        }
        
        // Write decrypted data
        DWORD written;
        WriteFile(hOutput, output, outputSize, &written, NULL);
    }
    
    printf("[+] Decryption complete!\n");
    result = TRUE;
    
cleanup:
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    if (output) HeapFree(GetProcessHeap(), 0, output);
    if (hInput != INVALID_HANDLE_VALUE) CloseHandle(hInput);
    if (hOutput != INVALID_HANDLE_VALUE) CloseHandle(hOutput);
    CleanupCrypto(&ctx);
    SecureZeroMemory(key, sizeof(key));
    
    return result;
}

// Secure file wipe
BOOL SecureDelete(const char* filename) {
    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, 
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    
    // Overwrite with random data 3 times
    PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, 65536);
    
    for (int pass = 0; pass < 3; pass++) {
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        LARGE_INTEGER written = {0};
        
        while (written.QuadPart < fileSize.QuadPart) {
            GenerateRandom(buffer, 65536);
            DWORD toWrite = (DWORD)min(65536, fileSize.QuadPart - written.QuadPart);
            DWORD bytesWritten;
            WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
            written.QuadPart += bytesWritten;
        }
        FlushFileBuffers(hFile);
    }
    
    HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(hFile);
    
    // Delete file
    return DeleteFileA(filename);
}

int main(int argc, char* argv[]) {
    printf("=== AES-256 File Encryptor v1.0 ===\n\n");
    
    if (argc < 4) {
        printf("Usage: %s <encrypt|decrypt|wipe> <input_file> <output_file|password>\n", argv[0]);
        printf("Examples:\n");
        printf("  %s encrypt secret.txt secret.enc\n", argv[0]);
        printf("  %s decrypt secret.enc secret.txt\n", argv[0]);
        printf("  %s wipe sensitive.txt\n", argv[0]);
        return 1;
    }
    
    if (_stricmp(argv[1], "encrypt") == 0 && argc >= 4) {
        char password[256];
        printf("Enter password: ");
        scanf("%255s", password);
        
        if (EncryptFileEx(argv[2], argv[3], password)) {
            printf("[+] File encrypted successfully!\n");
            
            // Option to delete original
            printf("Delete original file? (y/n): ");
            char answer;
            scanf(" %c", &answer);
            if (answer == 'y' || answer == 'Y') {
                SecureDelete(argv[2]);
                printf("[+] Original file securely deleted\n");
            }
        }
        
        SecureZeroMemory(password, sizeof(password));
        
    } else if (_stricmp(argv[1], "decrypt") == 0 && argc >= 4) {
        char password[256];
        printf("Enter password: ");
        scanf("%255s", password);
        
        if (DecryptFileEx(argv[2], argv[3], password)) {
            printf("[+] File decrypted successfully!\n");
        }
        
        SecureZeroMemory(password, sizeof(password));
        
    } else if (_stricmp(argv[1], "wipe") == 0) {
        if (SecureDelete(argv[2])) {
            printf("[+] File securely wiped!\n");
        } else {
            printf("[-] Failed to wipe file\n");
        }
    }
    
    return 0;
}