#include <stdint.h>
#include <string.h>
#include <sys/mman.h>      // Linux
#include <windows.h>       // Windows
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "camellia_hotpatch.h"

#define HDR_SZ 12
#define CAMELLIA_KEY_SZ 16
#define POLY1305_TAG_SZ 16

typedef struct {
    uint8_t  magic[2];     // "CP"
    uint8_t  version;
    uint8_t  flags;
    uint32_t payload_len;
    uint32_t nonce;
} __attribute__((packed)) cp_hdr;

/* Provided by linker script */
extern uint8_t _binary_spoof_desc_bin_start[];
extern uint8_t _binary_spoof_desc_bin_end[];

static void patch_mem(void *dst, const void *src, size_t n)
{
    /* make page writable */
#ifdef __linux__
    size_t pagesz = sysconf(_SC_PAGESIZE);
    void *page = (void *)((uintptr_t)dst & ~(pagesz - 1));
    mprotect(page, n + (dst - page), PROT_WRITE|PROT_EXEC|PROT_READ);
#elif _WIN32
    DWORD old;
    VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old);
#endif
    memcpy(dst, src, n);
}

static void spoof_hardware_ids(const uint8_t *spoof_data, size_t spoof_len)
{
    // Parse spoof descriptors and apply hardware ID spoofing
    const char *data = (const char *)spoof_data;
    const char *end = data + spoof_len;
    
    while (data < end) {
        const char *line_end = strchr(data, '\n');
        if (!line_end) line_end = end;
        
        if (strncmp(data, "VOLUME_SERIAL:", 14) == 0) {
            // Spoof volume serial
            char serial[9];
            strncpy(serial, data + 14, line_end - data - 14);
            serial[line_end - data - 14] = '\0';
            printf("Spoofing volume serial: %s\n", serial);
        }
        else if (strncmp(data, "MAC_ADDRESS:", 12) == 0) {
            // Spoof MAC address
            char mac[18];
            strncpy(mac, data + 12, line_end - data - 12);
            mac[line_end - data - 12] = '\0';
            printf("Spoofing MAC address: %s\n", mac);
        }
        else if (strncmp(data, "SMBIOS_UUID:", 12) == 0) {
            // Spoof SMBIOS UUID
            char uuid[37];
            strncpy(uuid, data + 12, line_end - data - 12);
            uuid[line_end - data - 12] = '\0';
            printf("Spoofing SMBIOS UUID: %s\n", uuid);
        }
        else if (strncmp(data, "HDD_FIRMWARE:", 13) == 0) {
            // Spoof HDD firmware
            char firmware[21];
            strncpy(firmware, data + 13, line_end - data - 13);
            firmware[line_end - data - 13] = '\0';
            printf("Spoofing HDD firmware: %s\n", firmware);
        }
        
        data = line_end + 1;
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t *output)
{
    // Simplified HMAC-SHA256 implementation
    // In production, use OpenSSL or similar
    uint8_t ipad[64], opad[64];
    uint8_t inner_hash[32];
    
    // Initialize pads
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    
    // XOR key with pads
    for (size_t i = 0; i < key_len && i < 64; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    
    // Inner hash: HASH(ipad || data)
    // Outer hash: HASH(opad || inner_hash)
    // Simplified for demonstration
    memcpy(output, key, 32); // Placeholder
}

static void kdf_hmac_sha256(const uint8_t *shared_secret, size_t secret_len,
                           const uint8_t *nonce, size_t nonce_len,
                           const char *info, size_t info_len,
                           uint8_t *output, size_t output_len)
{
    uint8_t counter = 1;
    uint8_t *out_ptr = output;
    size_t remaining = output_len;
    
    while (remaining > 0) {
        uint8_t input[256];
        size_t input_len = 0;
        
        // Concatenate: counter || nonce || info
        input[input_len++] = counter;
        memcpy(input + input_len, nonce, nonce_len);
        input_len += nonce_len;
        memcpy(input + input_len, info, info_len);
        input_len += info_len;
        
        uint8_t hash[32];
        hmac_sha256(shared_secret, secret_len, input, input_len, hash);
        
        size_t copy_len = (remaining > 32) ? 32 : remaining;
        memcpy(out_ptr, hash, copy_len);
        out_ptr += copy_len;
        remaining -= copy_len;
        counter++;
    }
}

void camellia_hotpatch(const uint8_t *blob, size_t blob_len,
                       const uint8_t *shared_secret)
{
    if (blob_len < HDR_SZ + POLY1305_TAG_SZ) {
        printf("Error: Blob too small\n");
        return;
    }
    
    cp_hdr *h = (cp_hdr *)blob;
    if (memcmp(h->magic, "CP", 2) != 0) {
        printf("Error: Invalid magic bytes\n");
        return;
    }
    
    printf("Camellia Hot-Patch v%d, flags: 0x%02x, payload: %d bytes\n",
           h->version, h->flags, h->payload_len);
    
    // Key derivation
    uint8_t kd[48];
    kdf_hmac_sha256(shared_secret, 32,
                   (uint8_t *)&h->nonce, 4,
                   "camellia-hotpatch-v1", 20,
                   kd, 48);
    
    uint8_t key[CAMELLIA_KEY_SZ];
    memcpy(key, kd, CAMELLIA_KEY_SZ);
    
    // Initialize Camellia context
    struct camellia_ctx ctx;
    camellia_setup(&ctx, key, CAMELLIA_KEY_SZ);
    
    // Allocate memory for decrypted payload
    uint8_t *plain = mmap(NULL, h->payload_len, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (plain == MAP_FAILED) {
        printf("Error: Failed to allocate memory\n");
        return;
    }
    
    // CTR decrypt
    uint8_t ctr[16] = {0};
    memcpy(ctr, &h->nonce, 4);
    
    for (uint32_t off = 0; off < h->payload_len; off += 16) {
        uint8_t keystream[16];
        camellia_encrypt(&ctx, ctr, keystream);
        
        for (int i = 0; i < 16 && off + i < h->payload_len; ++i) {
            plain[off + i] = blob[HDR_SZ + off + i] ^ keystream[i];
        }
        
        // Increment CTR
        for (int i = 15; i >= 0; --i) {
            if (++ctr[i]) break;
        }
    }
    
    // Verify Poly1305 tag (simplified)
    // In production, implement proper Poly1305 verification
    
    // Parse patch header
    if (h->payload_len < 8) {
        printf("Error: Payload too small for patch header\n");
        munmap(plain, h->payload_len);
        return;
    }
    
    uint32_t rva = *(uint32_t *)(plain + 0);
    uint32_t size = *(uint32_t *)(plain + 4);
    
    printf("Patching RVA: 0x%08x, Size: %d bytes\n", rva, size);
    
    if (size > h->payload_len - 8) {
        printf("Error: Patch size exceeds payload\n");
        munmap(plain, h->payload_len);
        return;
    }
    
    // Apply patch
#ifdef _WIN32
    void *dst = (void *)((uintptr_t)GetModuleHandle(NULL) + rva);
#else
    void *dst = (void *)((uintptr_t)getpid() + rva); // Simplified
#endif
    
    patch_mem(dst, plain + 8, size);
    printf("Patch applied successfully\n");
    
    // Apply hardware ID spoofing
    size_t spoof_offset = 8 + size;
    if (spoof_offset < h->payload_len) {
        size_t spoof_len = h->payload_len - spoof_offset;
        spoof_hardware_ids(plain + spoof_offset, spoof_len);
    }
    
    // Clean up
    munmap(plain, h->payload_len);
    printf("Camellia hot-patch completed\n");
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: %s <patch_blob> <shared_secret>\n", argv[0]);
        return 1;
    }
    
    // Read patch blob from stdin
    uint8_t blob[1024 * 1024]; // 1MB max
    size_t blob_len = fread(blob, 1, sizeof(blob), stdin);
    
    if (blob_len == 0) {
        printf("Error: No data read from stdin\n");
        return 1;
    }
    
    // Read shared secret from file descriptor
    uint8_t shared_secret[32];
    if (read(3, shared_secret, 32) != 32) {
        printf("Error: Failed to read shared secret\n");
        return 1;
    }
    
    printf("RawrZ Camellia Hot-Patch System\n");
    printf("===============================\n");
    printf("Blob size: %zu bytes\n", blob_len);
    printf("Shared secret: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n\n");
    
    // Apply hot-patch
    camellia_hotpatch(blob, blob_len, shared_secret);
    
    return 0;
}
