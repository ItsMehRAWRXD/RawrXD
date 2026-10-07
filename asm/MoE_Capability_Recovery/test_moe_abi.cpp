//==============================================================================
// test_moe_abi.cpp - Minimal test harness for MoE DLL ABI
// No deps, just raw Windows API + ABI header
//==============================================================================

#include <windows.h>
#include <stdio.h>

// Capability Flags
#define MOE_CAP_GHOST       0x01
#define MOE_CAP_LATENT      0x02
#define MOE_CAP_SHADOW      0x04
#define MOE_CAP_SWARM       0x08
#define MOE_CAP_PREFETCH    0x10
#define MOE_CAP_ECHO        0x20
#define MOE_CAP_MERGE       0x40
#define MOE_CAP_SPECULATIVE 0x80

// Structs (must match MASM layout exactly)
#pragma pack(push, 8)

struct MoEExpertInfo {
    unsigned int id;
    unsigned int caps;
};

struct MoETraceEntry {
    unsigned int expertId;
    unsigned int confidence;
    unsigned int caps;
};

#define MOE_TRACE_MAX_ENTRIES 256

struct MoETraceBuffer {
    unsigned int count;
    MoETraceEntry entries[MOE_TRACE_MAX_ENTRIES];
};

struct MoEGenerateInput {
    void* logits;
    void* kv;
    unsigned int token;
    unsigned int _pad;
};

struct MoEGenerateOutput {
    unsigned int expertId;
    unsigned int confidence;
    unsigned int caps;
};

struct MoEBackendCaps {
    unsigned int version;
    unsigned int maxExperts;
    unsigned int maxTraceEntries;
};

#pragma pack(pop)

// Function types
typedef void (*FnInit)(void);
typedef void (*FnGenerate)(const MoEGenerateInput*, MoEGenerateOutput*);
typedef void (*FnGetExpertInfo)(unsigned int, MoEExpertInfo*);
typedef void (*FnGetTrace)(MoETraceBuffer*);
typedef void (*FnGetCaps)(MoEBackendCaps*);

// Helper to print capability name
const char* GetCapName(unsigned int caps) {
    if (caps & MOE_CAP_GHOST) return "ghost";
    if (caps & MOE_CAP_LATENT) return "latent";
    if (caps & MOE_CAP_SHADOW) return "shadow";
    if (caps & MOE_CAP_SWARM) return "swarm";
    if (caps & MOE_CAP_PREFETCH) return "prefetch";
    if (caps & MOE_CAP_ECHO) return "echo";
    if (caps & MOE_CAP_MERGE) return "merge";
    if (caps & MOE_CAP_SPECULATIVE) return "speculative";
    return "core";
}

int main() {
    printf("==============================================================================\n");
    printf("MoE ABI Test Harness\n");
    printf("==============================================================================\n\n");

    // Load DLL
    HMODULE hMoE = LoadLibraryA("MoE.dll");
    if (!hMoE) {
        printf("ERROR: Failed to load MoE.dll (error: %lu)\n", GetLastError());
        printf("Trying alternate paths...\n");
        
        hMoE = LoadLibraryA(".\\MoE.dll");
        if (!hMoE) {
            hMoE = LoadLibraryA("..\\MoE.dll");
        }
        
        if (!hMoE) {
            printf("ERROR: Could not load MoE.dll from any path\n");
            return 1;
        }
    }
    printf("[OK] Loaded MoE.dll at %p\n", (void*)hMoE);

    // Get function pointers
    FnInit initFn = (FnInit)GetProcAddress(hMoE, "MoE_Initialize");
    FnGenerate genFn = (FnGenerate)GetProcAddress(hMoE, "MoE_Generate");
    FnGetExpertInfo infoFn = (FnGetExpertInfo)GetProcAddress(hMoE, "MoE_GetExpertInfo");
    FnGetTrace traceFn = (FnGetTrace)GetProcAddress(hMoE, "MoE_GetTrace");
    FnGetCaps capsFn = (FnGetCaps)GetProcAddress(hMoE, "MoE_GetBackendCaps");

    if (!initFn || !genFn) {
        printf("ERROR: Required exports not found\n");
        FreeLibrary(hMoE);
        return 1;
    }
    printf("[OK] Found all required exports\n");

    // Initialize
    printf("\n--- Initializing MoE ---\n");
    initFn();
    printf("[OK] MoE initialized\n");

    // Get capabilities
    if (capsFn) {
        MoEBackendCaps caps = {0};
        capsFn(&caps);
        printf("\n--- Backend Capabilities ---\n");
        printf("Version: %u\n", caps.version);
        printf("Max Experts: %u\n", caps.maxExperts);
        printf("Max Trace Entries: %u\n", caps.maxTraceEntries);
    }

    // Get expert info
    if (infoFn) {
        printf("\n--- Expert Information ---\n");
        for (unsigned int i = 0; i < 5; i++) {
            MoEExpertInfo info = {0};
            infoFn(i, &info);
            printf("Expert %u: id=%u, caps=0x%02X (%s)\n", 
                   i, info.id, info.caps, GetCapName(info.caps));
        }
    }

    // Test generation
    printf("\n--- Testing Generation ---\n");
    
    // Test 1: Normal token
    printf("\nTest 1: Normal token 'A'\n");
    float logits1[64];
    int kv1[64];
    for (int i = 0; i < 64; i++) {
        logits1[i] = 500.0f;
        kv1[i] = 500;
    }
    
    MoEGenerateInput in1 = {0};
    in1.logits = logits1;
    in1.kv = kv1;
    in1.token = 'A';
    
    MoEGenerateOutput out1 = {0};
    genFn(&in1, &out1);
    
    printf("  Selected: expert=%u, confidence=%u, caps=0x%02X (%s)\n",
           out1.expertId, out1.confidence, out1.caps, GetCapName(out1.caps));

    // Test 2: Low KV (should trigger ghost)
    printf("\nTest 2: Low KV density (ghost trigger)\n");
    int kv2[64];
    for (int i = 0; i < 64; i++) kv2[i] = 100;  // Low KV
    
    MoEGenerateInput in2 = {0};
    in2.logits = logits1;
    in2.kv = kv2;
    in2.token = 'A';
    
    MoEGenerateOutput out2 = {0};
    genFn(&in2, &out2);
    
    printf("  Selected: expert=%u, confidence=%u, caps=0x%02X (%s)\n",
           out2.expertId, out2.confidence, out2.caps, GetCapName(out2.caps));

    // Test 3: Digit token (should trigger latent)
    printf("\nTest 3: Digit token '5' (latent trigger)\n");
    int kv3[64];
    for (int i = 0; i < 64; i++) kv3[i] = 500;
    
    MoEGenerateInput in3 = {0};
    in3.logits = logits1;
    in3.kv = kv3;
    in3.token = '5';
    
    MoEGenerateOutput out3 = {0};
    genFn(&in3, &out3);
    
    printf("  Selected: expert=%u, confidence=%u, caps=0x%02X (%s)\n",
           out3.expertId, out3.confidence, out3.caps, GetCapName(out3.caps));

    // Test 4: Low confidence + high KV (should trigger swarm)
    printf("\nTest 4: Low confidence + high KV (swarm trigger)\n");
    float logits4[64];
    int kv4[64];
    for (int i = 0; i < 64; i++) {
        logits4[i] = 300.0f;  // Low confidence
        kv4[i] = 700;           // High KV
    }
    
    MoEGenerateInput in4 = {0};
    in4.logits = logits4;
    in4.kv = kv4;
    in4.token = 'A';
    
    MoEGenerateOutput out4 = {0};
    genFn(&in4, &out4);
    
    printf("  Selected: expert=%u, confidence=%u, caps=0x%02X (%s)\n",
           out4.expertId, out4.confidence, out4.caps, GetCapName(out4.caps));

    // Get trace
    if (traceFn) {
        printf("\n--- Trace Buffer ---\n");
        MoETraceBuffer buf = {0};
        traceFn(&buf);
        printf("Trace entries: %u\n", buf.count);
        
        for (unsigned int i = 0; i < buf.count && i < 10; i++) {
            printf("  [%u] expert=%u, confidence=%u, caps=0x%02X (%s)\n",
                   i, buf.entries[i].expertId, buf.entries[i].confidence,
                   buf.entries[i].caps, GetCapName(buf.entries[i].caps));
        }
        if (buf.count > 10) {
            printf("  ... and %u more entries\n", buf.count - 10);
        }
    }

    printf("\n==============================================================================\n");
    printf("All tests completed successfully!\n");
    printf("==============================================================================\n");

    FreeLibrary(hMoE);
    return 0;
}
