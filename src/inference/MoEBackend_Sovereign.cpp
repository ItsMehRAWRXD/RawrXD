//==============================================================================
// MoEBackend_Sovereign.cpp - Sovereign MoE Backend Glue Layer
// Minimal, dependency-free C++ glue that loads MASM DLL
// No STL, no CRT, no exceptions, no RTTI, no templates
//==============================================================================

#include "MoEBackend_Sovereign.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace Sovereign {
namespace Inference {

//==============================================================================
// Function Pointer Types (C ABI from MASM DLL)
//==============================================================================

typedef void (*FnInit)(void);
typedef void (*FnGenerate)(const MoEGenerateInput*, MoEGenerateOutput*);
typedef void (*FnGetExpertInfo)(unsigned int, MoEExpertInfo*);
typedef void (*FnGetTrace)(MoETraceBuffer*);
typedef void (*FnGetCaps)(MoEBackendCaps*);

//==============================================================================
// Static State
//==============================================================================

static HMODULE      g_hMoE = nullptr;
static FnInit       g_pfnInit = nullptr;
static FnGenerate   g_pfnGenerate = nullptr;
static FnGetExpertInfo g_pfnGetExpertInfo = nullptr;
static FnGetTrace   g_pfnGetTrace = nullptr;
static FnGetCaps    g_pfnGetCaps = nullptr;

static bool         g_bLoaded = false;
static bool         g_bInitialized = false;

//==============================================================================
// Backend Loader
//==============================================================================

bool MoEBackend_Load(const char* path)
{
    if (g_bLoaded) return true;
    if (!path) return false;

    g_hMoE = LoadLibraryA(path);
    if (!g_hMoE) {
        // Try common paths
        g_hMoE = LoadLibraryA("MoE.dll");
        if (!g_hMoE) {
            g_hMoE = LoadLibraryA(".\\MoE.dll");
        }
        if (!g_hMoE) {
            g_hMoE = LoadLibraryA("..\\MoE.dll");
        }
    }

    if (!g_hMoE) return false;

    // Get function pointers
    g_pfnInit = (FnInit)GetProcAddress(g_hMoE, "MoE_Initialize");
    g_pfnGenerate = (FnGenerate)GetProcAddress(g_hMoE, "MoE_Generate");
    g_pfnGetExpertInfo = (FnGetExpertInfo)GetProcAddress(g_hMoE, "MoE_GetExpertInfo");
    g_pfnGetTrace = (FnGetTrace)GetProcAddress(g_hMoE, "MoE_GetTrace");
    g_pfnGetCaps = (FnGetCaps)GetProcAddress(g_hMoE, "MoE_GetBackendCaps");

    // Validate required exports
    if (!g_pfnInit || !g_pfnGenerate) {
        FreeLibrary(g_hMoE);
        g_hMoE = nullptr;
        return false;
    }

    g_bLoaded = true;
    return true;
}

void MoEBackend_Unload()
{
    if (g_hMoE) {
        FreeLibrary(g_hMoE);
        g_hMoE = nullptr;
    }
    g_pfnInit = nullptr;
    g_pfnGenerate = nullptr;
    g_pfnGetExpertInfo = nullptr;
    g_pfnGetTrace = nullptr;
    g_pfnGetCaps = nullptr;
    g_bLoaded = false;
    g_bInitialized = false;
}

bool MoEBackend_IsLoaded()
{
    return g_bLoaded;
}

//==============================================================================
// Backend Interface
//==============================================================================

void MoEBackend_Initialize()
{
    if (!g_bLoaded || g_bInitialized) return;
    if (g_pfnInit) {
        g_pfnInit();
        g_bInitialized = true;
    }
}

void MoEBackend_Generate(const MoEGenerateInput* in, MoEGenerateOutput* out)
{
    if (!g_bLoaded || !g_pfnGenerate || !in || !out) return;
    g_pfnGenerate(in, out);
}

void MoEBackend_GetExpertInfo(unsigned int id, MoEExpertInfo* info)
{
    if (!g_bLoaded || !g_pfnGetExpertInfo || !info) return;
    g_pfnGetExpertInfo(id, info);
}

void MoEBackend_GetTrace(MoETraceBuffer* buf)
{
    if (!g_bLoaded || !g_pfnGetTrace || !buf) return;
    g_pfnGetTrace(buf);
}

void MoEBackend_GetCaps(MoEBackendCaps* caps)
{
    if (!g_bLoaded || !g_pfnGetCaps || !caps) return;
    g_pfnGetCaps(caps);
}

//==============================================================================
// Expert Enumeration
//==============================================================================

unsigned int MoEBackend_GetExpertCount()
{
    MoEBackendCaps caps = {0};
    MoEBackend_GetCaps(&caps);
    return caps.maxExperts;
}

const char* MoEBackend_GetExpertName(unsigned int id, char* buf, size_t bufSize)
{
    if (!buf || bufSize == 0) return nullptr;

    MoEExpertInfo info = {0};
    MoEBackend_GetExpertInfo(id, &info);

    if (info.id == 0xFFFFFFFF) {
        // Invalid expert
        return nullptr;
    }

    // Map capability bits to semantic name
    const char* baseName = "core";
    if (info.caps & MOE_CAP_GHOST) baseName = "ghost";
    else if (info.caps & MOE_CAP_LATENT) baseName = "latent";
    else if (info.caps & MOE_CAP_SHADOW) baseName = "shadow";
    else if (info.caps & MOE_CAP_SWARM) baseName = "swarm";
    else if (info.caps & MOE_CAP_PREFETCH) baseName = "prefetch";
    else if (info.caps & MOE_CAP_ECHO) baseName = "echo";
    else if (info.caps & MOE_CAP_MERGE) baseName = "merge";
    else if (info.caps & MOE_CAP_SPECULATIVE) baseName = "speculative";

    // Format: baseName_id
    #ifdef _WIN32
    wsprintfA(buf, "%s_%u", baseName, id);
    #else
    // Fallback for non-Windows
    char temp[32];
    const char* digits = "0123456789";
    unsigned int n = id;
    int i = 0;
    do {
        temp[i++] = digits[n % 10];
        n /= 10;
    } while (n > 0);
    
    // Copy baseName
    size_t j = 0;
    while (baseName[j] && j < bufSize - 1) {
        buf[j] = baseName[j];
        j++;
    }
    
    // Add underscore
    if (j < bufSize - 1) {
        buf[j++] = '_';
    }
    
    // Copy digits in reverse
    while (i > 0 && j < bufSize - 1) {
        buf[j++] = temp[--i];
    }
    buf[j] = '\0';
    #endif

    return buf;
}

//==============================================================================
// Trace Access
//==============================================================================

unsigned int MoEBackend_GetTraceCount()
{
    MoETraceBuffer buf = {0};
    MoEBackend_GetTrace(&buf);
    return buf.count;
}

bool MoEBackend_GetTraceEntry(unsigned int index, MoETraceEntry* entry)
{
    if (!entry) return false;

    MoETraceBuffer buf = {0};
    MoEBackend_GetTrace(&buf);

    if (index >= buf.count) return false;

    *entry = buf.entries[index];
    return true;
}

} // namespace Inference
} // namespace Sovereign
