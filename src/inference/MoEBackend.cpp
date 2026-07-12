//==============================================================================
// MoEBackend.cpp - Sovereign MASM MoE Integration Implementation
//==============================================================================

#include "MoEBackend.h"
#include "MoEBackend_ABI.h"
#include "../core/ExecutionJournal.h"
#include "../core/ModelRegistry.h"
#include <cstdio>
#include <cstring>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Sovereign {
namespace Inference {

// Dynamic function pointers
static HMODULE g_hMoEDLL = nullptr;
static MoE_InitializeFn g_pfnInitialize = nullptr;
static MoE_GenerateFn g_pfnGenerate = nullptr;
static MoE_GetExpertInfoFn g_pfnGetExpertInfo = nullptr;
static MoE_GetTraceFn g_pfnGetTrace = nullptr;
static MoE_GetBackendCapsFn g_pfnGetBackendCaps = nullptr;

//==============================================================================
// DLL Loading
//==============================================================================

static bool LoadMoEDLL() {
    if (g_hMoEDLL) return true;
    
    g_hMoEDLL = LoadLibraryA("MoE.dll");
    if (!g_hMoEDLL) {
        // Try alternative paths
        g_hMoEDLL = LoadLibraryA("..\\MoE.dll");
        if (!g_hMoEDLL) {
            g_hMoEDLL = LoadLibraryA(".\\MoE.dll");
        }
    }
    
    if (!g_hMoEDLL) {
        return false;
    }
    
    // Get function pointers
    g_pfnInitialize = (MoE_InitializeFn)GetProcAddress(g_hMoEDLL, "MoE_Initialize");
    g_pfnGenerate = (MoE_GenerateFn)GetProcAddress(g_hMoEDLL, "MoE_Generate");
    g_pfnGetExpertInfo = (MoE_GetExpertInfoFn)GetProcAddress(g_hMoEDLL, "MoE_GetExpertInfo");
    g_pfnGetTrace = (MoE_GetTraceFn)GetProcAddress(g_hMoEDLL, "MoE_GetTrace");
    g_pfnGetBackendCaps = (MoE_GetBackendCapsFn)GetProcAddress(g_hMoEDLL, "MoE_GetBackendCaps");
    
    if (!g_pfnInitialize || !g_pfnGenerate) {
        FreeLibrary(g_hMoEDLL);
        g_hMoEDLL = nullptr;
        return false;
    }
    
    // Initialize the MoE
    g_pfnInitialize();
    
    return true;
}

static void UnloadMoEDLL() {
    if (g_hMoEDLL) {
        FreeLibrary(g_hMoEDLL);
        g_hMoEDLL = nullptr;
        g_pfnInitialize = nullptr;
        g_pfnGenerate = nullptr;
        g_pfnGetExpertInfo = nullptr;
        g_pfnGetTrace = nullptr;
        g_pfnGetBackendCaps = nullptr;
    }
}

namespace Sovereign {
namespace Inference {

//==============================================================================
// Constructor / Destructor
//==============================================================================

MoEBackend::MoEBackend(const ModelInfo* info) 
    : m_handle(nullptr)
    , m_traceCallback(nullptr) {
    
    // Load the MoE DLL
    if (!LoadMoEDLL()) {
        Journal_LogEvent("MOE_BACKEND_ERROR", "Failed to load MoE.dll");
        return;
    }
    
    // Store paths from ModelInfo
    if (info && info->path[0]) {
        m_modelPath = info->path;
    }
    
    // Log initialization
    MoEBackendCaps caps = {0};
    if (g_pfnGetBackendCaps) {
        g_pfnGetBackendCaps(&caps);
    }
    
    char desc[256];
    snprintf(desc, sizeof(desc), "MoE backend initialized: %s (v%d, %d experts)", 
             info->name, caps.version, caps.maxExperts);
    Journal_LogEvent("MOE_BACKEND_INIT", desc);
}

MoEBackend::~MoEBackend() {
    if (m_handle) {
        MoE_Shutdown(m_handle);
        m_handle = nullptr;
    }
}

//==============================================================================
// Standard InferenceBackend Interface
//==============================================================================

int MoEBackend::Generate(const InferenceRequest* req, InferenceResponse* res) {
    if (!g_pfnGenerate || !req || !res) {
        return -1;
    }
    
    // Clear last trace
    m_lastTrace.clear();
    
    // Build MoE input
    MoEGenerateInput moe_in = {0};
    // For now, use stub pointers - in real implementation, these would point to actual data
    static float stub_logits[1] = {500.0f};  // Neutral confidence
    static int stub_kv[1] = {500};          // Medium KV density
    moe_in.logits = stub_logits;
    moe_in.kv = stub_kv;
    moe_in.token = req->prompt[0] ? req->prompt[0] : 'A';
    
    // Call MASM MoE
    MoEGenerateOutput moe_out = {0};
    g_pfnGenerate(&moe_in, &moe_out);
    
    // Convert result
    res->success = 1;
    res->tokens_generated = 1;  // Stub
    
    // Get trace
    if (g_pfnGetTrace) {
        MoETraceBuffer trace_buf = {0};
        g_pfnGetTrace(&trace_buf);
        
        // Convert trace entries
        for (uint32_t i = 0; i < trace_buf.count && i < MOE_TRACE_MAX_ENTRIES; i++) {
            MoEActivation act = {0};
            act.expert_id = trace_buf.entries[i].expertId;
            act.confidence = (float)trace_buf.entries[i].confidence;
            act.capabilities = trace_buf.entries[i].caps;
            
            // Get expert name from ID
            MoEExpertInfo info = {0};
            if (g_pfnGetExpertInfo) {
                g_pfnGetExpertInfo(act.expert_id, &info);
            }
            
            // Map capability bits to semantic name
            static const char* cap_names[] = {
                "core", "ghost", "latent", "shadow", 
                "swarm", "prefetch", "echo", "merge", "speculative"
            };
            
            // Build expert name from capabilities
            char name_buf[64];
            if (act.capabilities & MOE_CAP_GHOST) {
                snprintf(name_buf, sizeof(name_buf), "ghost_text_%d", act.expert_id);
            } else if (act.capabilities & MOE_CAP_LATENT) {
                snprintf(name_buf, sizeof(name_buf), "latent_expert_%d", act.expert_id);
            } else if (act.capabilities & MOE_CAP_SHADOW) {
                snprintf(name_buf, sizeof(name_buf), "shadow_fallback_%d", act.expert_id);
            } else if (act.capabilities & MOE_CAP_SWARM) {
                snprintf(name_buf, sizeof(name_buf), "swarm_coordinator_%d", act.expert_id);
            } else {
                snprintf(name_buf, sizeof(name_buf), "core_reasoning_%d", act.expert_id);
            }
            
            // Store in last trace
            m_lastTrace.push_back(act);
            LogExpertActivation(&act);
        }
    }
    
    return 0;
}

int MoEBackend::GetCapabilities(unsigned int* caps) {
    if (!caps) return -1;
    
    // MoE supports all these capabilities
    *caps = CAP_MOE | CAP_SWARM | CAP_GHOST | CAP_LATENT | 
            CAP_SHADOW | CAP_SPECULATIVE | CAP_ECHO | CAP_MERGE;
    return 0;
}

//==============================================================================
// MoE-Specific Extensions
//==============================================================================

int MoEBackend::GenerateWithExpert(const InferenceRequest* req, 
                                    const char* expert_tag,
                                    InferenceResponse* res) {
    if (!m_handle || !req || !res) {
        return -1;
    }
    
    m_lastTrace.clear();
    
    MoEResult moe_res = {0};
    int result = MoE_Generate(m_handle,
                              req->prompt,
                              req->max_tokens,
                              expert_tag,  // Specific expert tag
                              &moe_res);
    
    if (result != 0 || !moe_res.success) {
        char error[256];
        snprintf(error, sizeof(error), "MoE generation failed for expert: %s", expert_tag);
        res->error_message = error;
        res->success = 0;
        return -1;
    }
    
    ConvertResult(&moe_res, res);
    
    // Log targeted expert generation
    char desc[256];
    snprintf(desc, sizeof(desc), "Targeted expert: %s", expert_tag);
    Journal_LogEvent("MOE_TARGETED_EXPERT", desc);
    
    if (moe_res.expert_trace && moe_res.trace_count > 0) {
        m_lastTrace.reserve(moe_res.trace_count);
        for (int i = 0; i < moe_res.trace_count; i++) {
            m_lastTrace.push_back(moe_res.expert_trace[i]);
            LogExpertActivation(&moe_res.expert_trace[i]);
        }
    }
    
    MoE_FreeResult(&moe_res);
    return 0;
}

int MoEBackend::GenerateWithSwarm(const InferenceRequest* req,
                                   const char** expert_tags,
                                   int expert_count,
                                   InferenceResponse* res) {
    if (!m_handle || !req || !res || !expert_tags || expert_count <= 0) {
        return -1;
    }
    
    // For now, we call the first expert as primary
    // The MASM MoE handles swarm coordination internally
    // Future: extend MoE_Generate to accept expert array
    
    return GenerateWithExpert(req, expert_tags[0], res);
}

int MoEBackend::GetExpertList(std::vector<MoEActivation>* experts) {
    if (!m_handle || !experts) {
        return -1;
    }
    
    int count = MoE_GetExpertCount(m_handle);
    if (count <= 0) {
        return -1;
    }
    
    experts->clear();
    experts->reserve(count);
    
    for (int i = 0; i < count; i++) {
        MoEActivation info = {0};
        if (MoE_GetExpertInfo(m_handle, i, &info) == 0) {
            experts->push_back(info);
        }
    }
    
    return 0;
}

int MoEBackend::FindExpertByName(const char* name, MoEActivation* info) {
    if (!m_handle || !name || !info) {
        return -1;
    }
    
    int count = MoE_GetExpertCount(m_handle);
    for (int i = 0; i < count; i++) {
        MoEActivation candidate = {0};
        if (MoE_GetExpertInfo(m_handle, i, &candidate) == 0) {
            if (candidate.expert_name && 
                strcmp(candidate.expert_name, name) == 0) {
                *info = candidate;
                return 0;
            }
        }
    }
    
    return -1;  // Not found
}

int MoEBackend::FindExpertsByCapability(unsigned int cap_mask, 
                                          std::vector<MoEActivation>* experts) {
    if (!m_handle || !experts) {
        return -1;
    }
    
    experts->clear();
    
    int count = MoE_GetExpertCount(m_handle);
    for (int i = 0; i < count; i++) {
        MoEActivation info = {0};
        if (MoE_GetExpertInfo(m_handle, i, &info) == 0) {
            if (info.capabilities & cap_mask) {
                experts->push_back(info);
            }
        }
    }
    
    return 0;
}

void MoEBackend::SetTraceCallback(std::function<void(const MoEActivation&)> callback) {
    m_traceCallback = callback;
}

int MoEBackend::GetLastTrace(std::vector<MoEActivation>* trace) {
    if (!trace) {
        return -1;
    }
    
    *trace = m_lastTrace;
    return 0;
}

int MoEBackend::GetActivationHeatMap(std::vector<std::pair<int, int>>* heat_map) {
    if (!heat_map) {
        return -1;
    }
    
    // Aggregate from last trace
    // In production, this would query the MASM side for cumulative stats
    heat_map->clear();
    
    // Count activations per expert
    std::vector<int> counts(64, 0);  // Assume max 64 experts
    for (const auto& act : m_lastTrace) {
        if (act.expert_id >= 0 && act.expert_id < 64) {
            counts[act.expert_id]++;
        }
    }
    
    // Convert to heat map
    for (int i = 0; i < 64; i++) {
        if (counts[i] > 0) {
            heat_map->push_back({i, counts[i]});
        }
    }
    
    // Sort by count descending
    std::sort(heat_map->begin(), heat_map->end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    return 0;
}

void MoEBackend::ResetStatistics() {
    m_lastTrace.clear();
    // Future: call into MASM to reset cumulative stats
}

//==============================================================================
// Internal Helpers
//==============================================================================

void MoEBackend::TraceCallbackWrapper(const MoEActivation* activation, void* user_data) {
    if (!activation || !user_data) {
        return;
    }
    
    MoEBackend* self = static_cast<MoEBackend*>(user_data);
    
    // Call C++ callback if set
    if (self->m_traceCallback) {
        self->m_traceCallback(*activation);
    }
    
    // Log to journal
    self->LogExpertActivation(activation);
}

void MoEBackend::ConvertResult(const MoEResult* moe_res, InferenceResponse* inf_res) {
    if (!moe_res || !inf_res) {
        return;
    }
    
    inf_res->success = moe_res->success;
    inf_res->tokens_generated = moe_res->tokens_generated;
    inf_res->duration_us = moe_res->duration_us;
    
    if (moe_res->generated_text && moe_res->text_length > 0) {
        // Copy text (truncate if needed)
        size_t copy_len = moe_res->text_length;
        if (copy_len >= sizeof(inf_res->text)) {
            copy_len = sizeof(inf_res->text) - 1;
        }
        memcpy(inf_res->text, moe_res->generated_text, copy_len);
        inf_res->text[copy_len] = '\0';
    }
}

void MoEBackend::LogExpertActivation(const MoEActivation* activation) {
    if (!activation) {
        return;
    }
    
    char desc[512];
    snprintf(desc, sizeof(desc), 
             "expert=%s id=%d confidence=%.1f caps=0x%X",
             activation->expert_name ? activation->expert_name : "unknown",
             activation->expert_id,
             activation->confidence,
             activation->capabilities);
    
    Journal_LogEvent("MOE_EXPERT_ACTIVATION", desc);
}

} // namespace Inference
} // namespace Sovereign
