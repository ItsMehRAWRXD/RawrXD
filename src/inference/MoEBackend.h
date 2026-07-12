//==============================================================================
// MoEBackend.h - Sovereign MASM MoE Integration
//
// Bridges your pure x64 MASM MoE system into the Sovereign Runtime.
// Enables SEG workflows to target specific experts by semantic tag:
//   - "ghost_text" for speculative generation
//   - "latent_math" for mathematical reasoning
//   - "shadow_fallback" for low-confidence recovery
//   - "swarm" for parallel expert activation
//
// This backend exposes your MASM MoE as a standard InferenceBackend,
// allowing full integration with ModelRegistry, SEG, and the GUI.
//==============================================================================

#ifndef MOE_BACKEND_H
#define MOE_BACKEND_H

#include "InferenceBackend.h"
#include "../../src/core/ModelRegistry.h"
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// MASM MoE Interface (C-compatible)
//==============================================================================

// Opaque handle to MASM MoE instance
typedef void* MoEHandle;

// Expert activation record from MASM side
typedef struct MoEActivation {
    int expert_id;
    const char* expert_name;      // Semantic name (e.g., "ghost_text_0")
    float confidence;
    unsigned int capabilities;    // Bitmask of CAP_* flags
    uint64_t timestamp;
    const char* context;          // Additional context (trigger, reason, etc.)
} MoEActivation;

// MoE generation result
typedef struct MoEResult {
    const char* generated_text;
    size_t text_length;
    int tokens_generated;
    MoEActivation* expert_trace;  // Array of expert activations
    int trace_count;
    uint64_t duration_us;
    int success;
} MoEResult;

// MASM-exported functions (implemented in your MoE DLL)
extern MoEHandle MoE_Initialize(const char* model_path, const char* config_path);
extern void MoE_Shutdown(MoEHandle handle);
extern int MoE_Generate(MoEHandle handle, 
                        const char* prompt,
                        int max_tokens,
                        const char* expert_tag,  // NULL for auto, or "ghost_text", etc.
                        MoEResult* result);
extern int MoE_GetExpertCount(MoEHandle handle);
extern int MoE_GetExpertInfo(MoEHandle handle, int expert_id, MoEActivation* info);
extern void MoE_FreeResult(MoEResult* result);

// Trace callback for real-time expert monitoring
typedef void (*MoETraceCallback)(const MoEActivation* activation, void* user_data);
extern void MoE_SetTraceCallback(MoEHandle handle, MoETraceCallback callback, void* user_data);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

//==============================================================================
// C++ MoEBackend Class
//==============================================================================

#include <string>
#include <vector>
#include <functional>

namespace Sovereign {
namespace Inference {

class MoEBackend : public InferenceBackend {
public:
    // Constructor loads the MASM MoE DLL and initializes it
    MoEBackend(const ModelInfo* info);
    virtual ~MoEBackend();

    // Standard InferenceBackend interface
    virtual int Generate(const InferenceRequest* req, InferenceResponse* res) override;
    virtual int GetCapabilities(unsigned int* caps) override;
    virtual const char* GetBackendName() override { return "MoE_Sovereign"; }

    // MoE-specific extensions
    
    // Generate with specific expert tag (e.g., "ghost_text", "latent_math")
    int GenerateWithExpert(const InferenceRequest* req, 
                           const char* expert_tag,
                           InferenceResponse* res);
    
    // Generate with swarm mode (activate multiple experts)
    int GenerateWithSwarm(const InferenceRequest* req,
                          const char** expert_tags,
                          int expert_count,
                          InferenceResponse* res);
    
    // Get list of available experts
    int GetExpertList(std::vector<MoEActivation>* experts);
    
    // Get expert by semantic name
    int FindExpertByName(const char* name, MoEActivation* info);
    
    // Get experts by capability
    int FindExpertsByCapability(unsigned int cap_mask, std::vector<MoEActivation>* experts);
    
    // Set trace callback for real-time monitoring
    void SetTraceCallback(std::function<void(const MoEActivation&)> callback);
    
    // Get last generation's expert trace
    int GetLastTrace(std::vector<MoEActivation>* trace);
    
    // Statistics
    int GetActivationHeatMap(std::vector<std::pair<int, int>>* heat_map);  // (expert_id, count)
    void ResetStatistics();

private:
    MoEHandle m_handle;
    std::string m_modelPath;
    std::string m_configPath;
    std::vector<MoEActivation> m_lastTrace;
    std::function<void(const MoEActivation&)> m_traceCallback;
    
    // Internal trace callback wrapper
    static void TraceCallbackWrapper(const MoEActivation* activation, void* user_data);
    
    // Convert MoEResult to InferenceResponse
    void ConvertResult(const MoEResult* moe_res, InferenceResponse* inf_res);
    
    // Log to ExecutionJournal
    void LogExpertActivation(const MoEActivation* activation);
};

} // namespace Inference
} // namespace Sovereign

#endif // __cplusplus

#endif // MOE_BACKEND_H
