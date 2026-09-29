// ============================================================================
// enterprise_license_manifest.cpp — W3/BatchD
// ============================================================================
// Sole production definition of RawrXD::License::g_FeatureManifest for the
// Win32IDE link. The header contract (include/enterprise_license.h):
//
//     extern FeatureDefV2 g_FeatureManifest[TOTAL_FEATURES];
//     struct FeatureDefV2 { char name[64]; LicenseTierV2 minTier;
//                           bool implemented; bool wiredToUI; bool tested; };
//
// requires a NON-CONST array of the 5-member struct; a const definition
// mangles to a different symbol and never resolves the reference from
// enterprise_licensev2_impl.obj.
//
// Data provenance: the authoritative 65-entry feature table (flags: tier /
// implemented / wiredToUI / tested) is transcribed from the project's own
// manifest source (src/core/ide_linker_bridge.cpp, entries verified against
// include/enterprise_license.h FeatureID enum order 0..64). The id /
// description / sourceFile / phase columns of that table have no
// corresponding members in the current FeatureDefV2 struct and are dropped.
// Rows are listed in FeatureID enum order; indices >= COUNT are
// value-initialized (empty name, Community tier).
// ============================================================================

#include "../../include/enterprise_license.h"

namespace RawrXD::License {

FeatureDefV2 g_FeatureManifest[TOTAL_FEATURES] = {
    // Index 0 = FeatureID::None (consumers index by the FeatureID enum value)
    { "",                          LicenseTierV2::Community,    false, false, false },
    // ── Community (1–6) ─────────────────────────────────────────
    { "Basic GGUF Loading",        LicenseTierV2::Community,    true,  true,  true  },
    { "Q4 Quantization",           LicenseTierV2::Community,    true,  true,  true  },
    { "CPU Inference",             LicenseTierV2::Community,    true,  true,  true  },
    { "Basic Chat UI",             LicenseTierV2::Community,    true,  true,  true  },
    { "Config File Support",       LicenseTierV2::Community,    true,  true,  true  },
    { "Single Model Session",      LicenseTierV2::Community,    true,  true,  true  },
    // ── Professional (7–27) ─────────────────────────────────────
    { "Memory Hotpatching",        LicenseTierV2::Professional, true,  true,  false },
    { "Byte-Level Hotpatching",    LicenseTierV2::Professional, true,  true,  false },
    { "Server Hotpatching",        LicenseTierV2::Professional, true,  true,  false },
    { "Unified Hotpatch Manager",  LicenseTierV2::Professional, true,  true,  false },
    { "Q5/Q8/F16 Quantization",    LicenseTierV2::Professional, true,  true,  false },
    { "Multi-Model Loading",       LicenseTierV2::Professional, true,  true,  false },
    { "CUDA Backend",              LicenseTierV2::Professional, false, false, false },
    { "Advanced Settings Panel",   LicenseTierV2::Professional, true,  true,  false },
    { "Prompt Templates",          LicenseTierV2::Professional, true,  true,  false },
    { "Token Streaming",           LicenseTierV2::Professional, true,  true,  false },
    { "Inference Statistics",      LicenseTierV2::Professional, true,  true,  false },
    { "KV Cache Management",       LicenseTierV2::Professional, true,  false, false },
    { "Model Comparison",          LicenseTierV2::Professional, true,  true,  false },
    { "Batch Processing",          LicenseTierV2::Professional, true,  false, false },
    { "Custom Stop Sequences",     LicenseTierV2::Professional, true,  true,  false },
    { "Grammar-Constrained Gen",   LicenseTierV2::Professional, true,  false, false },
    { "LoRA Adapter Support",      LicenseTierV2::Professional, false, false, false },
    { "Response Caching",          LicenseTierV2::Professional, true,  false, false },
    { "Prompt Library",            LicenseTierV2::Professional, true,  true,  false },
    { "Export/Import Sessions",    LicenseTierV2::Professional, true,  true,  false },
    { "HIP Backend",               LicenseTierV2::Professional, false, false, false },
    // ── Enterprise (28–55) ──────────────────────────────────────
    { "800B Dual-Engine",          LicenseTierV2::Enterprise,   true,  true,  false },
    { "Agentic Failure Detection", LicenseTierV2::Enterprise,   true,  true,  false },
    { "Agentic Puppeteer",         LicenseTierV2::Enterprise,   true,  true,  false },
    { "Agentic Self-Correction",   LicenseTierV2::Enterprise,   true,  true,  false },
    { "Proxy Hotpatching",         LicenseTierV2::Enterprise,   true,  true,  false },
    { "Server-Side Patching",      LicenseTierV2::Enterprise,   true,  true,  false },
    { "Schematic Studio IDE",      LicenseTierV2::Enterprise,   false, false, false },
    { "Wiring Oracle Debug",       LicenseTierV2::Enterprise,   false, false, false },
    { "Flash Attention",           LicenseTierV2::Enterprise,   true,  true,  false },
    { "Speculative Decoding",      LicenseTierV2::Enterprise,   false, false, false },
    { "Model Sharding",            LicenseTierV2::Enterprise,   true,  false, false },
    { "Tensor Parallel",           LicenseTierV2::Enterprise,   false, false, false },
    { "Pipeline Parallel",         LicenseTierV2::Enterprise,   true,  false, false },
    { "Continuous Batching",       LicenseTierV2::Enterprise,   false, false, false },
    { "GPTQ Quantization",         LicenseTierV2::Enterprise,   false, false, false },
    { "AWQ Quantization",          LicenseTierV2::Enterprise,   false, false, false },
    { "Custom Quant Schemes",      LicenseTierV2::Enterprise,   false, false, false },
    { "Multi-GPU Load Balance",    LicenseTierV2::Enterprise,   true,  true,  false },
    { "Dynamic Batch Sizing",      LicenseTierV2::Enterprise,   false, false, false },
    { "Priority Queuing",          LicenseTierV2::Enterprise,   false, false, false },
    { "Rate Limiting Engine",      LicenseTierV2::Enterprise,   true,  false, false },
    { "Audit Logging",             LicenseTierV2::Enterprise,   true,  true,  false },
    { "API Key Management",        LicenseTierV2::Enterprise,   true,  true,  false },
    { "Model Signing & Verify",    LicenseTierV2::Enterprise,   true,  false, false },
    { "RBAC",                      LicenseTierV2::Enterprise,   false, false, false },
    { "Observability Dashboard",   LicenseTierV2::Enterprise,   true,  true,  false },
    { "AVX-512 Acceleration",      LicenseTierV2::Enterprise,   true,  true,  false },
    { "RawrTuner IDE",             LicenseTierV2::Enterprise,   false, false, false },
    // ── Sovereign (56–65) ───────────────────────────────────────
    { "Air-Gapped Deploy",         LicenseTierV2::Sovereign,    false, false, false },
    { "HSM Integration",           LicenseTierV2::Sovereign,    false, false, false },
    { "FIPS 140-2 Compliance",     LicenseTierV2::Sovereign,    false, false, false },
    { "Custom Security Policies",  LicenseTierV2::Sovereign,    false, false, false },
    { "Sovereign Key Management",  LicenseTierV2::Sovereign,    false, false, false },
    { "Classified Network",        LicenseTierV2::Sovereign,    false, false, false },
    { "Immutable Audit Logs",      LicenseTierV2::Sovereign,    false, false, false },
    { "Kubernetes Support",        LicenseTierV2::Sovereign,    false, false, false },
    { "Tamper Detection",          LicenseTierV2::Sovereign,    true,  false, false },
    { "Secure Boot Chain",         LicenseTierV2::Sovereign,    false, false, false },
};

} // namespace RawrXD::License