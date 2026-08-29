// =============================================================================
// ProjectState.hpp — Shared parallel-agent project authority
// =============================================================================
// Cross-session coordination signal (NOT part of neural token sampling).
// Prevents agents from accidentally using the stale G:\rawrxd tree.
//
// Deep2 inference stack: ZERO third-party inference deps.
//   - No Ollama
//   - No llama.cpp linked into Deep2 / InferenceEngine
//   - No cloud inference APIs
// External llama.cpp binaries may be used ONLY as a PARITY measuring stick
// (separate process), never as a Deep2 runtime dependency.
// =============================================================================
#pragma once

#include <cstdint>
#include <mutex>
#include <string>

namespace RawrXD::Agents {

enum class CertPhase {
    StreamerCertified,
    ParityNext,
    LifecycleOpen,
    AutonomousE2EBlockedOnParity
};

inline const char* certPhaseName(CertPhase p) {
    switch (p) {
    case CertPhase::StreamerCertified: return "STREAMER-CERT-001=CERTIFIED";
    case CertPhase::ParityNext: return "PARITY-CERT-001=NEXT";
    case CertPhase::LifecycleOpen: return "LIFECYCLE-CERT-001=OPEN";
    case CertPhase::AutonomousE2EBlockedOnParity: return "AUTONOMOUS-E2E-001=BLOCKED_ON_PARITY";
    }
    return "UNKNOWN";
}

struct ProjectState {
    // Directory authority
    std::string canonicalRepo = R"(F:\~dev\rawrxd)";
    std::string staleReferenceRepo = R"(G:\rawrxd)";
    std::string modelPath = R"(F:\~dev\tinyllama_fresh.gguf)";
    std::string modelSha256 =
        "DA3087FB14AEDE55FDE6EB81A0E55E886810E43509EC82ECDC7AA5D62A03B556";

    // STREAMER-CERT-001 freeze
    std::string streamerCertCommit = "ec1d98e6a402e0ece18f02187009a126deca4c13";
    std::string streamerCertTag = "streamer-cert-001";
    std::string streamerCertExe =
        R"(F:\~dev\rawrxd\build-ninja\bin\deep2_streamer_cert.exe)";
    std::string streamerCertExeSha256 =
        "FDF79A0DCCFA152B5FA2D4097FA3419AD9F5FE75E603C0B4486BB481889960EB";
    std::string streamerEvidenceDir =
        R"(F:\~dev\rawrxd\evidence\STREAMER_CERT_001)";

    // External measuring stick ONLY (never a Deep2 link dependency)
    std::string llamaRefDir = R"(F:\~dev\llama-direct\vulkan)";
    std::string deep2InferenceDeps = "NONE"; // no ollama / no llama.cpp / no cloud

    CertPhase phase = CertPhase::ParityNext;
    uint64_t ownerSession = 0;
    uint64_t ownerAgent = 0;

    static ProjectState& instance() {
        static ProjectState s;
        return s;
    }

    bool isCanonicalPath(const std::string& path) const {
        // Reject stale G:\rawrxd for certification / agent work roots.
        if (path.size() >= 8) {
            std::string lower = path;
            for (char& c : lower) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                if (c == '/') c = '\\';
            }
            if (lower.rfind("g:\\rawrxd", 0) == 0) return false;
        }
        return true;
    }

    std::string summary() const {
        return std::string("canonical_repo=") + canonicalRepo +
               "\nstale_reference=" + staleReferenceRepo +
               "\nmodel=" + modelPath +
               "\nmodel_sha256=" + modelSha256 +
               "\nstreamer_commit=" + streamerCertCommit +
               "\nstreamer_tag=" + streamerCertTag +
               "\nstreamer_exe_sha256=" + streamerCertExeSha256 +
               "\ndeep2_inference_deps=" + deep2InferenceDeps +
               "\nllama_ref_measuring_stick_only=" + llamaRefDir +
               "\nphase=" + certPhaseName(phase) +
               "\n" + certPhaseName(CertPhase::StreamerCertified) +
               "\n" + certPhaseName(CertPhase::ParityNext) +
               "\n" + certPhaseName(CertPhase::LifecycleOpen) +
               "\n" + certPhaseName(CertPhase::AutonomousE2EBlockedOnParity) +
               "\nowner_session=" + std::to_string(ownerSession) +
               "\nowner_agent=" + std::to_string(ownerAgent) + "\n";
    }
};

} // namespace RawrXD::Agents
