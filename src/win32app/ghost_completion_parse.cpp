// ghost_completion_parse.cpp - Real implementation for Win32IDE build
// Parses inline completion suggestions from model responses for ghost text.
// Now with AVX2/AVX-512 MASM fast-path via GhostParser_ScanVectorized.asm

#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>

// ============================================================================
// MASM Fast-Path Forward Declarations
// ============================================================================
extern "C" {
    // AVX2 broadside scanner — processes 16 wchar_t units per iteration
    size_t GhostParser_ScanVectorized(
        const wchar_t* buffer,
        size_t bufferLen,
        void* outPayloads,
        size_t maxPayloads);

    // AVX-512 version — processes 32 wchar_t units per iteration
    size_t GhostParser_ScanVectorized_AVX512(
        const wchar_t* buffer,
        size_t bufferLen,
        void* outPayloads,
        size_t maxPayloads);
}

// ============================================================================
// Payload structure (must match MASM layout exactly)
// ============================================================================
#pragma pack(push, 1)
struct GhostCompletionPayload {
    const wchar_t* text;    // Pointer into source buffer (no copy)
    int startPos;           // Start position in wchar_t units
    int endPos;             // End position in wchar_t units
    float confidence;       // 0.85f for [[COMPLETION:]], 0.90f for ``` blocks
};
#pragma pack(pop)

struct GhostCompletion {
    std::wstring text;
    int startPos;
    int endPos;
    float confidence;
};

class GhostCompletionParser {
public:
    GhostCompletionParser() : m_initialized(false) {}
    
    std::vector<GhostCompletion> Parse(const std::wstring& input) {
        std::vector<GhostCompletion> results;
        if (!m_initialized || input.empty()) return results;
        
        const size_t len = input.length();
        if (len >= 32) {
            // Try MASM fast-path first for buffers >= 32 wchar_t units
            alignas(32) GhostCompletionPayload payloads[64];
            size_t found = 0;
            
            // Attempt AVX-512 if buffer is large enough (64+ wchar_t units)
            if (len >= 64) {
                found = GhostParser_ScanVectorized_AVX512(
                    input.c_str(), len, payloads, 64);
            }
            
            // Fall back to AVX2 if AVX-512 returned nothing or wasn't suitable
            if (found == 0) {
                found = GhostParser_ScanVectorized(
                    input.c_str(), len, payloads, 64);
            }
            
            // Convert MASM payloads to C++ results
            for (size_t i = 0; i < found; ++i) {
                const auto& p = payloads[i];
                if (p.text && p.startPos >= 0 && p.endPos > p.startPos) {
                    GhostCompletion gc;
                    gc.text = std::wstring(p.text, (p.endPos - p.startPos - 15) / 2);
                    gc.startPos = p.startPos;
                    gc.endPos = p.endPos;
                    gc.confidence = p.confidence;
                    results.push_back(std::move(gc));
                }
            }
            
            if (!results.empty()) {
                std::sort(results.begin(), results.end(),
                    [](const GhostCompletion& a, const GhostCompletion& b) {
                        return a.confidence > b.confidence;
                    });
                return results;
            }
        }
        
        // Scalar fallback for small buffers or if MASM fast-path found nothing
        // Parse completion markers: [[COMPLETION:text]] or ```code``` blocks
        const wchar_t* p = input.c_str();
        const wchar_t* end = p + input.length();
        
        while (p < end) {
            const wchar_t* marker = wcsstr(p, L"[[COMPLETION:");
            if (!marker) break;
            
            const wchar_t* contentStart = marker + 13;
            const wchar_t* contentEnd = wcsstr(contentStart, L"]]");
            if (!contentEnd) break;
            
            std::wstring completionText(contentStart, contentEnd - contentStart);
            int prefixLen = static_cast<int>(marker - input.c_str());
            
            GhostCompletion gc;
            gc.text = completionText;
            gc.startPos = prefixLen;
            gc.endPos = prefixLen + static_cast<int>(completionText.length());
            gc.confidence = 0.85f;
            results.push_back(std::move(gc));
            p = contentEnd + 2;
        }
        
        p = input.c_str();
        while (p < end) {
            const wchar_t* codeBlock = wcsstr(p, L"```");
            if (!codeBlock) break;
            
            const wchar_t* langEnd = codeBlock + 3;
            while (langEnd < end && *langEnd != L'\n') ++langEnd;
            
            const wchar_t* blockEnd = wcsstr(langEnd, L"```");
            if (!blockEnd) break;
            
            std::wstring code(langEnd + 1, blockEnd - langEnd - 1);
            if (!code.empty()) {
                int startPos = static_cast<int>(codeBlock - input.c_str());
                GhostCompletion gc;
                gc.text = code;
                gc.startPos = startPos;
                gc.endPos = startPos + static_cast<int>(code.length());
                gc.confidence = 0.90f;
                results.push_back(std::move(gc));
            }
            p = blockEnd + 3;
        }
        
        std::sort(results.begin(), results.end(),
            [](const GhostCompletion& a, const GhostCompletion& b) {
                return a.confidence > b.confidence;
            });
        
        return results;
    }
    
    bool Initialize() {
        m_initialized = true;
        return true;
    }
    
    void Shutdown() {
        m_initialized = false;
    }
    
private:
    bool m_initialized;
};

extern "C" {
    __declspec(dllexport) void* GhostParser_Create() {
        GhostCompletionParser* parser = new GhostCompletionParser();
        parser->Initialize();
        return parser;
    }
    
    __declspec(dllexport) void GhostParser_Destroy(void* parser) {
        if (parser) {
            static_cast<GhostCompletionParser*>(parser)->Shutdown();
            delete static_cast<GhostCompletionParser*>(parser);
        }
    }
    
    __declspec(dllexport) int GhostParser_Parse(void* parser, const wchar_t* input, wchar_t* output, int outputLen) {
        if (!parser || !input || !output || outputLen <= 0) return 0;
        
        std::wstring winput(input);
        auto results = static_cast<GhostCompletionParser*>(parser)->Parse(winput);
        
        if (results.empty()) return 0;
        
        const auto& best = results[0];
        int len = static_cast<int>(best.text.length());
        if (len >= outputLen) len = outputLen - 1;
        
        wmemcpy(output, best.text.c_str(), len);
        output[len] = L'\0';
        
        return len;
    }
    
    __declspec(dllexport) int GhostParser_GetCompletionCount(void* parser, const wchar_t* input) {
        if (!parser || !input) return 0;
        auto results = static_cast<GhostCompletionParser*>(parser)->Parse(input);
        return static_cast<int>(results.size());
    }
    
    __declspec(dllexport) float GhostParser_GetConfidence(void* parser, const wchar_t* input, int index) {
        if (!parser || !input || index < 0) return 0.0f;
        auto results = static_cast<GhostCompletionParser*>(parser)->Parse(input);
        if (index >= static_cast<int>(results.size())) return 0.0f;
        return results[index].confidence;
    }
}
