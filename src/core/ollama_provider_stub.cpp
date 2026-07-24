// ============================================================================
// ollama_provider_stub.cpp - Stub implementation for OllamaProvider
// ============================================================================

#include <string>
#include <windows.h>

namespace RawrXD {
namespace Prediction {

class OllamaProvider {
public:
    OllamaProvider(const std::string& url) {
        (void)url;
        OutputDebugStringA("[OllamaProvider] Constructor stub called\n");
    }
};

} // namespace Prediction
} // namespace RawrXD
