// G01-04 private-link closure stubs (PROMOTE=0). Mangling-only types.
// Do NOT define RunDecodeStream here — ProductRunDecode owns it (LNK4006).
#include <string>

class Win32IDE {
public:
    void setOllamaModelOverride(const std::string& model);
};

void Win32IDE::setOllamaModelOverride(const std::string& /*model*/) {}
