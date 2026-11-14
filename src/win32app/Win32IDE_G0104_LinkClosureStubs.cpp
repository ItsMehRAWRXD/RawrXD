// G01-04 private-link closure stubs (PROMOTE=0). Mangling-only types.
#include <functional>
#include <string>
#include <cstdint>

class Win32IDE {
public:
    void setOllamaModelOverride(const std::string& model);
};

void Win32IDE::setOllamaModelOverride(const std::string& /*model*/) {}

namespace rawr {
namespace product_run {

struct ProductRuntime {};
struct Result {};

void RunDecodeStream(ProductRuntime& /*rt*/,
                     const char* /*prompt*/,
                     uint32_t /*maxTokens*/,
                     const std::function<bool(const std::string&)>& /*onPiece*/,
                     Result& /*r*/,
                     int& /*out*/) {}

}  // namespace product_run
}  // namespace rawr
