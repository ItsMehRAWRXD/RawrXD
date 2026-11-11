// Link stub for deep2_agentic_loop when ggml-vulkan is not in the tip_ext tree.
#include <cstddef>
struct ggml_backend;
typedef ggml_backend* ggml_backend_t;
extern "C" {
int ggml_backend_vk_get_device_count(void) { return 0; }
ggml_backend_t ggml_backend_vk_init(size_t /*dev_num*/) { return nullptr; }
}
