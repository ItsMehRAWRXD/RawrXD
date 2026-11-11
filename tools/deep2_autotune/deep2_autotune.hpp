#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace deep2::tune {
struct Hardware {
  uint32_t logical_cpus = 0;
  uint64_t ram_bytes = 0;
  std::vector<std::string> display_adapters;
  std::string fingerprint;
};
struct Config {
  uint32_t threads = 1;
  uint32_t batch = 1;
  uint32_t gpu_layers = 0;
  uint32_t context = 4096;
  uint32_t kv_bits = 16;
};
struct Result {
  bool valid = false;
  bool parity_ok = false;
  bool stable = false;
  uint64_t peak_bytes = 0;
  uint64_t generated_tokens = 0;
  double elapsed_seconds = 0;
  double prefill_tps = 0;
  std::string error;
  double decode_tps() const { return elapsed_seconds > 0 ? double(generated_tokens)/elapsed_seconds : 0; }
};
struct Runtime {
  virtual ~Runtime() = default;
  virtual std::string model_fingerprint() const = 0; // must include content hash, architecture and quantization
  virtual std::string implementation_fingerprint() const = 0; // kernel/runtime version
  virtual bool supports(const Config&, std::string& why_not) = 0;
  virtual Result benchmark(const Config&, uint32_t repetition) = 0; // actual model inference + independent parity check
  virtual bool activate(const Config&, std::string& error) = 0;
};
struct Decision {
  Config config;
  Result result;
  bool reused = false;
};
Hardware discover_hardware();
std::optional<Decision> autotune(Runtime&, const Hardware&, const std::string& profile_path,
                                  uint64_t memory_budget_bytes, bool force,
                                  std::string& diagnostic);
}
