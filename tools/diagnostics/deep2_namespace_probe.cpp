// Diagnostic probe for namespace contamination
// Compile each include incrementally to find the first that causes
// std::filesystem to appear under Deep2::std

// Test 1: ReverseIntegration.hpp
#include "ReverseIntegration.hpp"
#include <filesystem>

namespace probe_reverse {
    namespace fs = ::std::filesystem;
}

// Test 2: mars/MARSController.hpp
#include "mars/MARSController.hpp"
#include <filesystem>

namespace probe_mars {
    namespace fs = ::std::filesystem;
}

// Test 3: ThreadPool.h
#include "ThreadPool.h"
#include <filesystem>

namespace probe_threadpool {
    namespace fs = ::std::filesystem;
}

// Test 4: KVCache.h
#include "KVCache.h"
#include <filesystem>

namespace probe_kvcache {
    namespace fs = ::std::filesystem;
}

// Test 5: GGUFLoader.hpp
#include "GGUFLoader.hpp"
#include <filesystem>

namespace probe_gguf {
    namespace fs = ::std::filesystem;
}

// Test 6: BP16Streamer.hpp
#include "BP16Streamer.hpp"
#include <filesystem>

namespace probe_bp16 {
    namespace fs = ::std::filesystem;
}

// Test 7: Tokenizer.hpp
#include "Tokenizer.hpp"
#include <filesystem>

namespace probe_tokenizer {
    namespace fs = ::std::filesystem;
}

// Test 8: ../sampling/advanced_sampler.hpp
#include "../sampling/advanced_sampler.hpp"
#include <filesystem>

namespace probe_sampler {
    namespace fs = ::std::filesystem;
}

// Test 9: MoERouter.hpp
#include "MoERouter.hpp"
#include <filesystem>

namespace probe_moerouter {
    namespace fs = ::std::filesystem;
}

// Test 10: MoEWeightProxy.hpp
#include "MoEWeightProxy.hpp"
#include <filesystem>

namespace probe_moeproxy {
    namespace fs = ::std::filesystem;
}

int main() {
    return 0;
}