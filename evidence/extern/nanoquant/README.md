# RawrXD nanoquant residency prototype

C++17 header-only, no external dependencies. This is a **lossless byte-stream packing prototype**, not a new GGUF numerical quantization scheme, and not yet integrated with Vulkan.

`plan()` stores compressed bytes only when smaller than the input; `restore()` reproduces the original GGUF weight bytes exactly. The codec targets repeated byte runs; high-entropy quantized weights may not compress, so no memory or upload reduction is promised.

Build/test: `g++ -std=c++17 -O2 -Wall -Wextra -pedantic test.cpp -o nanoquant_test && ./nanoquant_test`

Integration guidance: pack the *host-side* tensor cache first; for reduced PCIe uploads, decode on GPU using a validated Vulkan decoder, or upload packed bytes and decode on device. If decoding on CPU before upload, the PCIe upload count remains unchanged. Native Q2_K/Q3_K kernels can reduce expanded-F32 traffic without lossy requantization. Keep all existing GGUF type metadata, tensor identity/revision, offsets, and per-device residency ownership. Compare full logits bitwise against the unmodified baseline. Treat allocations, eviction, upload, and completion as transactional with fence-safe leases.

Safety: untrusted streams must be bounded by expected output length; decoder validates lengths but does not authenticate data. Add checksums, fuzz tests, and device-side decode parity before production use.
