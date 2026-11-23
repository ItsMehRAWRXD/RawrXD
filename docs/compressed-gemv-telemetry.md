# Compressed GEMV runtime telemetry

The tiled compressed Vulkan GEMV API optionally fills `VulkanCompressedGemvStats`:

- matrix rows and columns;
- number of dispatched tiles;
- total decoded F32 weight bytes;
- peak decoded F32 tile bytes;
- total weight bytes uploaded to Vulkan;
- encoded pager residency before and after the operation.

`Deep2Engine::compressedWeightResidencyStats()` aggregates currently retained compressed tensor views and reports logical bytes, resident encoded bytes, compressed/raw page counts, and cache misses.

The ROM execution smoke prints tile count, peak decoded tile bytes, and encoded cache residency for each GPU. This makes it possible to verify that the full matrix is not expanded into a single F32 host buffer: peak decoded weight memory should be approximately `activeTileRows * columns * sizeof(float)`, while cumulative decoded/uploaded bytes scale with the full matrix.

The encoded-cache residency is a snapshot of the engine's currently retained compressed views, not process-wide memory accounting. It excludes the current temporary decoded tile, Vulkan allocations, driver overhead, and any other tensor allocations. The telemetry is diagnostic, not a replacement for OS/GPU memory profiling.

No local build or target-device measurements have been run by the GitHub connector. Capture these values from the Windows Release ROM smoke on both supported AMD GPUs before promoting the implementation.
