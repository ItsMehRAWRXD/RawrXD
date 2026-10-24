# Deep2 native MoE optimization program

Research reference: https://github.com/Magnvs7/Promethevs

Do not import NVIDIA binaries or new dependencies. Preserve existing Deep2, Ollama, GGUF and agent paths. Default to exact decoding until validated.

## Batch 1 (1-15): baseline
1. Inventory existing MoE code
2. Map expert load path
3. Map residency counters
4. Map NVMe stream path
5. Map Vulkan dispatch
6. Map multi-GPU placement
7. Map quant formats
8. Identify model architectures
9. Capture exact reference tokens
10. Capture prefill TPS
11. Capture decode TPS
12. Capture IO bytes
13. Capture GPU wait time
14. Capture RAM/VRAM peaks
15. Freeze baseline receipts

## Batch 2 (16-30): core implementation
16. Expert store format
17. Versioned header
18. Checksums
19. Compact quant metadata
20. Correction plane metadata
21. Exact reconstruction
22. Roundtrip tests
23. Confidence gate
24. Fail-closed fallback
25. Expert cache index
26. LRU policy
27. Async read scheduling
28. Batched expert reads
29. Prefetch telemetry
30. Exact/approx mode switch

## Batch 3 (31-45): decoding
31. Draft capability detection
32. Draft tokenizer parity
33. Draft KV isolation
34. Candidate generation
35. Verification path
36. Rejection rollback
37. EOS handling
38. Tool-call integrity
39. Streaming integrity
40. Cancellation
41. Context overflow
42. Batch size sweep
43. Prompt length sweep
44. Quality sweep
45. Decode receipts

## Batch 4 (46-60): AMD optimization
46. Vulkan staging pools
47. Transfer queue assessment
48. GPU0 wait attribution
49. GPU1 wait attribution
50. GPU-local expert residency
51. Placement policy
52. Cache coherence
53. Dual-GPU synchronization
54. Quant GEMV parity
55. FFN parity
56. NaN checks
57. Memory-pressure fallback
58. Device-loss recovery
59. TPS matched sweep
60. GPU receipts

## Batch 5 (61-75): release certification
61. DeepSeek model compatibility
62. Nemotron compatibility
63. Kimi compatibility
64. Dense-model regression
65. Ollama regression
66. Deep2 regression
67. Agent tool-call regression
68. Compiler edit-build-test regression
69. Snapshot rollback
70. HTTP API regression
71. IDE integration
72. Clean Windows build
73. GitHub Actions build
74. Repeatable benchmark
75. Release gate with no unsupported PASS claims

No tasks are certified by this plan alone. Promote optimizations only when semantic correctness and matched benchmark receipts pass.