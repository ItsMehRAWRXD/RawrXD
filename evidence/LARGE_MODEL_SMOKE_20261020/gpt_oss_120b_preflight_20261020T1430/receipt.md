# GPT-OSS 120B preflight — 2026-10-20

Status: **BLOCKED (host-memory budget)**

The local Ollama model resolves to:

`F:\OllamaModels\blobs\sha256-6be6d66a3f546d8c19b130dc41dc24b2fc159f84ffbc76a0ee0676205083cf5a`

The GGUF blob is 65,369,799,840 bytes (about 60.9 GiB) with architecture
`gptoss`, 36 blocks, embedding 2880, 128 experts, and 4 active experts. The
host reports 64 GiB total RAM and about 44.3 GB free before loading. A prior
19.85 GB model on this same executable reached 23.99 GB resident host memory
during its bounded run. The current runtime materializes/dequantises weights
in host memory, so launching the 120B smoke would exceed the available RAM
budget before a meaningful logits receipt could be produced.

No GPU process was launched for this preflight. GPT-OSS remains eligible only
after ROM/streaming residency is wired into the executable or the host-memory
budget changes. This is a resource gate, not an inference correctness result.
