cd /d F:\rawrxd
git commit -m "RawrXDCore.dll: Minimal inference with IR executor integration

Removed broken Deep2Engine.cpp from build
Added cpu_inference_engine.cpp to build for CPUInferenceEngine
Added ChatTemplate.hpp for tokenizer support
Removed IR adapter files (syntax errors)
Minimal inference implementation in RawrXDCore.cpp (placeholder)
IR executor works and generates tokens:
Position 0: input=1 -> pred=185 PASS
Position 1: input=185 -> pred=185 PASS
Position 2: input=16 -> pred=13 PASS
Position 3: input=15 -> pred=15 PASS
All logits finite, 300/300 ops dispatched
IR executor works and generates tokens. RawrXDCore.dll builds but needs full inference integration."