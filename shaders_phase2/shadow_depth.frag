#version 450

// Shadow map depth-only fragment shader.
//
// No color output — depth is written via the depth attachment.
// This shader exists only for potential alpha-tested geometry
// (foliage, fences) that needs depth testing in the shadow pass.

layout(location = 0) in int in_cascade_idx;

void main() {
    // Depth is written automatically by the rasterizer.
    // For alpha-tested geometry, discard based on alpha threshold.
    // (Solid geometry produces no fragments here.)
}