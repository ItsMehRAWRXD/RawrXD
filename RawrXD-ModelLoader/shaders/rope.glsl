#version 450

layout(local_size_x = 32) in;

layout(set = 0, binding = 0) readonly buffer Input {
    float data[];
} input_buf;

layout(set = 0, binding = 1) writeonly buffer Output {
    float data[];
} output_buf;

uniform uint dim;
uniform uint seq_pos;
uniform uint rotation_dim;

const float PI = 3.14159265359;

void main() {
    uint idx = gl_GlobalInvocationID.x;
    
    if (idx >= rotation_dim / 2) return;
    
    // Rotary Position Embedding (RoPE)
    // theta = base^(-2k/d)
    // RoPE(x, m) = [x * cos(m*theta) - x' * sin(m*theta), x * sin(m*theta) + x' * cos(m*theta)]
    
    float base = 10000.0;
    float inv_freq = 1.0 / pow(base, 2.0 * float(idx) / float(rotation_dim));
    float angle = seq_pos * inv_freq;
    
    float cos_angle = cos(angle);
    float sin_angle = sin(angle);
    
    uint pos1 = 2 * idx;
    uint pos2 = 2 * idx + 1;
    
    float x1 = input_buf.data[pos1];
    float x2 = input_buf.data[pos2];
    
    output_buf.data[pos1] = x1 * cos_angle - x2 * sin_angle;
    output_buf.data[pos2] = x1 * sin_angle + x2 * cos_angle;
}
