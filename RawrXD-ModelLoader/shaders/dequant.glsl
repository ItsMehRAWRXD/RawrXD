#version 450

layout(local_size_x = 32) in;

layout(set = 0, binding = 0) readonly buffer Quantized {
    uint8_t data[];
} quantized_buf;

layout(set = 0, binding = 1) writeonly buffer Output {
    float data[];
} output_buf;

uniform uint elements;
uniform uint quant_type;  // 0=Q2_K, 1=Q3_K, 2=Q4_K, 3=Q5_K, 4=Q6_K, 5=Q8_0

void main() {
    uint idx = gl_GlobalInvocationID.x;
    
    if (idx >= elements) return;
    
    // Dequantization logic (simplified)
    // Different quantization schemes have different encodings
    
    float scale = 1.0 / 127.0;  // Placeholder
    float output_val;
    
    if (quant_type == 0) {  // Q2_K: 2.625 bits per weight
        uint byte_idx = idx / 4;
        uint bit_offset = (idx % 4) * 2;
        uint8_t quant_val = (quantized_buf.data[byte_idx] >> bit_offset) & 0x3;
        output_val = (float(quant_val) - 2.0) * scale;
    } else if (quant_type == 2) {  // Q4_K: 4 bits per weight
        uint byte_idx = idx / 2;
        uint nibble = idx % 2;
        uint8_t quant_val = (quantized_buf.data[byte_idx] >> (nibble * 4)) & 0xF;
        output_val = (float(quant_val) - 8.0) * scale;
    } else {
        output_val = float(quantized_buf.data[idx]) * scale;
    }
    
    output_buf.data[idx] = output_val;
}
