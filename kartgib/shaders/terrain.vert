#version 450

layout(location = 0) in vec3 inPos;
layout(location = 1) in vec3 inNormal;
layout(location = 2) in vec2 inUV;

layout(set = 0, binding = 0) uniform UBO {
    mat4 view;
    mat4 proj;
    mat4 model;
    vec4 lightDir;
    vec4 cameraPos;
    float time;
    float shadowOn;
    float padA;
    float padB;
    mat4 cascadeVp[4];
    vec4 cascadeSplits;
} ubo;

layout(location = 0) out vec3 fragNormal;
layout(location = 1) out vec3 fragWorldPos;
layout(location = 2) out vec2 fragUV;

void main() {
    if (inUV.y > 9.5) {
        gl_Position = vec4(inPos.xy, 0.0, 1.0);
        fragNormal = vec3(0.0, 1.0, 0.0);
        fragWorldPos = vec3(0.0);
        fragUV = inUV;
        return;
    }
    vec4 worldPos = ubo.model * vec4(inPos, 1.0);
    gl_Position = ubo.proj * ubo.view * worldPos;
    fragNormal = normalize(mat3(ubo.model) * inNormal);
    fragWorldPos = worldPos.xyz;
    fragUV = inUV;
}
