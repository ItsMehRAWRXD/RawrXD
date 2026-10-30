#version 450

layout(location = 0) in vec3 fragNormal;
layout(location = 1) in vec3 fragWorldPos;
layout(location = 2) in vec2 fragUV;
layout(location = 0) out vec4 outColor;

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
layout(set = 0, binding = 1) uniform sampler2D shadowMap;

vec3 aces(vec3 x) {
    return clamp((x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14), 0.0, 1.0);
}
float ggx(float noh, float roughness) {
    float a = roughness * roughness;
    float a2 = a * a;
    float d = noh * noh * (a2 - 1.0) + 1.0;
    return a2 / max(3.14159265 * d * d, 1e-5);
}
float shadowOcc(vec3 worldPos, out int cascade) {
    float dist = -(ubo.view[0].z * worldPos.x + ubo.view[1].z * worldPos.y
        + ubo.view[2].z * worldPos.z + ubo.view[3].z);
    cascade = dist < ubo.cascadeSplits.x ? 0 : dist < ubo.cascadeSplits.y ? 1
        : dist < ubo.cascadeSplits.z ? 2 : 3;
    if (ubo.shadowOn < 0.5) return 1.0;
    vec4 lp = ubo.cascadeVp[cascade] * vec4(worldPos, 1.0);
    vec3 ndc = lp.xyz / lp.w;
    if (ndc.x < -1.0 || ndc.x > 1.0 || ndc.y < -1.0 || ndc.y > 1.0) return 1.0;
    vec2 uv = ndc.xy * 0.25 + 0.25;
    uv += vec2(float(cascade & 1), float(cascade >> 1)) * 0.5;
    float vis = 0.0;
    for (int y = -1; y <= 1; ++y) {
        for (int x = -1; x <= 1; ++x) {
            float d = texture(shadowMap, uv + vec2(x, y) / 2048.0).r;
            vis += (d + 0.0008 >= ndc.z) ? 1.0 : 0.0;
        }
    }
    return vis / 9.0;
}
void main() {
    if (fragUV.y > 9.5) { outColor = vec4(1.0, 1.0, 1.0, 1.0); return; }
    if (fragUV.y > 8.5) { outColor = vec4(0.15, 0.35, 1.0, 1.0); return; }
    if (fragUV.y > 7.5) { outColor = vec4(0.15, 0.85, 0.2, 1.0); return; }
    if (fragUV.y > 6.5) { outColor = vec4(0.95, 0.12, 0.08, 1.0); return; }
    if (fragUV.y > 4.5) { outColor = vec4(1.0, 0.95, 0.05, 1.0); return; }
    if (fragUV.y > 3.5) { outColor = vec4(0.16, 0.62, 0.14, 1.0); return; }
    if (fragUV.y > 2.5) { outColor = vec4(0.90, 0.32, 0.05, 1.0); return; }
    if (fragUV.y > 1.5) {
        vec3 n = normalize(fragNormal);
        vec3 l = normalize(-ubo.lightDir.xyz);
        vec3 v = normalize(ubo.cameraPos.xyz - fragWorldPos);
        vec3 h = normalize(l + v);
        float ndotl = max(dot(n, l), 0.0);
        float ndotv = max(dot(n, v), 0.0);
        float ndoth = max(dot(n, h), 0.0);
        int cascade = 0;
        float occ = shadowOcc(fragWorldPos, cascade);
        float fresnel = 0.02 + 0.98 * pow(1.0 - ndotv, 5.0);
        vec3 water = mix(vec3(0.01, 0.05, 0.08), vec3(0.04, 0.22, 0.20), clamp(fragWorldPos.y - 6.0, 0.0, 1.0));
        vec3 color = mix(water, vec3(0.55, 0.62, 0.68), fresnel) + vec3(ggx(ndoth, 0.05)) * ndotl * occ * 0.35;
        color = mix(color, vec3(0.86, 0.90, 0.88), clamp(fragUV.x, 0.0, 1.0));
        outColor = vec4(aces(color), 1.0);
        return;
    }
    vec3 n = normalize(fragNormal);
    vec3 l = normalize(-ubo.lightDir.xyz);
    vec3 v = normalize(ubo.cameraPos.xyz - fragWorldPos);
    vec3 h = normalize(l + v);
    float height = fragWorldPos.y;
    vec3 albedo = vec3(0.30, 0.48, 0.18);
    if (ubo.padA > 0.5) {
        float temp = clamp(fragUV.x, 0.0, 1.0);
        float moist = clamp(fragUV.y, 0.0, 1.0);
        float elev = clamp(height / 32.0, 0.0, 1.0);
        albedo = mix(vec3(0.45, 0.50, 0.22), vec3(0.72, 0.58, 0.32), smoothstep(0.45, 0.75, temp) * (1.0 - moist));
        albedo = mix(albedo, vec3(0.12, 0.36, 0.16), smoothstep(0.45, 0.80, moist));
        albedo = mix(albedo, vec3(0.05, 0.42, 0.22), smoothstep(0.60, 0.85, temp) * smoothstep(0.55, 0.85, moist));
        albedo = mix(albedo, vec3(0.55, 0.56, 0.58), smoothstep(0.55, 0.90, elev));
        if (moist > 0.82 && height < 10.0) albedo = mix(albedo, vec3(0.15, 0.35, 0.62), 0.65);
    } else if (height < 2.0) albedo = vec3(0.18, 0.28, 0.45);
    else if (height < 12.0) albedo = vec3(0.45, 0.36, 0.22);
    else if (height < 28.0) albedo = vec3(0.55, 0.55, 0.52);
    else albedo = vec3(0.90, 0.90, 0.92);
    float rough = mix(0.85, 0.35, clamp(height / 40.0, 0.0, 1.0));
    float ndotl = max(dot(n, l), 0.0);
    float ndoth = max(dot(n, h), 0.0);
    int cascade = 0;
    float occ = shadowOcc(fragWorldPos, cascade);
    if (ubo.lightDir.w > 4.5) {
        vec3 id = cascade == 0 ? vec3(1, 0, 0) : cascade == 1 ? vec3(0, 1, 0)
            : cascade == 2 ? vec3(0, 0, 1) : vec3(1, 1, 0);
        outColor = vec4(id, 1.0);
        return;
    }
    vec3 diffuse = albedo * (0.15 + 0.85 * ndotl * occ);
    vec3 spec = vec3(ggx(ndoth, rough)) * ndotl * occ * 0.08;
    vec3 color = diffuse + spec;
    if (ubo.lightDir.w > 2.5) color = albedo;
    else if (ubo.lightDir.w > 0.5) color = diffuse;
    outColor = vec4(aces(color), 1.0);
}
