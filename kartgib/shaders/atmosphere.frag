#version 450

layout(location = 0) out vec4 outColor;

layout(push_constant) uniform PC {
    vec4 screenSun;
    vec4 sunTime;
} pc;

vec3 aces(vec3 x) {
    return clamp((x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14), 0.0, 1.0);
}

void main() {
    vec2 resolution = max(pc.screenSun.xy, vec2(1.0));
    vec2 uv = (gl_FragCoord.xy / resolution) * 2.0 - 1.0;
    uv.x *= resolution.x / resolution.y;
    vec3 rd = normalize(vec3(uv, 1.25));
    vec3 sun = normalize(vec3(pc.screenSun.z, pc.screenSun.w, pc.sunTime.x));
    float mu = clamp(dot(rd, sun), 0.0, 1.0);
    float height = clamp(rd.y * 0.5 + 0.5, 0.0, 1.0);
    vec3 betaR = vec3(0.0058, 0.0135, 0.0331);
    vec3 sky = mix(vec3(0.32, 0.42, 0.58), vec3(0.12, 0.32, 0.82), height);
    sky *= exp(-betaR * (1.0 - height) * 80.0);
    sky += vec3(1.0, 0.86, 0.55) * pow(mu, 64.0) * 2.2;
    sky += vec3(1.0, 0.92, 0.82) * pow(mu, 8.0) * 0.18;
    float cloud = sin(rd.x * 14.0 + pc.sunTime.y) * sin(rd.z * 9.0 - pc.sunTime.y * 0.15);
    cloud = smoothstep(0.4, 0.85, cloud * 0.5 + 0.5) * clamp(rd.y, 0.0, 1.0);
    sky = mix(sky, vec3(0.96, 0.97, 0.99), cloud * 0.5);
    outColor = vec4(aces(sky), 1.0);
}
