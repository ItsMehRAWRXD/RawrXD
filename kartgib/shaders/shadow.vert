#version 450

layout(location = 0) in vec3 inPos;
layout(push_constant) uniform PC { mat4 vp; } pc;

void main() {
    gl_Position = pc.vp * vec4(inPos, 1.0);
}
