#version 450

void main() {
    vec2 positions[3] = vec2[](
        vec2(-0.7, -0.7),
        vec2( 0.7, -0.7),
        vec2( 0.0,  0.7)
    );
    gl_Position = vec4(positions[gl_VertexIndex], 0.5, 1.0);
}