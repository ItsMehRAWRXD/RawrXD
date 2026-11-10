#version 450
layout(location=0) in vec3 inPosition;
layout(location=4) in vec4 instanceRow0;
layout(location=5) in vec4 instanceRow1;
layout(location=6) in vec4 instanceRow2;
layout(location=7) in vec4 instanceRow3;
layout(set=0,binding=0) uniform ShadowCamera {mat4 lightViewProj;} camera;
void main(){mat4 model=mat4(instanceRow0,instanceRow1,instanceRow2,instanceRow3);gl_Position=camera.lightViewProj*model*vec4(inPosition,1.0);}
