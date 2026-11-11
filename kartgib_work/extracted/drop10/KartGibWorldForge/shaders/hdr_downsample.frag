#version 450
layout(location=0) in vec2 uv;
layout(location=0) out vec4 outColor;
layout(set=0,binding=0) uniform sampler2D srcImage;
void main(){vec2 t=0.5/vec2(textureSize(srcImage,0));vec3 c=texture(srcImage,uv+vec2(-t.x,-t.y)).rgb+texture(srcImage,uv+vec2(t.x,-t.y)).rgb+texture(srcImage,uv+vec2(-t.x,t.y)).rgb+texture(srcImage,uv+t).rgb;outColor=vec4(c*.25,1);}
