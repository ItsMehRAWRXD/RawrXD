#version 450
layout(location=0) in vec2 uv;
layout(location=0) out vec4 outColor;
layout(set=0,binding=0) uniform sampler2D hdrImage;
layout(push_constant) uniform Settings {float threshold;float knee;} settings;
void main(){vec3 c=max(texture(hdrImage,uv).rgb,0.0);float l=dot(c,vec3(.2126,.7152,.0722));float k=max(settings.knee,.0001);float soft=clamp(l-settings.threshold+k,0.0,2.0*k);soft=soft*soft/(4.0*k);float w=max(soft,l-settings.threshold)/max(l,.0001);outColor=vec4(c*w,1);}
