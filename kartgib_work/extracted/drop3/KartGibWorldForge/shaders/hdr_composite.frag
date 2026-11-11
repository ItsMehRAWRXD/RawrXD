#version 450
layout(location=0) in vec2 uv;
layout(location=0) out vec4 outColor;
layout(set=0,binding=0) uniform sampler2D hdrImage;
layout(set=0,binding=1) uniform sampler2D bloomImage;
layout(push_constant) uniform Settings {float exposureEV;float bloomStrength;int enableBloom;float _pad;} settings;
vec3 aces(vec3 x){return clamp((x*(2.51*x+0.03))/(x*(2.43*x+0.59)+0.14),0.0,1.0);}
vec3 linearToSrgb(vec3 c){return mix(12.92*c,1.055*pow(c,vec3(1.0/2.4))-0.055,greaterThan(c,vec3(0.0031308)));}
void main(){vec3 c=texture(hdrImage,uv).rgb;if(settings.enableBloom!=0)c+=texture(bloomImage,uv).rgb*settings.bloomStrength;c=aces(max(c,0.0)*exp2(settings.exposureEV));outColor=vec4(linearToSrgb(c),1.0);}
