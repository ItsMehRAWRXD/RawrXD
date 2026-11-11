#version 450
layout(location=0) in vec3 worldPos;
layout(location=0) out vec4 outColor;
layout(push_constant) uniform Water {vec4 cameraAndTime;vec4 deepColor;vec4 shallowColor;} water;
void main(){float t=water.cameraAndTime.w;vec2 p=worldPos.xz;float a=.23*cos(p.x*.23+p.y*.12+t*1.4);float b=.12*cos(p.x*.51-p.y*.37-t*2.1);vec3 n=normalize(vec3(-a-b,1.,-.5*a+.7*b));vec3 v=normalize(water.cameraAndTime.xyz-worldPos);float fresnel=pow(1.-clamp(dot(n,v),0.,1.),5.);vec3 c=mix(water.deepColor.rgb,water.shallowColor.rgb,.3+.3*n.y);outColor=vec4(mix(c,vec3(.55,.72,.9),fresnel*.7),1.);}
