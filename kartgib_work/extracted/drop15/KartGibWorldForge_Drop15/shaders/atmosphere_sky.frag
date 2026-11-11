#version 450
layout(location=0) in vec2 uv;
layout(location=0) out vec4 outColor;
layout(push_constant) uniform Params {vec4 sunDir;vec4 horizon;vec4 zenith;vec4 settings;} pc;
void main(){vec3 dir=normalize(vec3(uv*2.0-1.0,1.0));float t=clamp(dir.y*.65+.35,0.,1.);vec3 sky=mix(pc.horizon.rgb,pc.zenith.rgb,pow(t,.55));float angle=max(dot(dir,normalize(pc.sunDir.xyz)),0.);float disc=1.-smoothstep(0.,.00008,1.-angle);sky+=vec3(9.,6.,3.)*disc;outColor=vec4(sky,1.);}
