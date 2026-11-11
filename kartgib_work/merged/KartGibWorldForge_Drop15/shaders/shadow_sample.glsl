// Include in the lighting fragment shader after binding a comparison sampler.
// Vulkan shadow images must be transitioned to DEPTH_STENCIL_READ_ONLY_OPTIMAL.
float kartgibShadowPCF(sampler2DShadow shadowTex,vec3 uvz,vec2 texelSize,float bias){
 if(any(lessThan(uvz,vec3(0.0)))||any(greaterThan(uvz,vec3(1.0))))return 1.0;
 float visibility=0.0;
 for(int y=-1;y<=1;++y)for(int x=-1;x<=1;++x)
   visibility+=texture(shadowTex,vec3(uvz.xy+vec2(x,y)*texelSize,uvz.z-bias));
 return visibility/9.0;
}
