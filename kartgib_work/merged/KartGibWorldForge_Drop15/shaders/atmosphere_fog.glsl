// Linear-HDR distance fog. Include in an existing fragment shader.
vec3 kgApplyFog(vec3 scene,vec3 fogColor,float distanceMeters,float density){float transmittance=exp(-max(distanceMeters,0.)*max(density,0.));return mix(fogColor,scene,transmittance);}
