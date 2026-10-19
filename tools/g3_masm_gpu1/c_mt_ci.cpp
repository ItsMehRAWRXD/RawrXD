#include <stdio.h>
#include <vulkan/vulkan.h>
int main(void){
  VkApplicationInfo app={};
  app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
  app.apiVersion=VK_API_VERSION_1_2;
  VkInstanceCreateInfo ci={};
  ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
  ci.pApplicationInfo=&app;
  VkInstance inst=0;
  VkResult r=vkCreateInstance(&ci,0,&inst);
  printf("C_MT_CREATE_INSTANCE=%d\n", (int)r);
  if(inst) vkDestroyInstance(inst,0);
  return 0;
}
