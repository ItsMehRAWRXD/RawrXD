; Toolchain test 
extrn ExitProcess: proc 
.code 
mainCRTStartup proc 
  xor ecx, ecx 
  call ExitProcess 
mainCRTStartup endp 
end 
