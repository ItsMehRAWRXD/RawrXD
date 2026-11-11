; Simple exit program 
.code 
extrn ExitProcess: proc 
mainCRTStartup proc 
    xor ecx, ecx 
    call ExitProcess 
mainCRTStartup endp 
end 
