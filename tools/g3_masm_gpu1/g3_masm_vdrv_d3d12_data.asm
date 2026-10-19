; g3_masm_vdrv_d3d12_data.asm
OPTION CASEMAP:NONE
PUBLIC szDxgi,szD3d12,szCF1,szCD,szGate,szPath,szVk0,szFail,sz7800,sz9700,n7800,n9700
PUBLIC iidFact,hDxgi,hD3d,pfnCF1,pFactory
.data
szDxgi BYTE "dxgi.dll",0
szD3d12 BYTE "d3d12.dll",0
szCF1 BYTE "CreateDXGIFactory1",0
szCD BYTE "D3D12CreateDevice",0
szGate BYTE "GATE=G3_GPU1_VDRIVER_D3D12_001",0
szPath BYTE "VDRIVER_PATH=WDDM_UMD_via_D3D12_no_vulkan",0
szVk0 BYTE "VULKAN_USED=0",0
szFail BYTE "VDRV_INIT=FAIL",0
sz7800 BYTE "RX7800XT_",0
sz9700 BYTE "R9700_",0
n7800 BYTE "7800",0
n9700 BYTE "R9700",0
align 16
iidFact BYTE 78h,0AEh,0Ah,77h,6Fh,0F2h,0BAh,4Dh,0A8h,29h,25h,3Ch,83h,0D1h,0B3h,87h
align 8
hDxgi QWORD 0
hD3d QWORD 0
pfnCF1 QWORD 0
pFactory QWORD 0
END
