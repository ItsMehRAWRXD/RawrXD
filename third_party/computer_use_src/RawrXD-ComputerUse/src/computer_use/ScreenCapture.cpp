#include "ComputerUse.h"
#include <vector>
#include <string>
namespace rawrxd::computer_use {
ActionResult ComputerUseEngine::Capture(HWND window) const {
    if(!policy_.allowScreenshots || !IsTargetAllowed(window)) return {false,ERROR_ACCESS_DENIED,L"Screenshot denied by policy or window not allowed"};
    RECT rect{}; if(!GetClientRect(window,&rect)) return {false,GetLastError(),L"GetClientRect failed"};
    int w=rect.right,h=rect.bottom;
    if(w<=0 || h<=0 || static_cast<uint64_t>(w)*h>16000000) return {false,ERROR_INVALID_PARAMETER,L"Invalid or excessive capture dimensions"};
    HDC src=GetDC(window); if(!src) return {false,GetLastError(),L"GetDC failed"};
    HDC mem=CreateCompatibleDC(src); HBITMAP bmp=CreateCompatibleBitmap(src,w,h);
    if(!mem || !bmp) { if(bmp) DeleteObject(bmp); if(mem) DeleteDC(mem); ReleaseDC(window,src); return {false,ERROR_NOT_ENOUGH_MEMORY,L"Bitmap allocation failed"}; }
    HGDIOBJ old=SelectObject(mem,bmp); bool copied=BitBlt(mem,0,0,w,h,src,0,0,SRCCOPY|CAPTUREBLT)!=0;
    BITMAPINFO info{}; info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER); info.bmiHeader.biWidth=w; info.bmiHeader.biHeight=-h; info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32; info.bmiHeader.biCompression=BI_RGB;
    std::vector<unsigned char> pixels(static_cast<size_t>(w)*h*4);
    bool extracted=copied && GetDIBits(mem,bmp,0,static_cast<UINT>(h),pixels.data(),&info,DIB_RGB_COLORS)!=0;
    SelectObject(mem,old); DeleteObject(bmp); DeleteDC(mem); ReleaseDC(window,src);
    if(!extracted) return {false,ERROR_GEN_FAILURE,L"Capture failed (occlusion/protected surface possible)"};
    wchar_t temp[MAX_PATH]{}; if(!GetTempPathW(MAX_PATH,temp)) return {false,GetLastError(),L"GetTempPath failed"};
    wchar_t file[MAX_PATH]{}; if(!GetTempFileNameW(temp,L"RXD",0,file)) return {false,GetLastError(),L"GetTempFileName failed"};
    // Write uncompressed BMP; temporary file is local and must be handled as sensitive.
    BITMAPFILEHEADER fh{}; fh.bfType=0x4D42; fh.bfOffBits=sizeof(fh)+sizeof(BITMAPINFOHEADER); fh.bfSize=fh.bfOffBits+static_cast<DWORD>(pixels.size());
    BITMAPINFOHEADER bh=info.bmiHeader;
    HANDLE out=CreateFileW(file,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY,nullptr);
    if(out==INVALID_HANDLE_VALUE) { DeleteFileW(file); return {false,GetLastError(),L"Open screenshot file failed"}; }
    auto write=[&](const void* p,DWORD n){DWORD written=0;return WriteFile(out,p,n,&written,nullptr) && written==n;};
    bool ok=write(&fh,sizeof(fh)) && write(&bh,sizeof(bh)) && write(pixels.data(),static_cast<DWORD>(pixels.size()));
    CloseHandle(out); if(!ok) {DeleteFileW(file);return {false,ERROR_WRITE_FAULT,L"Screenshot write failed"};}
    ActionResult r; r.success=true;r.message=L"BMP captured to local temporary file";r.window=window;r.screenshotPath=file;return r;
}
}
