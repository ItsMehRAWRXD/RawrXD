# RawrZ FHp.ps1 - Public Domain File-less Hot-patch One-liner
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org/>
#
# File-less hot-patch one-liner
# Drag any .cpp onto it → compiles in memory, encrypts the native exe, then hot-injects into current PowerShell process
$args|%{$c=[IO.File]::ReadAllText($_);Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Security.Cryptography;public class H{[DllImport(\"kernel32\")]static extern IntPtr VirtualAlloc(IntPtr p,uint s,uint t,uint f);[DllImport(\"kernel32\")]static extern bool VirtualProtect(IntPtr a,uint s,uint f,out uint o);[DllImport(\"kernel32\")]static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr e,IntPtr p,uint f,out uint i);public static void R(byte[]b,byte[]k,byte[]i){var a=VirtualAlloc(IntPtr.Zero,(uint)b.Length,0x1000|0x2000,0x40);var c=new CamelliaManaged(){Key=k,IV=i};var d=c.CreateDecryptor();var p=d.TransformFinalBlock(b,0,b.Length);Marshal.Copy(p,0,a,p.Length);uint o;VirtualProtect(a,(uint)p.Length,0x20,out o);CreateThread(IntPtr.Zero,0,a,IntPtr.Zero,0,out o);}}';$k=RandomNumberGenerator.GetBytes(32);$i=RandomNumberGenerator.GetBytes(16);$o=New-Object System.IO.MemoryStream;(Start-Process -FilePath "clang++" -ArgumentList @("-x","c++","-o","-","-O2","-static","-"),InputString $c,NoNewWindow:$true,PassThru:$true).StandardOutput.BaseStream.CopyTo($o);$e=$o.ToArray();$x=Convert.ToBase64String((new CamelliaManaged(){Key=$k,IV=$i}).CreateEncryptor().TransformFinalBlock($e,0,$e.Length));[H]::R([Convert]::FromBase64String($x),$k,$i);Write-Host "✔ Hot-patched: $_" -ForegroundColor Magenta}
