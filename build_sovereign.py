import os
import subprocess
import glob

vswhere_path = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
vs_install = r"C:\VS2022Enterprise"
if os.path.exists(vswhere_path):
    out = subprocess.check_output(f'"{vswhere_path}" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath', text=True)
    if out.strip():
        vs_install = out.strip()

vcvars = os.path.join(vs_install, r"VC\Auxiliary\Build\vcvars64.bat")
src_dir = r"D:\rawrxd\src"
bin_dir = r"D:\rawrxd\bin"
if not os.path.exists(bin_dir):
    os.makedirs(bin_dir)

files = glob.glob(os.path.join(src_dir, "Sovereign_*.asm"))

build_bat = r"D:\rawrxd\build_sovereign.bat"
with open(build_bat, "w") as f:
    f.write(f'call "{vcvars}"\n')
    for file in files:
        fname = os.path.basename(file)
        obj_file = os.path.join(bin_dir, fname.replace(".asm", ".obj"))
        f.write(f'ml64.exe /c /nologo /Zi /W3 /Cp /Cx /Fo"{obj_file}" "{file}"\n')
        
    obj_files = glob.glob(os.path.join(bin_dir, "Sovereign_*.obj"))
    obj_files_str = " ".join([f'"{obj}"' for obj in obj_files])
    if not obj_files_str:
        # In case they aren't generated yet, we'll write the expected names
        obj_files_list = [os.path.join(bin_dir, os.path.basename(f).replace('.asm', '.obj')) for f in files]
        obj_files_str = " ".join([f'"{obj}"' for obj in obj_files_list])
        
    f.write(f'link.exe /NOLOGO /OUT:"{bin_dir}\\Sovereign_Kernel.exe" /SUBSYSTEM:CONSOLE /MACHINE:X64 /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /NXCOMPAT /DYNAMICBASE /NODEFAULTLIB kernel32.lib {obj_files_str}\n')
