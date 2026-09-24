import subprocess, os, sys

# Build isolated CycloneScheduler test using MSVC cl.exe
vcvars = r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
if not os.path.exists(vcvars):
    vcvars = r'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
if not os.path.exists(vcvars):
    vcvars = r'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat'

build_cmd = (
    f'"{vcvars}" && cl.exe /EHsc /std:c++17 '
    f'/I F:\\~dev\\rawrxd\\src\\deep2 '
    f'F:\\~dev\\rawrxd\\src\\deep2\\CycloneScheduler_test.cpp '
    f'F:\\~dev\\rawrxd\\src\\deep2\\CycloneScheduler.cpp '
    f'/Fe:F:\\~dev\\_test_cyclone.exe'
)

print("=== BUILD COMMAND ===")
print(build_cmd)

build_proc = subprocess.run(
    build_cmd,
    shell=True,
    capture_output=True,
    text=True
)

with open(r'F:\~dev\_test_cyclone_build.txt', 'w', encoding='utf-8') as f:
    f.write(build_proc.stdout)
    f.write(build_proc.stderr)

if build_proc.returncode != 0:
    print("BUILD FAILED")
    print(build_proc.stderr)
    sys.exit(1)

print("BUILD SUCCEEDED")

# Run test
run_proc = subprocess.run(
    r'F:\~dev\_test_cyclone.exe',
    capture_output=True,
    text=True
)

with open(r'F:\~dev\_test_cyclone_run.txt', 'w', encoding='utf-8') as f:
    f.write(run_proc.stdout)
    f.write(run_proc.stderr)

if run_proc.returncode != 0:
    print("TEST FAILED")
    print(run_proc.stdout)
    print(run_proc.stderr)
    sys.exit(1)

print("TEST PASSED")
print(run_proc.stdout)
