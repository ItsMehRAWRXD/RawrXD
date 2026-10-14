"""CPU-only inspection of the exact reference runtime's public GGML traits."""
import ctypes
import hashlib
import json
import os
from pathlib import Path

out = Path(__file__).resolve().parent
binary_dir = Path(r'F:\rawrxd\tmp_llama-clone\build\bin\Release')
cookie = os.add_dll_directory(str(binary_dir))


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024*1024):
            h.update(chunk)
    return h.hexdigest()


class CpuTraits(ctypes.Structure):
    _fields_ = [('from_float',ctypes.c_void_p),('vec_dot',ctypes.c_void_p),
                ('vec_dot_type',ctypes.c_int),('nrows',ctypes.c_int64)]


dll = ctypes.CDLL(str(binary_dir/'ggml-cpu.dll'))
traits = dll.ggml_get_type_traits_cpu
traits.argtypes = [ctypes.c_int]
traits.restype = ctypes.POINTER(CpuTraits)
base = ctypes.CDLL(str(binary_dir/'ggml-base.dll'))
type_name = base.ggml_type_name
type_name.argtypes = [ctypes.c_int]
type_name.restype = ctypes.c_char_p
rows = []
for kind in (2,8,12,14):
    value = traits(kind).contents
    rows.append({'weight_type':kind,'weight_name':type_name(kind).decode(),
                 'vec_dot_type':value.vec_dot_type,'vec_dot_name':type_name(value.vec_dot_type).decode(),
                 'nrows':value.nrows,'from_float_present':bool(value.from_float),
                 'vec_dot_present':bool(value.vec_dot)})
paths = [binary_dir/name for name in ('llama_dump_logits_teacher_forced.exe','llama.dll','ggml.dll','ggml-cpu.dll','ggml-base.dll')]
result = {'cpu_only':True,'method':'ggml_get_type_traits_cpu exported by reference binary dependency',
          'abi_authority':'3rdparty/ggml/include/ggml-cpu.h:112 (from_float,vec_dot,vec_dot_type,nrows)',
          'traits':rows,'binaries':[{'path':str(p),'bytes':p.stat().st_size,'sha256':digest(p)} for p in paths],
          'interpretation':'Q4_K and Q6_K use Q8_K activations in this exact reference runtime; per-32 Q8_0 activation granularity does not explain their differences.'}
(out/'reference_binary_traits.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
