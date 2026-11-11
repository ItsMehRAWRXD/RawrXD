#!/usr/bin/env python3
"""Surgical, fail-closed correction of GGML-contiguous indexing and token0 Q6_K.
Recognizes both the 2026-10-08 b7f4c35 executor and already-patched variants.
Never modifies generated headers, ROM/model data, or Git submodules.
"""
import argparse
from pathlib import Path
import re
import sys

OLD_MATMUL = "B[k * N + j]"
CORRECT_MATMUL_MARKER = "RAWRXD_GGML_CONTIGUOUS_MATMUL_002"
Q6_MARKER = "RAWRXD_Q6_SIGNED_SCALES_002"


def swap_once_or_confirm(src: str, old: str, new: str, label: str):
    hits = src.count(old)
    if hits == 1 and new not in src:
        return src.replace(old, new), True, label + '=CORRECTED'
    if hits == 0 and new in src:
        return src, False, label + '=ALREADY_CORRECT'
    raise ValueError(f'{label}: unexpected source, old matches={hits}, new matches={src.count(new)}')


def patch_executor(src: str):
    notes=[]; changed=False
    for old,new,label in (
        ('output[j] = weight[j * out + token];',
         'output[j] = weight[token * in + j];', 'EMBEDDING_ROW'),
        ('sum += double(input[j]) * double(weight[j * out + i]);',
         'sum += double(input[j]) * double(weight[i * in + j]);','DOTROWS_ROW'),
    ):
        src,d,n=swap_once_or_confirm(src,old,new,label);notes.append(n);changed|=d
    src=src.replace('// weight[j * out + i] is element at row j (input), column i (output).',
                    '// GGML dim[0] contiguous: weight[i * in + j] selects output row i.')
    src=src.replace('// weight[j * out + i] is element at row j, column i.',
                    '// GGML dim[0] contiguous: weight[i * in + j] selects output row i.')
    src=src.replace('// Computes: output[i] = sum_j input[j] * weight[j * out + i]',
                    '// Computes: output[i] = sum_j input[j] * weight[i * in + j]')
    # Existing comment claims column lookup, when GGML storage has contiguous token rows.
    src=src.replace('// output = column `token` of weight, length = in (hidden)',
                    '// output = contiguous row `token` of weight, length = in (hidden)')
    return src,changed,notes


def patch_matmul(src):
    start=src.find('static void MatMul(const float* A, const float* B, float* C, int M, int K, int N)')
    end=src.find('static void VecAdd(',start+1)
    if start<0 or end<0 or src.find('static void MatMul(',start+1)>=0:
        raise ValueError('MATMUL: expected exactly one MatMul/VecAdd anchor')
    body=src[start:end]
    if CORRECT_MATMUL_MARKER in body:
        return src,False,'MATMUL=ALREADY_CORRECT'
    if OLD_MATMUL not in body or 'B + k * N + j' not in body:
        # Avoid stomping local optimized kernels; require independent audit.
        if ('B[k + j * K]' in body or 'B + j * K + k' in body) and 'B + k * N + j' not in body:
            return src,False,'MATMUL=ALREADY_CORRECT_NEEDS_COMPARISON'
        raise ValueError('MATMUL: unknown implementation; abort instead of replacing')
    new='''static void MatMul(const float* A, const float* B, float* C, int M, int K, int N)
{
    // RAWRXD_GGML_CONTIGUOUS_MATMUL_002: GGML B has [K,N], stride K per output.
    // Float64 summation is a diagnostic accuracy baseline, not a speed optimization.
    if (!A || !B || !C || M <= 0 || K <= 0 || N <= 0) return;
    for (int i = 0; i < M; ++i) {
        #pragma omp parallel for schedule(static) if(N >= 128)
        for (int j = 0; j < N; ++j) {
            const float* a = A + size_t(i) * K;
            const float* b = B + size_t(j) * K;
            double sum = 0.0;
            for (int k = 0; k < K; ++k)
                sum += double(a[k]) * double(b[k]);
            C[size_t(i) * N + j] = float(sum);
        }
    }
}

'''
    return src[:start]+new+src[end:],True,'MATMUL=CORRECTED'


def patch_q6(src):
    start=src.rfind('case ModelGenie::GGMLType::Q6_K:',0,src.find('struct Q6KBlock'))
    if start<0: raise ValueError('Q6: struct/branch not found')
    end=src.find('        default:',start)
    if end<0:raise ValueError('Q6: default anchor missing')
    body=src[start:end]
    if Q6_MARKER in body:
        return src,False,'Q6_K=ALREADY_CORRECT'
    if 'int8_t scales[16]' in body:
        # Do not rewrite local fixed Q6 kernels without evidence.
        return src,False,'Q6_K=SIGNED_SCALES_PRESENT_REVIEW_DECODE'
    if 'uint16_t scales[8]' not in body:
        raise ValueError('Q6: unknown format, refusing rewrite')
    new='''case ModelGenie::GGMLType::Q6_K:
        {
            // RAWRXD_Q6_SIGNED_SCALES_002: identical layout to ggml block_q6_K.
            struct Q6KBlock { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; };
            static_assert(sizeof(Q6KBlock)==210, "Q6_K block ABI");
            const auto* src = reinterpret_cast<const Q6KBlock*>(tv.data);
            const size_t blocks = tv.bytes / sizeof(Q6KBlock);
            if (tv.elementCount != blocks * 256u) { throw std::runtime_error("Q6_K size mismatch"); }
            for (size_t b = 0; b < blocks; ++b) {
                const float d = FP16ToFloat(src[b].d);
                for (size_t half=0; half<2; ++half) {
                    const uint8_t* ql=src[b].ql+64*half;
                    const uint8_t* qh=src[b].qh+32*half;
                    const int8_t* sc=src[b].scales+8*half;
                    float* dst=out.data()+b*256+128*half;
                    for (size_t l=0; l<32; ++l) {
                        const size_t g=l/16;
                        dst[l] = d*float(sc[g+0]*(int((ql[l]&15)|((qh[l]&3)<<4))-32));
                        dst[l+32] = d*float(sc[g+2]*(int((ql[l+32]&15)|(((qh[l]>>2)&3)<<4))-32));
                        dst[l+64] = d*float(sc[g+4]*(int((ql[l]>>4)|(((qh[l]>>4)&3)<<4))-32));
                        dst[l+96] = d*float(sc[g+6]*(int((ql[l+32]>>4)|(((qh[l]>>6)&3)<<4))-32));
                    }
                }
            }
            break;
        }
'''
    return src[:start]+new+src[end:],True,'Q6_K=CORRECTED'


def patch_token0(src):
    src,a,x=patch_matmul(src)
    src,b,y=patch_q6(src)
    return src,a or b,[x,y]


def write_safe(path: Path, transform, apply: bool):
    original=path.read_bytes()
    decoded=original.decode('utf-8-sig')
    updated,changed,notes=transform(decoded)
    # A UTF8 BOM is retained, and line endings remain CRLF if originally CRLF.
    newline='\r\n' if b'\r\n' in original else '\n'
    if newline=='\r\n': updated=updated.replace('\r\n','\n').replace('\n','\r\n')
    output=(b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b'')+updated.encode('utf-8')
    if changed and apply:
        backup=path.with_name(path.name+'.pre_numerical_parity.bak')
        if backup.exists():
            raise ValueError('BACKUP_EXISTS: refusing destructive overwrite: '+str(backup))
        backup.write_bytes(original)
        path.write_bytes(output)
    return changed,notes


def main():
    p=argparse.ArgumentParser()
    p.add_argument('repo',type=Path)
    p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    targets=[(a.repo/'tools/rawrxd_modelgenie_ir_executor.cpp',patch_executor),
             (a.repo/'tools/rawrxd_modelgenie_token0_execution.cpp',patch_token0)]
    for path,fn in targets:
        if not path.is_file(): raise SystemExit('MISSING='+str(path))
        try:
            changed,notes=write_safe(path,fn,a.apply)
        except Exception as ex: raise SystemExit('FAIL_CLOSED '+str(ex))
        for note in notes:print(note)
        print(f'SOURCE={path.name} PENDING_CHANGE={int(changed and not a.apply)} PATCH_APPLIED={int(changed and a.apply)}')
    print('VERDICT=PATCH_APPLIED_NOT_MODEL_VERIFIED' if a.apply else 'VERDICT=PATCH_DRY_RUN_PASS')

if __name__=='__main__': main()
