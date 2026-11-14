"""Isolate FFN_DOWN_2 row 624: host float32 vs alt accumulates. PROMOTE=0."""
import os
import struct

import numpy as np
from gguf import GGUFReader

os.chdir(r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001")

QK, BS = 256, 144
ROW = 624


def f16_to_f32(u16: int) -> float:
    return float(np.array([np.uint16(u16)], dtype=np.uint16).view(np.float16)[0])


def nearest_int_q8k(x: float) -> int:
    val = np.float32(x) + np.float32(12582912.0)
    bits = int(np.array([val], dtype=np.float32).view(np.uint32)[0])
    return int(bits & 0x007FFFFF) - 0x00400000


def quantize_row_q8_K(x: np.ndarray):
    nblk = len(x) // QK
    yd = np.zeros(nblk, np.float32)
    qs = np.zeros((nblk, QK), np.int8)
    bsums = np.zeros((nblk, 16), np.int16)
    for i in range(nblk):
        blk = x[i * QK : (i + 1) * QK].astype(np.float32)
        amax = np.float32(0.0)
        maxv = np.float32(0.0)
        for j in range(QK):
            ax = np.abs(blk[j])
            if ax > amax:
                amax = ax
                maxv = blk[j]
        if amax == 0:
            continue
        iscale = np.float32(-127.0) / maxv
        yd[i] = np.float32(1.0) / iscale
        for j in range(QK):
            v = nearest_int_q8k(float(iscale * blk[j]))
            qs[i, j] = np.int8(127 if v > 127 else v)
        for j in range(16):
            bsums[i, j] = np.int16(int(qs[i, j * 16 : (j + 1) * 16].sum()))
    return yd, qs, bsums


def vec_dot(row_w: bytes, yd, qs, bsums, mode: str) -> float:
    kmask1, kmask2, kmask3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303
    nblk = len(yd)
    if mode == "f64":
        sums = [0.0] * 8
        sumf = 0.0
    else:
        sums = [np.float32(0.0)] * 8
        sumf = np.float32(0.0)
    for i in range(nblk):
        blk = row_w[i * BS : (i + 1) * BS]
        d = np.float32(f16_to_f32(blk[0] | (blk[1] << 8)))
        dmin = np.float32(f16_to_f32(blk[2] | (blk[3] << 8)))
        utmp0 = blk[4] | (blk[5] << 8) | (blk[6] << 16) | (blk[7] << 24)
        utmp1 = blk[8] | (blk[9] << 8) | (blk[10] << 16) | (blk[11] << 24)
        utmp2 = blk[12] | (blk[13] << 8) | (blk[14] << 16) | (blk[15] << 24)
        utmp3 = ((utmp2 >> 4) & kmask2) | (((utmp1 >> 6) & kmask3) << 4)
        uaux = utmp1 & kmask1
        utmp1 = (utmp2 & kmask2) | (((utmp0 >> 6) & kmask3) << 4)
        utmp2 = uaux
        utmp0 &= kmask1
        scales = [
            utmp0 & 0xFF,
            (utmp0 >> 8) & 0xFF,
            (utmp0 >> 16) & 0xFF,
            (utmp0 >> 24) & 0xFF,
            utmp1 & 0xFF,
            (utmp1 >> 8) & 0xFF,
            (utmp1 >> 16) & 0xFF,
            (utmp1 >> 24) & 0xFF,
        ]
        mins = [
            utmp2 & 0xFF,
            (utmp2 >> 8) & 0xFF,
            (utmp2 >> 16) & 0xFF,
            (utmp2 >> 24) & 0xFF,
            utmp3 & 0xFF,
            (utmp3 >> 8) & 0xFF,
            (utmp3 >> 16) & 0xFF,
            (utmp3 >> 24) & 0xFF,
        ]
        q4 = blk[16:]
        aux8 = np.zeros(256, np.int32)
        a = 0
        for j in range(4):
            qo = j * 32
            for l in range(32):
                aux8[a + l] = q4[qo + l] & 15
            a += 32
            for l in range(32):
                aux8[a + l] = q4[qo + l] >> 4
            a += 32
        sumi = 0
        for j in range(16):
            sumi += int(bsums[i, j]) * int(mins[j // 2])
        aux32 = [0] * 8
        qi = 0
        ai = 0
        for j in range(8):
            scale = int(scales[j])
            for _r in range(4):
                aux16 = [0] * 8
                for l in range(8):
                    aux16[l] = int(np.int16(int(qs[i, qi + l]) * int(aux8[ai + l])))
                for l in range(8):
                    aux32[l] += scale * aux16[l]
                qi += 8
                ai += 8
        dw = np.float32(d * yd[i])
        dm = np.float32(dmin * yd[i])
        if mode == "host":
            for l in range(8):
                sums[l] = np.float32(sums[l] + dw * np.float32(aux32[l]))
            sumf = np.float32(sumf - dm * np.float32(sumi))
        elif mode == "fused":
            for l in range(8):
                sums[l] = np.float32(sums[l] + np.float32(dw * float(aux32[l])))
            sumf = np.float32(sumf - np.float32(dm * float(sumi)))
        elif mode == "kahan":
            # Kahan on lane adds
            c = [np.float32(0.0)] * 8
            for l in range(8):
                y = np.float32(dw * np.float32(aux32[l]) - c[l])
                t = np.float32(sums[l] + y)
                c[l] = np.float32((t - sums[l]) - y)
                sums[l] = t
            sumf = np.float32(sumf - dm * np.float32(sumi))
        elif mode == "f64":
            for l in range(8):
                sums[l] = sums[l] + float(dw) * float(aux32[l])
            sumf = sumf - float(dm) * float(sumi)
        elif mode == "single":
            block = np.float32(0.0)
            for l in range(8):
                block = np.float32(block + dw * np.float32(aux32[l]))
            sumf = np.float32(sumf + block)
            sumf = np.float32(sumf - dm * np.float32(sumi))
            continue
        else:
            raise ValueError(mode)
    if mode != "single":
        if mode == "f64":
            for l in range(8):
                sumf = sumf + sums[l]
            return float(np.float32(sumf))
        for l in range(8):
            sumf = np.float32(sumf + sums[l])
    return float(sumf)


def main():
    act = np.fromfile(
        "stage_dump_ffn_down_2_q6spv/deep2_FFN_ACT_2_pos0_layer0_full_n5632_seq054.bin",
        dtype=np.float32,
    )
    deep = np.fromfile(
        "stage_dump_ffn_down_2_q6spv/deep2_FFN_DOWN_2_pos0_layer0_full_n2048_seq055.bin",
        dtype=np.float32,
    )
    ref = np.fromfile(
        "stage_dump_gpu_ref/llama_FFN_DOWN_2_pos0_layer0_full_n2048_seq289.bin",
        dtype=np.float32,
    )
    r = GGUFReader(r"G:\~dev\rawrxd\models\tinyllama.gguf")
    t = next(x for x in r.tensors if x.name == "blk.2.ffn_down.weight")
    w = bytes(t.data) if not isinstance(t.data, bytes) else t.data
    # gguf may give ndarray
    if not isinstance(w, (bytes, bytearray)):
        w = np.ascontiguousarray(t.data).tobytes()
    rows, cols = 2048, 5632
    assert len(w) == rows * (cols // 256) * BS
    yd, qs, bsums = quantize_row_q8_K(act)
    row_w = w[ROW * (cols // 256) * BS : (ROW + 1) * (cols // 256) * BS]
    print(f"ROW={ROW} deep={deep[ROW]:.8f} ref={ref[ROW]:.8f}")
    for mode in ("host", "fused", "kahan", "f64", "single"):
        y = vec_dot(row_w, yd, qs, bsums, mode)
        bits = np.asarray(np.float32(y)).view(np.uint32).item()
        db = np.asarray(np.float32(deep[ROW])).view(np.uint32).item()
        rb = np.asarray(np.float32(ref[ROW])).view(np.uint32).item()
        print(
            f"  {mode:6s} y={y:.8f} bits={bits:08X} "
            f"|y-deep|={abs(y-deep[ROW]):.6e} |y-ref|={abs(y-ref[ROW]):.6e} "
            f"ulp_deep={abs(int(bits)-int(db))} ulp_ref={abs(int(bits)-int(rb))}"
        )


if __name__ == "__main__":
    main()
