import struct

# Check first block at token 42
TENSOR_OFFSET = 0x1d405000
TOKEN_ID = 42
ROW_SIZE = 2304

row_offset = TENSOR_OFFSET + (TOKEN_ID * ROW_SIZE)

with open('D:\\ministral3_q4_0.gguf', 'rb') as f:
    f.seek(row_offset)
    
    # Read first block
    scale_bytes = f.read(2)
    quants = f.read(16)
    
    scale_raw = struct.unpack('<H', scale_bytes)[0]
    
    # Convert FP16 to FP32
    sign = (scale_raw >> 15) & 0x1
    exp = (scale_raw >> 10) & 0x1F
    mant = scale_raw & 0x3FF
    
    if exp == 0:
        scale = mant / 1024.0 * 0.00006103515625
    else:
        scale = (1.0 + mant / 1024.0) * (2 ** (exp - 15))
    
    print(f'Block 0 at token 42:')
    print(f'  Raw scale: 0x{scale_raw:04x}')
    print(f'  Scale: {scale}')
    print(f'  Quants: {" ".join(f"{b:02x}" for b in quants)}')
    
    # Dequantize first few values
    print(f'\n  Dequantized values:')
    for i in range(4):
        byte = quants[i]
        low = (byte & 0x0F) - 8
        high = ((byte >> 4) & 0x0F) - 8
        print(f'    [{i*2}]: {low} * {scale} = {low * scale}')
        print(f'    [{i*2+1}]: {high} * {scale} = {high * scale}')
