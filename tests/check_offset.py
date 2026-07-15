import struct

# Check what L4_1_1_Decode reads at token 42
# From L4_1_1_Decode output, it should be at offset 0x1dc1bc83

offset = 0x1dc1bc83

with open('D:\\ministral3_q4_0.gguf', 'rb') as f:
    f.seek(offset)
    
    # Read first block (18 bytes)
    block_data = f.read(18)
    
    print(f'Data at 0x{offset:x}:')
    print(' '.join(f'{b:02x}' for b in block_data))
    
    # Parse as Q4_0 block
    scale_raw = struct.unpack('<H', block_data[0:2])[0]
    quants = block_data[2:18]
    
    # Convert FP16 to FP32
    sign = (scale_raw >> 15) & 0x1
    exp = (scale_raw >> 10) & 0x1F
    mant = scale_raw & 0x3FF
    
    if exp == 0:
        scale = mant / 1024.0 * 0.00006103515625
    else:
        scale = (1.0 + mant / 1024.0) * (2 ** (exp - 15))
    
    print(f'\nScale: 0x{scale_raw:04x} = {scale}')
    print(f'Quants: {" ".join(f"{b:02x}" for b in quants)}')
    
    # Dequantize first 8 values
    print('\nFirst 8 dequantized values:')
    for i in range(4):
        byte = quants[i]
        low = (byte & 0x0F) - 8
        high = ((byte >> 4) & 0x0F) - 8
        print(f'  [{i*2}]: {low} * {scale} = {low * scale}')
        print(f'  [{i*2+1}]: {high} * {scale} = {high * scale}')
