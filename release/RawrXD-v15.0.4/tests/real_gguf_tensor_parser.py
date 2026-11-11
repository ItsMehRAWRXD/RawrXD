"""
Real GGUF Tensor Parser
Extracts actual tensor data from validated GGUF file.
"""

import struct
import numpy as np
import sys
import os

class GGUFValueType:
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12

class GGMLType:
    F32 = 0
    F16 = 1
    Q4_0 = 2
    Q4_1 = 3
    Q5_0 = 6
    Q5_1 = 7
    Q8_0 = 8
    Q8_1 = 9

class GGUFParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.file = None
        self.version = None
        self.tensor_count = 0
        self.metadata_count = 0
        self.metadata = {}
        self.tensors = []
        self.tensor_data_offset = 0
        
    def open(self):
        """Open and validate GGUF file"""
        self.file = open(self.filepath, 'rb')
        
        # Read magic
        magic = self.file.read(4)
        if magic != b'GGUF':
            raise ValueError(f"Invalid magic: {magic}")
            
        # Read version
        self.version = struct.unpack('<I', self.file.read(4))[0]
        print(f"GGUF Version: {self.version}")
        
        # Read counts
        self.tensor_count = struct.unpack('<Q', self.file.read(8))[0]
        self.metadata_count = struct.unpack('<Q', self.file.read(8))[0]
        print(f"Tensors: {self.tensor_count}, Metadata: {self.metadata_count}")
        
        return True
        
    def read_string(self):
        """Read a GGUF string"""
        length = struct.unpack('<Q', self.file.read(8))[0]
        return self.file.read(length).decode('utf-8')
        
    def read_metadata_value(self, vtype):
        """Read a metadata value based on type"""
        if vtype == GGUFValueType.UINT32:
            return struct.unpack('<I', self.file.read(4))[0]
        elif vtype == GGUFValueType.INT32:
            return struct.unpack('<i', self.file.read(4))[0]
        elif vtype == GGUFValueType.FLOAT32:
            return struct.unpack('<f', self.file.read(4))[0]
        elif vtype == GGUFValueType.UINT64:
            return struct.unpack('<Q', self.file.read(8))[0]
        elif vtype == GGUFValueType.INT64:
            return struct.unpack('<q', self.file.read(8))[0]
        elif vtype == GGUFValueType.FLOAT64:
            return struct.unpack('<d', self.file.read(8))[0]
        elif vtype == GGUFValueType.BOOL:
            return struct.unpack('<?', self.file.read(1))[0]
        elif vtype == GGUFValueType.STRING:
            return self.read_string()
        elif vtype == GGUFValueType.ARRAY:
            # Read array type and length
            arr_type = struct.unpack('<I', self.file.read(4))[0]
            arr_len = struct.unpack('<Q', self.file.read(8))[0]
            arr = []
            for _ in range(arr_len):
                arr.append(self.read_metadata_value(arr_type))
            return arr
        else:
            raise ValueError(f"Unknown value type: {vtype}")
            
    def parse_metadata(self):
        """Parse all metadata key-value pairs"""
        print("\nParsing metadata...")
        for i in range(self.metadata_count):
            key = self.read_string()
            vtype = struct.unpack('<I', self.file.read(4))[0]
            value = self.read_metadata_value(vtype)
            self.metadata[key] = value
            if i < 10:  # Print first 10
                print(f"  {key}: {value}")
        print(f"  ... and {self.metadata_count - 10} more")
        
    def parse_tensor_info(self):
        """Parse tensor information (name, dimensions, type, offset)"""
        print("\nParsing tensor info...")
        for i in range(self.tensor_count):
            name = self.read_string()
            n_dims = struct.unpack('<I', self.file.read(4))[0]
            dims = []
            for _ in range(n_dims):
                dims.append(struct.unpack('<Q', self.file.read(8))[0])
            
            ggml_type = struct.unpack('<I', self.file.read(4))[0]
            offset = struct.unpack('<Q', self.file.read(8))[0]
            
            self.tensors.append({
                'name': name,
                'dims': dims,
                'type': ggml_type,
                'offset': offset
            })
            
            if i < 5:  # Print first 5
                print(f"  {name}: {dims}, type={ggml_type}, offset={offset}")
        print(f"  ... and {self.tensor_count - 5} more")
        
    def find_tensor_offset(self):
        """Calculate where tensor data begins"""
        # Tensor data starts after all tensor info
        # We've already read past metadata and tensor info
        self.tensor_data_offset = self.file.tell()
        # Align to 32 bytes
        self.tensor_data_offset = (self.tensor_data_offset + 31) & ~31
        print(f"\nTensor data starts at offset: {self.tensor_data_offset}")
        
    def get_tensor(self, name):
        """Get tensor data by name"""
        for tensor in self.tensors:
            if tensor['name'] == name:
                return tensor
        return None
        
    def read_tensor_data_sample(self, tensor, sample_size=1000):
        """Read a sample of tensor data from file"""
        name = tensor['name']
        dims = tensor['dims']
        ggml_type = tensor['type']
        offset = tensor['offset']
        
        # Calculate total size
        num_elements = 1
        for d in dims:
            num_elements *= d
            
        # Limit to sample size
        read_elements = min(sample_size, num_elements)
        
        # Calculate bytes based on type
        if ggml_type == GGMLType.F32:
            bytes_per_element = 4
            dtype = np.float32
            data_size = read_elements * bytes_per_element
            self.file.seek(self.tensor_data_offset + offset)
            raw_data = self.file.read(data_size)
            arr = np.frombuffer(raw_data, dtype=dtype)
            return arr
            
        elif ggml_type == GGMLType.F16:
            bytes_per_element = 2
            dtype = np.float16
            data_size = read_elements * bytes_per_element
            self.file.seek(self.tensor_data_offset + offset)
            raw_data = self.file.read(data_size)
            arr = np.frombuffer(raw_data, dtype=dtype)
            return arr.astype(np.float32)
            
        elif ggml_type == GGMLType.Q8_0:
            # Q8_0: block_q8_0 { delta (f16); q (QK8_0 bytes); }
            block_size = 32
            num_blocks = (read_elements + block_size - 1) // block_size
            data_size = num_blocks * 34
            
            self.file.seek(self.tensor_data_offset + offset)
            raw_data = self.file.read(data_size)
            
            return self.dequantize_q8_0_sample(raw_data, read_elements)
            
        elif ggml_type == GGMLType.Q4_0:
            # Q4_0: block_q4_0 { delta (f16); q (QK4_0/2 bytes); }
            block_size = 32
            num_blocks = (read_elements + block_size - 1) // block_size
            data_size = num_blocks * 18
            
            self.file.seek(self.tensor_data_offset + offset)
            raw_data = self.file.read(data_size)
            
            return self.dequantize_q4_0_sample(raw_data, read_elements)
        else:
            raise ValueError(f"Unsupported GGML type: {ggml_type}")
        
    def dequantize_q8_0(self, raw_data, num_elements, dims):
        """Dequantize Q8_0 data to FP32"""
        block_size = 32
        num_blocks = (num_elements + block_size - 1) // block_size
        
        result = np.zeros(num_elements, dtype=np.float32)
        
        for b in range(num_blocks):
            block_offset = b * 34
            # Read delta (f16)
            delta_bytes = raw_data[block_offset:block_offset+2]
            delta = np.frombuffer(delta_bytes, dtype=np.float16)[0]
            
            # Read quantized values
            q_offset = block_offset + 2
            q = np.frombuffer(raw_data[q_offset:q_offset+32], dtype=np.int8)
            
            # Dequantize
            start_idx = b * block_size
            end_idx = min(start_idx + block_size, num_elements)
            for i in range(end_idx - start_idx):
                result[start_idx + i] = q[i] * delta
                
        return result.reshape(dims)
        
    def dequantize_q4_0(self, raw_data, num_elements, dims):
        """Dequantize Q4_0 data to FP32"""
        block_size = 32
        num_blocks = (num_elements + block_size - 1) // block_size
        
        result = np.zeros(num_elements, dtype=np.float32)
        
        for b in range(num_blocks):
            block_offset = b * 18
            # Read delta (f16)
            delta_bytes = raw_data[block_offset:block_offset+2]
            delta = np.frombuffer(delta_bytes, dtype=np.float16)[0]
            
            # Read quantized values (16 bytes = 32 nibbles)
            q_offset = block_offset + 2
            q_bytes = raw_data[q_offset:q_offset+16]
            
            # Dequantize
            start_idx = b * block_size
            end_idx = min(start_idx + block_size, num_elements)
            for i in range(end_idx - start_idx):
                byte_idx = i // 2
                nibble = i % 2
                if nibble == 0:
                    q = q_bytes[byte_idx] & 0x0F
                else:
                    q = (q_bytes[byte_idx] >> 4) & 0x0F
                # Convert to signed and dequantize
                q_signed = q - 8  # 0-15 -> -8 to +7
                result[start_idx + i] = q_signed * delta
                
        return result.reshape(dims)

    def dequantize_q8_0_sample(self, raw_data, num_elements):
        """Dequantize Q8_0 data sample to FP32"""
        block_size = 32
        num_blocks = (num_elements + block_size - 1) // block_size
        result = np.zeros(num_elements, dtype=np.float32)

        for b in range(num_blocks):
            block_offset = b * 34
            delta_bytes = raw_data[block_offset:block_offset+2]
            delta = np.frombuffer(delta_bytes, dtype=np.float16)[0]
            q_offset = block_offset + 2
            q = np.frombuffer(raw_data[q_offset:q_offset+32], dtype=np.int8)
            start_idx = b * block_size
            end_idx = min(start_idx + block_size, num_elements)
            for i in range(end_idx - start_idx):
                result[start_idx + i] = q[i] * delta
        return result

    def dequantize_q4_0_sample(self, raw_data, num_elements):
        """Dequantize Q4_0 data sample to FP32"""
        block_size = 32
        num_blocks = (num_elements + block_size - 1) // block_size
        result = np.zeros(num_elements, dtype=np.float32)

        for b in range(num_blocks):
            block_offset = b * 18
            delta_bytes = raw_data[block_offset:block_offset+2]
            delta = np.frombuffer(delta_bytes, dtype=np.float16)[0]
            q_offset = block_offset + 2
            q_bytes = raw_data[q_offset:q_offset+16]
            start_idx = b * block_size
            end_idx = min(start_idx + block_size, num_elements)
            for i in range(end_idx - start_idx):
                byte_idx = i // 2
                nibble = i % 2
                if nibble == 0:
                    q = q_bytes[byte_idx] & 0x0F
                else:
                    q = (q_bytes[byte_idx] >> 4) & 0x0F
                q_signed = q - 8
                result[start_idx + i] = q_signed * delta
        return result

    def close(self):
        """Close the file"""
        if self.file:
            self.file.close()
            self.file = None


def main():
    model_path = r'D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf'
    
    if not os.path.exists(model_path):
        print(f"Model not found: {model_path}")
        sys.exit(1)
        
    print(f"Real GGUF Tensor Parser")
    print(f"File: {model_path}")
    print(f"Size: {os.path.getsize(model_path) / (1024*1024):.2f} MB\n")
    
    parser = GGUFParser(model_path)
    
    try:
        # Open and parse
        parser.open()
        parser.parse_metadata()
        parser.parse_tensor_info()
        parser.find_tensor_offset()
        
        # Try to find and read embedding tensor
        print("\n" + "="*60)
        print("TENSOR EXTRACTION")
        print("="*60)
        
        # Look for token_embd.weight or similar
        target_tensors = ['token_embd.weight', 'tok_embeddings.weight', 'embed_tokens.weight']
        found = False
        
        for target in target_tensors:
            tensor = parser.get_tensor(target)
            if tensor:
                print(f"\nFound: {target}")
                print(f"  Dimensions: {tensor['dims']}")
                print(f"  Type: {tensor['type']} (Q8_0={GGMLType.Q8_0}, F32={GGMLType.F32})")
                print(f"  Offset: {tensor['offset']}")
                
                # Read just a sample of the data (first 1000 elements)
                print("\n  Reading tensor data sample...")
                data = parser.read_tensor_data_sample(tensor, sample_size=1000)
                print(f"  Full Shape: {tensor['dims']}")
                print(f"  Sample Shape: {data.shape}")
                print(f"  Dtype: {data.dtype}")
                print(f"  First 5 values: {data[:5]}")
                print(f"  Sample Checksum: {np.sum(data):.4f}")
                print(f"  Finite: {np.all(np.isfinite(data))}")
                print(f"  Non-zero: {np.any(data != 0)}")
                
                found = True
                break
                
        if not found:
            print("\nEmbedding tensor not found. Available tensors:")
            for t in parser.tensors[:10]:
                print(f"  {t['name']}")
            print(f"  ... and {len(parser.tensors) - 10} more")
            
        print("\n" + "="*60)
        print("Result: SUCCESS" if found else "Result: TENSOR NOT FOUND")
        print("="*60)
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        parser.close()


if __name__ == "__main__":
    main()
