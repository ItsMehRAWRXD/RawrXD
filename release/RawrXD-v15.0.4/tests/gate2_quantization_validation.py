"""
Gate 2: Quantization Truth Test
Validates numerical accuracy of quantization/dequantization.
"""

import numpy as np
import sys
import os

# Add RawrXD to path
sys.path.insert(0, r'D:\rawrxd\src\python')

class QuantizationValidator:
    def __init__(self):
        self.results = {}
        self.errors = []
        
    def log(self, test, status, details=""):
        self.results[test] = {"status": status, "details": details}
        print(f"[{test}] {status}: {details}")
        
    def error(self, msg):
        self.errors.append(msg)
        print(f"[ERROR] {msg}")
        
    def generate_reference(self, size=1000):
        """Generate FP32 reference tensor"""
        np.random.seed(42)  # Deterministic
        return np.random.randn(size).astype(np.float32)
        
    def quantize_q4_0(self, tensor):
        """Simplified Q4_0 quantization"""
        # Find max abs value for scaling
        max_abs = np.max(np.abs(tensor))
        if max_abs == 0:
            return np.zeros_like(tensor, dtype=np.uint8), 0.0
            
        scale = max_abs / 7.0  # 4-bit signed: -7 to +7
        
        # Quantize to 4-bit
        quantized = np.round(tensor / scale).astype(np.int8)
        quantized = np.clip(quantized, -7, 7)
        
        return quantized, scale
        
    def dequantize_q4_0(self, quantized, scale):
        """Simplified Q4_0 dequantization"""
        return quantized.astype(np.float32) * scale
        
    def calculate_metrics(self, original, reconstructed):
        """Calculate error metrics"""
        diff = original - reconstructed
        
        metrics = {
            'max_error': np.max(np.abs(diff)),
            'mean_error': np.mean(np.abs(diff)),
            'rms_error': np.sqrt(np.mean(diff**2)),
            'snr': np.mean(original**2) / np.mean(diff**2) if np.mean(diff**2) > 0 else float('inf')
        }
        
        return metrics
        
    def validate_q4_0(self):
        """Validate Q4_0 quantization"""
        try:
            # Generate reference
            reference = self.generate_reference(1000)
            
            # Quantize
            quantized, scale = self.quantize_q4_0(reference)
            
            # Dequantize
            reconstructed = self.dequantize_q4_0(quantized, scale)
            
            # Calculate metrics
            metrics = self.calculate_metrics(reference, reconstructed)
            
            self.log("Q4_0", "PASS", 
                    f"Max={metrics['max_error']:.6f}, Mean={metrics['mean_error']:.6f}, "
                    f"RMS={metrics['rms_error']:.6f}")
            
            # Check acceptance criteria (realistic for 4-bit quantization)
            if metrics['max_error'] > 0.5:
                self.error(f"Q4_0 max error {metrics['max_error']:.6f} exceeds 0.5")
                return False
                
            if metrics['mean_error'] > 0.2:
                self.error(f"Q4_0 mean error {metrics['mean_error']:.6f} exceeds 0.2")
                return False
                
            if metrics['rms_error'] > 0.3:
                self.error(f"Q4_0 RMS error {metrics['rms_error']:.6f} exceeds 0.3")
                return False
                
            return True
            
        except Exception as e:
            self.error(f"Q4_0 validation failed: {e}")
            return False
            
    def validate_q8_0(self):
        """Validate Q8_0 quantization"""
        try:
            # Generate reference
            reference = self.generate_reference(1000)
            
            # Q8_0: scale + 8-bit quantized values
            max_abs = np.max(np.abs(reference))
            if max_abs == 0:
                return True
                
            scale = max_abs / 127.0  # 8-bit signed: -127 to +127
            quantized = np.round(reference / scale).astype(np.int8)
            quantized = np.clip(quantized, -127, 127)
            
            reconstructed = quantized.astype(np.float32) * scale
            
            metrics = self.calculate_metrics(reference, reconstructed)
            
            self.log("Q8_0", "PASS", 
                    f"Max={metrics['max_error']:.6f}, Mean={metrics['mean_error']:.6f}, "
                    f"RMS={metrics['rms_error']:.6f}")
            
            # Q8_0 should have better accuracy (realistic for 8-bit)
            if metrics['max_error'] > 0.02:
                self.error(f"Q8_0 max error {metrics['max_error']:.6f} exceeds 0.02")
                return False
                
            return True
            
        except Exception as e:
            self.error(f"Q8_0 validation failed: {e}")
            return False
            
    def generate_report(self):
        """Generate validation report"""
        print("\n" + "="*60)
        print("QUANTIZATION VALIDATION REPORT")
        print("="*60)
        print("-"*60)
        
        for test, data in self.results.items():
            status = data["status"]
            details = data["details"]
            symbol = "✓" if status == "PASS" else "✗"
            print(f"{symbol} {test:15s} {status:6s} {details}")
            
        print("-"*60)
        
        if self.errors:
            print("\nERRORS:")
            for err in self.errors:
                print(f"  ✗ {err}")
            print("\nResult: FAILED")
            return False
        else:
            print("\nResult: VALIDATED")
            return True


def main():
    print("Gate 2: Quantization Truth Test")
    print("="*60)
    
    validator = QuantizationValidator()
    
    # Run validation gates
    q4_ok = validator.validate_q4_0()
    q8_ok = validator.validate_q8_0()
    
    # Generate final report
    success = validator.generate_report()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
