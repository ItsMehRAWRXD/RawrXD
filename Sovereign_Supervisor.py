import mmap
import time
import subprocess
import os

# Sovereign Constants
APERTURE_ADDR = 0x20000000  # Must be accessed via a persistent mapped file
SOVEREIGN_BIN = "d:\\rawrxd\\Sovereign.exe"

class SovereignSupervisor:
    def __init__(self):
        self.process = None

    def ignite(self):
        print("IGNITING SOVEREIGN SUBSTRATE (1M-Order Soak)...")
        self.process = subprocess.Popen([SOVEREIGN_BIN, "--mode=soak", "--iterations=1000000", "--aperture=0x70000000"])

    def monitor(self):
        # Open the telemetry aperture file (created by the Kernel)
        # Ensure the file exists (create it if missing so mmap doesn't fail before kernel writes)
        telemetry_path = "d:\\rawrxd\\telemetry.bin"
        if not os.path.exists(telemetry_path):
            with open(telemetry_path, "wb") as f:
                f.write(b'\x00' * 4096)

        with open(telemetry_path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), 1024)
            
            while self.process.poll() is None:
                # Read Sentinel at offset 0
                sentinel = int.from_bytes(mm[0:4], byteorder='little')
                
                if sentinel == 0xDEADBEEF:
                    print(" PANIC DETECTED (0xDEADBEEF)! Extracting Flight Data...")
                    # Extract RIP (offset 4) and RSP (offset 12)
                    rip = int.from_bytes(mm[4:12], byteorder='little')
                    rsp = int.from_bytes(mm[12:20], byteorder='little')
                    
                    dump_msg = f"[SOVEREIGN REPLAY] Panic Dump - RIP: 0x{rip:016X} | RSP: 0x{rsp:016X}\n"
                    print(dump_msg)
                    
                    with open("d:\\rawrxd\\panic_dump.log", "a") as log:
                        log.write(dump_msg)
                    
                    print(" Triggering Recovery Sequence...")
                    self.process.terminate()
                    time.sleep(0.1)  # Brief stabilize
                    self.ignite() # Auto-Restart
                
                time.sleep(1/60)
        
        print(f" Substrate Exited with Return Code: {self.process.returncode}")

if __name__ == "__main__":
    sup = SovereignSupervisor()
    sup.ignite()
    sup.monitor()
