#!/usr/bin/env python3
"""
PCIe Lane Starvation Beacon Mapper
===================================
Probes PCIe topology, detects lane allocation conflicts,
and streams state via unidirectional UDP beacons (ping-ping).

Protocol: Beaconism v1 — no HTTP, no TCP, no response expected.
Each beacon is a 64-byte packet: 16B header + 48B payload.

Usage:
  python pcie_beacon_mapper.py [--listen PORT] [--target HOST:PORT]
  
  --listen PORT    : Run in listener mode (passive, never responds)
  --target HOST:PORT : Run in probe mode, beacon to target
  --interval MS    : Beacon interval in milliseconds (default: 1000)
"""

import sys
import os
import json
import time
import struct
import socket
import threading
import subprocess
import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Tuple

# ============================================================================
# Beacon Protocol Constants
# ============================================================================
BEACON_MAGIC = 0x50434945  # "PCIE" in ASCII
BEACON_VERSION = 1
BEACON_HEADER_FMT = "!IIII"  # magic, version, seq, flags
BEACON_PAYLOAD_FMT = "IIIIQQ"  # node_id, gpu_count, lane_width, starved_mask, timestamp_ns, vram_total (no byte-order prefix)
BEACON_TOTAL_FMT = "!IIIIIIIIQQ"  # Combined: magic, version, seq, flags, node_id, gpu_count, lane_width, starved_mask, timestamp_ns, vram_total
BEACON_SIZE = struct.calcsize(BEACON_TOTAL_FMT)  # 48 bytes

# Beacon flags
FLAG_STARVED = 0x00000001
FLAG_PHANTOM = 0x00000002
FLAG_LANE_CONFLICT = 0x00000004
FLAG_SINGLE_GPU = 0x00000008

# Known AMD PCI device IDs
AMD_VENDOR = 0x1002
KNOWN_GPUS = {
    0x7551: "AMD Radeon AI PRO R9700",
    0x747E: "AMD Radeon RX 7800 XT",
    0x164E: "AMD Radeon(TM) Graphics (Integrated)",
}

KNOWN_PCIE_SWITCHES = {
    0x1478: "AMD PCI Express Upstream Switch Port",
    0x1479: "AMD PCI Express Downstream Switch Port",
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class PCIeDevice:
    """Represents a PCIe device discovered on the bus."""
    name: str
    device_id: str
    vendor_id: int = 0
    device_code: int = 0
    status: str = "Unknown"
    pnp_class: str = ""
    is_gpu: bool = False
    is_switch: bool = False
    is_storage: bool = False
    lane_width: int = 0  # Detected lane width (0 = unknown)
    expected_lanes: int = 0  # What the device expects
    starved: bool = False  # True if device has fewer lanes than expected


@dataclass
class PCIeTopology:
    """Complete PCIe topology snapshot."""
    timestamp: float = 0.0
    devices: List[PCIeDevice] = field(default_factory=list)
    gpu_count: int = 0
    phantom_gpus: List[str] = field(default_factory=list)
    starved_devices: List[str] = field(default_factory=list)
    lane_conflicts: List[str] = field(default_factory=list)
    total_vram_gb: float = 0.0
    flags: int = 0

    def to_beacon_payload(self, node_id: int, sequence: int) -> bytes:
        """Encode topology state into a 48-byte beacon packet."""
        starved_mask = 0
        for i, dev in enumerate(self.devices):
            if dev.starved and i < 32:
                starved_mask |= (1 << i)

        flags = self.flags
        if self.phantom_gpus:
            flags |= FLAG_PHANTOM
        if self.starved_devices:
            flags |= FLAG_STARVED
        if self.lane_conflicts:
            flags |= FLAG_LANE_CONFLICT
        if self.gpu_count < 2:
            flags |= FLAG_SINGLE_GPU

        return struct.pack(BEACON_TOTAL_FMT,
            BEACON_MAGIC, BEACON_VERSION, sequence, flags,
            node_id & 0xFFFFFFFF,
            self.gpu_count,
            max((d.lane_width for d in self.devices if d.is_gpu), default=0),
            starved_mask,
            int(time.time_ns()),
            int(self.total_vram_gb * 1024))  # VRAM in MB


# ============================================================================
# PCIe Probing (Windows WMI)
# ============================================================================

def probe_powershell(script: str) -> str:
    """Run a PowerShell script and return stdout."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def probe_pcie_topology_wmi() -> PCIeTopology:
    """Probe PCIe topology using Windows WMI."""
    topo = PCIeTopology()
    topo.timestamp = time.time()

    # Get all AMD PCI devices
    ps_script = '''
    Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.DeviceID -match "PCI\\\\\\\\VEN_1002" -or
        $_.PNPClass -eq "Display"
    } | Select-Object Name, DeviceID, Status, PNPClass, Service |
      ConvertTo-Json -Compress
    '''
    output = probe_powershell(ps_script)

    devices_data = []
    try:
        parsed = json.loads(output)
        if isinstance(parsed, dict):
            devices_data = [parsed]
        elif isinstance(parsed, list):
            devices_data = parsed
    except json.JSONDecodeError:
        pass

    for d in devices_data:
        name = d.get("Name", "") or ""
        device_id = d.get("DeviceID", "") or ""
        status = d.get("Status", "") or ""
        pnp_class = d.get("PNPClass", "") or ""

        dev = PCIeDevice(
            name=name,
            device_id=device_id,
            status=status,
            pnp_class=pnp_class,
        )

        # Parse vendor/device IDs from PCI path
        ven_match = re.search(r"VEN_([0-9A-Fa-f]+)", device_id)
        dev_match = re.search(r"DEV_([0-9A-Fa-f]+)", device_id)
        if ven_match:
            dev.vendor_id = int(ven_match.group(1), 16)
        if dev_match:
            dev.device_code = int(dev_match.group(1), 16)

        # Classify device
        code = dev.device_code
        if code in KNOWN_GPUS:
            dev.is_gpu = True
            dev.expected_lanes = 16  # x16 slot
            topo.gpu_count += 1
        elif code in KNOWN_PCIE_SWITCHES:
            dev.is_switch = True
        elif name and ("NVMe" in name or "RAID" in name or "M.2" in name):
            dev.is_storage = True

        topo.devices.append(dev)

    # Detect phantom GPUs (devices expected but not on bus)
    # The 7800 XT (DEV_747E) should be present
    has_7800xt = any(d.device_code == 0x747E for d in topo.devices)
    if not has_7800xt:
        topo.phantom_gpus.append("AMD Radeon RX 7800 XT (DEV_747E) — not on PCI bus")

    # Detect lane conflicts
    # If we have PCIe switches but only 1 GPU, lanes are being diverted
    switch_count = sum(1 for d in topo.devices if d.is_switch)
    if switch_count >= 2 and topo.gpu_count < 2:
        topo.lane_conflicts.append(
            f"PCIe switch topology detected ({switch_count} switches) "
            f"but only {topo.gpu_count} GPU(s) active — "
            f"lanes likely diverted to M.2 RAID"
        )

    # Mark starved devices
    for dev in topo.devices:
        if dev.is_gpu and dev.status != "OK":
            dev.starved = True
            topo.starved_devices.append(dev.name)

    # Get VRAM info
    vram_script = '''
    Get-CimInstance Win32_VideoController | Where-Object {
        $_.Name -match "AMD|Radeon"
    } | Select-Object Name, @{N='VRAM_GB';E={[math]::Round($_.AdapterRAM/1GB,2)}} |
      ConvertTo-Json -Compress
    '''
    vram_output = probe_powershell(vram_script)
    try:
        vram_data = json.loads(vram_output)
        if isinstance(vram_data, dict):
            vram_data = [vram_data]
        for v in vram_data:
            topo.total_vram_gb += float(v.get("VRAM_GB", 0))
    except (json.JSONDecodeError, ValueError):
        pass

    return topo


# ============================================================================
# Beacon Transmitter (Ping-Ping)
# ============================================================================

class BeaconTransmitter:
    """Unidirectional beacon transmitter — sends, never receives."""

    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 9999,
                 node_id: int = 0xCAFEBABE, interval_ms: int = 1000):
        self.target = (target_host, target_port)
        self.node_id = node_id
        self.interval = interval_ms / 1000.0
        self.sequence = 0
        self.running = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.thread = None

    def send_beacon(self, topology: PCIeTopology):
        """Encode and send a single beacon pulse — no response expected."""
        packet = topology.to_beacon_payload(self.node_id, self.sequence)
        try:
            self.sock.sendto(packet, self.target)
            self.sequence += 1
        except Exception:
            pass  # Fire and forget — true ping-ping

    def _loop(self):
        """Main beacon loop — pure unidirectional stream."""
        while self.running:
            try:
                topo = probe_pcie_topology_wmi()
                self.send_beacon(topo)

                # Also print human-readable summary
                status = "SINGLE" if topo.gpu_count < 2 else "DUAL"
                starved = "STARVED" if topo.starved_devices else "OK"
                phantom = "PHANTOM" if topo.phantom_gpus else "OK"
                print(f"[BEACON] #{self.sequence} | "
                      f"GPUs: {topo.gpu_count} | "
                      f"VRAM: {topo.total_vram_gb:.0f}GB | "
                      f"Status: {status}/{starved}/{phantom} | "
                      f"Flags: 0x{topo.flags:08X}")

                if topo.phantom_gpus:
                    for p in topo.phantom_gpus:
                        print(f"  ⚠ PHANTOM: {p}")
                if topo.lane_conflicts:
                    for c in topo.lane_conflicts:
                        print(f"  ⚠ CONFLICT: {c}")
                if topo.starved_devices:
                    for s in topo.starved_devices:
                        print(f"  ⚠ STARVED: {s}")

            except Exception as e:
                print(f"[BEACON] Error: {e}")

            time.sleep(self.interval)

    def start(self):
        """Start beaconing in background thread."""
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        print(f"[BEACON] Transmitter started → {self.target[0]}:{self.target[1]}")
        print(f"[BEACON] Protocol: Ping-Ping (unidirectional, no response)")

    def stop(self):
        """Stop beaconing."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self.sock.close()
        print("[BEACON] Transmitter stopped")


# ============================================================================
# Beacon Listener (Passive — Never Responds)
# ============================================================================

class BeaconListener:
    """Passive beacon listener — receives, never responds."""

    def __init__(self, listen_port: int = 9999):
        self.port = listen_port
        self.running = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", listen_port))
        self.thread = None
        self.last_beacon: Optional[Tuple[int, PCIeTopology]] = None

    def _listen(self):
        """Passive listen loop — never sends data."""
        print(f"[LISTENER] Passive beacon receiver on port {self.port}")
        print(f"[LISTENER] Protocol: Receive-only (no ACK, no response)")
        print(f"[LISTENER] Waiting for PCIe topology beacons...\n")

        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                if len(data) < BEACON_SIZE:
                    continue

                # Parse header + payload
                magic, version, seq, flags, node_id, gpu_count, lane_width, starved_mask, ts_ns, vram_mb = \
                    struct.unpack(BEACON_TOTAL_FMT, data[:BEACON_SIZE])

                ts_s = ts_ns / 1_000_000_000
                vram_gb = vram_mb / 1024

                # Decode flags
                status_parts = []
                if flags & FLAG_SINGLE_GPU:
                    status_parts.append("SINGLE-GPU")
                if flags & FLAG_STARVED:
                    status_parts.append("STARVED")
                if flags & FLAG_PHANTOM:
                    status_parts.append("PHANTOM")
                if flags & FLAG_LANE_CONFLICT:
                    status_parts.append("LANE-CONFLICT")

                status_str = "/".join(status_parts) if status_parts else "NOMINAL"

                print(f"[BEACON] From {addr[0]}:{addr[1]} | "
                      f"Seq: {seq} | Node: 0x{node_id:08X} | "
                      f"GPUs: {gpu_count} | VRAM: {vram_gb:.0f}GB | "
                      f"LaneWidth: x{lane_width} | "
                      f"Status: {status_str} | "
                      f"Time: {ts_s:.3f}")

                # Decode starved device mask
                if starved_mask:
                    starved_list = []
                    for i in range(32):
                        if starved_mask & (1 << i):
                            starved_list.append(f"Device#{i}")
                    print(f"  ⚠ Starved devices: {', '.join(starved_list)}")

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[LISTENER] Error: {e}")

    def start(self):
        """Start listening in background thread."""
        self.running = True
        self.sock.settimeout(1.0)
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop listening."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self.sock.close()
        print("[LISTENER] Listener stopped")


# ============================================================================
# CLI Entry Point
# ============================================================================

def print_topology(topo: PCIeTopology):
    """Print a human-readable topology summary."""
    print("\n" + "=" * 60)
    print("PCIe LANE STARVATION TOPOLOGY REPORT")
    print("=" * 60)
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(topo.timestamp))}")
    print(f"GPUs detected: {topo.gpu_count}")
    print(f"Total VRAM: {topo.total_vram_gb:.0f} GB")
    print(f"Devices on bus: {len(topo.devices)}")
    print()

    for dev in topo.devices:
        role = ""
        if dev.is_gpu:
            role = " [GPU]"
        elif dev.is_switch:
            role = " [SWITCH]"
        elif dev.is_storage:
            role = " [STORAGE]"

        status_icon = "✅" if dev.status == "OK" else "❌"
        starved_mark = " ⚠ STARVED" if dev.starved else ""
        print(f"  {status_icon} {dev.name}{role}{starved_mark}")
        print(f"     DeviceID: {dev.device_id}")
        print(f"     Status: {dev.status}")

    if topo.phantom_gpus:
        print(f"\n⚠ PHANTOM DEVICES (expected but not on bus):")
        for p in topo.phantom_gpus:
            print(f"  ❌ {p}")

    if topo.lane_conflicts:
        print(f"\n⚠ LANE CONFLICTS:")
        for c in topo.lane_conflicts:
            print(f"  ⚠ {c}")

    if topo.starved_devices:
        print(f"\n⚠ STARVED DEVICES:")
        for s in topo.starved_devices:
            print(f"  ⚠ {s}")

    print("=" * 60)
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="PCIe Lane Starvation Beacon Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single probe (one-shot topology dump)
  python pcie_beacon_mapper.py --probe

  # Beacon transmitter (streams topology via UDP)
  python pcie_beacon_mapper.py --target 127.0.0.1:9999

  # Passive listener (receives beacons, never responds)
  python pcie_beacon_mapper.py --listen 9999

  # Probe + beacon simultaneously
  python pcie_beacon_mapper.py --probe --target 127.0.0.1:9999
        """
    )

    parser.add_argument("--probe", action="store_true",
                       help="One-shot topology probe and print")
    parser.add_argument("--target", type=str, default=None,
                       help="Beacon target HOST:PORT (e.g. 127.0.0.1:9999)")
    parser.add_argument("--listen", type=int, default=None,
                       help="Passive listen port")
    parser.add_argument("--interval", type=int, default=1000,
                       help="Beacon interval in ms (default: 1000)")
    parser.add_argument("--node-id", type=lambda x: int(x, 0), default=0xCAFEBABE,
                       help="Node identifier hex (default: 0xCAFEBABE)")

    args = parser.parse_args()

    # If no mode specified, default to probe
    if not args.probe and not args.target and not args.listen:
        args.probe = True

    # Probe mode
    if args.probe:
        print("Probing PCIe topology...")
        topo = probe_pcie_topology_wmi()
        print_topology(topo)

    # Listener mode
    listener = None
    if args.listen:
        listener = BeaconListener(listen_port=args.listen)
        listener.start()

    # Transmitter mode
    transmitter = None
    if args.target:
        host, port_str = args.target.split(":")
        port = int(port_str)
        transmitter = BeaconTransmitter(
            target_host=host,
            target_port=port,
            node_id=args.node_id,
            interval_ms=args.interval,
        )
        transmitter.start()

    # If only transmitter, keep main thread alive
    if transmitter and not listener:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[MAIN] Shutting down...")
            transmitter.stop()

    # If listener only, keep alive
    if listener and not transmitter:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[MAIN] Shutting down...")
            listener.stop()

    # If both, keep alive
    if listener and transmitter:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[MAIN] Shutting down...")
            transmitter.stop()
            listener.stop()


if __name__ == "__main__":
    main()
