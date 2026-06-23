#!/usr/bin/env python3
import sys

def validate_ts(filename):
    print(f"=================================================================")
    print(f"  STANAG 4609 / MISB ST 0601 — MPEG-TS Validator")
    print(f"  Validating: {filename}")
    print(f"=================================================================\n")

    pids_found = set()
    packet_count = 0
    klv_packets = 0
    video_packets = 0

    try:
        with open(filename, 'rb') as f:
            while True:
                packet = f.read(188)
                if not packet:
                    break
                if len(packet) != 188:
                    break
                if packet[0] != 0x47:
                    print(f"Warning: Discovered packet without sync byte at index {packet_count}")
                    continue
                
                packet_count += 1
                pid = ((packet[1] & 0x1F) << 8) | packet[2]
                pids_found.add(pid)
                
                if pid == 256:
                    video_packets += 1
                elif pid == 257:
                    klv_packets += 1

    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        sys.exit(1)

    print(f"  ── Stream Statistics ───────────────────────────────────")
    print(f"  Total TS Packets       : {packet_count}")
    print(f"  Unique PIDs Found      : {sorted(list(pids_found))}")
    
    print(f"\n  ── Compliance Gates ────────────────────────────────────")
    
    # Check PAT
    pat_ok = 0 in pids_found
    print(f"  PAT (PID 0) Present    : {'PASS ✓' if pat_ok else 'FAIL ✗'}")
    
    # Check PMT
    pmt_ok = 4096 in pids_found
    print(f"  PMT (PID 4096) Present : {'PASS ✓' if pmt_ok else 'FAIL ✗'}")
    
    # Check Video
    video_ok = 256 in pids_found and video_packets > 0
    print(f"  H.264 Video (PID 256)  : {'PASS ✓' if video_ok else 'FAIL ✗'} ({video_packets} pkts)")
    
    # Check KLV
    klv_ok = 257 in pids_found and klv_packets > 0
    print(f"  KLV Metadata (PID 257) : {'PASS ✓' if klv_ok else 'FAIL ✗'} ({klv_packets} pkts)")
    print(f"")
    
    if pat_ok and pmt_ok and video_ok and klv_ok:
        print("  ALL COMPLIANCE GATES PASSED")
        sys.exit(0)
    else:
        print("  COMPLIANCE GATES FAILED")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python validate_ts.py <file.ts>")
        sys.exit(1)
    validate_ts(sys.argv[1])
