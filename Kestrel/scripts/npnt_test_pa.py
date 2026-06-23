#!/usr/bin/env python3
"""
DGCA NPNT Test Permission Artifact Signer — Kestrel Protocol
Generates a binary test PA (signed with DGCA private seed) for UAV NPNT validation.

The PA is pre-configured for the UAV simulator's default GPS location (Seattle, WA)
with a 1-hour validity window from current system time.

Usage:
    python npnt_test_pa.py                  # Uses keys/dgca_priv_seed.bin
    python npnt_test_pa.py --lat 476700000 --lon -1223200000 --radius 5000
"""

import struct
import time
import sys
import os
import argparse

def main():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("ERROR: 'cryptography' package not found.  pip install cryptography")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Generate signed DGCA NPNT Permission Artifact")
    parser.add_argument("--lat",    type=int, default=47670000,   help="Geofence centre lat  (deg x 1e7, default: Seattle UAV sim)")
    parser.add_argument("--lon",    type=int, default=-122320000, help="Geofence centre lon  (deg x 1e7)")
    parser.add_argument("--radius", type=int, default=2000,       help="Geofence radius (metres, default 2000)")
    parser.add_argument("--window", type=int, default=3600,       help="Validity window in seconds (default: 3600 = 1 hour)")
    parser.add_argument("--seed",   default="keys/dgca_priv_seed.bin", help="Path to DGCA private seed file")
    parser.add_argument("--out",    default="keys/test_pa.bin",   help="Output file for raw 82-byte PA blob")
    args = parser.parse_args()

    # Load DGCA private seed
    if not os.path.exists(args.seed):
        print(f"ERROR: DGCA private seed not found at '{args.seed}'")
        print("  Run  scripts/dgca_keygen.py  first.")
        sys.exit(1)

    with open(args.seed, "rb") as f:
        seed = f.read()
    assert len(seed) == 32, "Seed must be 32 bytes"

    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    # Build time window
    now        = int(time.time())
    valid_from  = now - 60          # valid since 60s ago (clock skew tolerance)
    valid_until = now + args.window

    # Build the signed body: [valid_from(4) | valid_until(4) | lat(4) | lon(4) | radius(2)] = 18 bytes
    body = struct.pack("<IIiiH",
                       valid_from, valid_until,
                       args.lat, args.lon,
                       args.radius)
    assert len(body) == 18

    # Hash with BLAKE2b-512 (matches UAV: crypto_blake2b(h, 64, body, 18))
    import hashlib
    h = hashlib.blake2b(body, digest_size=64).digest()

    # Ed25519 sign the BLAKE2b hash
    signature = private_key.sign(h)   # 64 bytes
    assert len(signature) == 64

    # Assemble ks_npnt_pa_t wire layout (82 bytes):
    # [0..63]  signature
    # [64..67] valid_from  (uint32 LE)
    # [68..71] valid_until (uint32 LE)
    # [72..75] center_lat  (int32  LE)
    # [76..79] center_lon  (int32  LE)
    # [80..81] radius_m    (uint16 LE)
    pa_blob = signature + struct.pack("<IIiiH",
                                      valid_from, valid_until,
                                      args.lat, args.lon,
                                      args.radius)
    assert len(pa_blob) == 82

    with open(args.out, "wb") as f:
        f.write(pa_blob)

    print("=" * 62)
    print("  DGCA NPNT Test Permission Artifact Generated")
    print("=" * 62)
    print(f"  Output:        {args.out}  (82 bytes)")
    print(f"  valid_from:    {valid_from}  ({time.ctime(valid_from)})")
    print(f"  valid_until:   {valid_until}  ({time.ctime(valid_until)})")
    print(f"  Geofence:      lat={args.lat/1e7:.5f} lon={args.lon/1e7:.5f} r={args.radius}m")
    print()
    print("  In GCS interactive menu, press 'N' to send this PA to the UAV.")
    print("  UAV will verify signature, time window, and geofence, then")
    print("  set g_npnt_validated=true — ARM commands will then be accepted.")
    print("=" * 62)

if __name__ == "__main__":
    main()
