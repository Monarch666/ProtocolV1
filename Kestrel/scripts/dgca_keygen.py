#!/usr/bin/env python3
"""
DGCA NPNT Ed25519 Authority Key Generator — Kestrel Protocol
Generates a test DGCA key pair for India NPNT compliance testing.
Saves the 32-byte raw public key to keys/dgca_pub.bin (loaded by UAV at startup).
Saves the 32-byte seed to keys/dgca_priv_seed.bin (used to sign Permission Artifacts).

Usage:
    python dgca_keygen.py
"""

import secrets
import sys
import os

def main():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        print("ERROR: 'cryptography' package not found.")
        print("Install it with:  pip install cryptography")
        sys.exit(1)

    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)

    # Generate cryptographically secure 32-byte seed
    seed = secrets.token_bytes(32)

    # Derive Ed25519 key pair (RFC 8032 — compatible with monocypher)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key  = private_key.public_key()
    pub_bytes   = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes

    assert len(pub_bytes) == 32, "Ed25519 public key must be 32 bytes"
    assert len(seed)      == 32, "Seed must be 32 bytes"

    pub_path  = os.path.join(keys_dir, "dgca_pub.bin")
    priv_path = os.path.join(keys_dir, "dgca_priv_seed.bin")

    with open(pub_path,  "wb") as f:
        f.write(pub_bytes)
    with open(priv_path, "wb") as f:
        f.write(seed)

    print("=" * 62)
    print("  DGCA NPNT Ed25519 Key Pair Generated")
    print("=" * 62)
    print(f"  Public key  -> {pub_path}  ({len(pub_bytes)} bytes)")
    print(f"  Private seed-> {priv_path} ({len(seed)} bytes)")
    print(f"  Public key (hex): {pub_bytes.hex()}")
    print()
    print("  UAV will load dgca_pub.bin at startup -> g_npnt_enabled = true")
    print("  Use npnt_test_pa.py to sign a Permission Artifact for testing.")
    print()
    print("  [!] Keep dgca_priv_seed.bin SECRET — it authorises NPNT arming!")
    print("=" * 62)

if __name__ == "__main__":
    main()
