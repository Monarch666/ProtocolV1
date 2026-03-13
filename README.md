# UAVLink Protocol
UAVLink is a lightweight secure protocol for UAV telemetry and command/control over unreliable links.

## Highlights
- ChaCha20-Poly1305 AEAD packet protection
- X25519 ECDH session key exchange with authenticated handshake
- Replay protection and nonce persistence
- Compact binary framing with stream parsing
- Telemetry + command + ACK transport in one protocol
- Mission payload fragmentation/reassembly support

## Repository Scope
This repository is intentionally kept focused on core protocol implementation.

Tracked core components:
- Protocol/uavlink.h
- Protocol/uavlink.c
- Protocol/uavlink_fast.h
- Protocol/uavlink_fast.c
- Protocol/uavlink_compress.h
- Protocol/uavlink_compress.c
- Protocol/uavlink_hw_crypto.h
- Protocol/uavlink_hw_crypto.c
- Protocol/uavlink_keymanager.h
- Protocol/uavlink_keymanager.c
- Protocol/monocypher.h
- Protocol/monocypher.c
- Protocol/gcs_receiver.c
- Protocol/uav_simulator.c
- Protocol/uavlink_benchmark.c
- Protocol/Makefile

Non-core local artifacts (testing, documentation builds, helper scripts, local keys, logs) are excluded from GitHub through .gitignore.

## Build
From repository root:

```powershell
cd Protocol
mingw32-make
```

Generated binaries:
- uav_simulator.exe
- gcs_receiver.exe
- uavlink_benchmark.exe

## Manual Run (Single Machine)
Use two terminals in Protocol/:

Terminal 1:
```powershell
.\uav_simulator.exe
```

Terminal 2:
```powershell
.\gcs_receiver.exe 127.0.0.1
```

## Soak Automation Mode
For internal automatic command cycling inside GCS:

```powershell
.\gcs_receiver.exe --auto-soak
```

## Notes
- Default localhost ports:
  - 14552 (UAV to GCS telemetry/ACK)
  - 14553 (GCS to UAV commands)
- If bind errors occur, stop stale processes using those ports before rerun.
 for `size_t` type ✅

2. **Issue:** Missing `sys/stat.h` include in `key_example.c`
   - **Resolution:** Added conditional include for Unix `chmod()` ✅

3. **Issue:** Benchmark used hardcoded test key
   - **Resolution:** Updated to load from file or generate deterministic key ✅

**All issues resolved - no remaining bugs.**

### Deployment Readiness

**Production Readiness Checklist:**

- ✅ **Key Management:** Secure generation and storage system implemented
- ✅ **Debugging Tools:** Wireshark dissector for traffic analysis
- ✅ **Security Hardening:** No hardcoded keys, secure memory handling
- ✅ **Documentation:** Comprehensive guides for key management and Wireshark
- ✅ **Testing:** All components validated and working
- ⚠️ **Hardware Testing:** Still requires testing on actual UAV hardware
- ⚠️ **Flight Testing:** Needs validation during actual flights
- ⚠️ **Soak Testing:** 24-48 hour continuous operation recommended

**Recommendation:** Protocol is ready for **development/research UAV deployments**. Commercial deployment should include additional hardware-in-the-loop testing and flight validation.

---

## License

This project includes:

- **UAVLink Protocol:** MIT License
- **Monocypher:** Dual-licensed BSD-2-Clause OR CC0-1.0 (public domain)

See LICENSE file for details.

---

## References

- [ChaCha20-IETF Specification (RFC 8439)](https://tools.ietf.org/html/rfc8439)
- [Monocypher Library](https://monocypher.org/)
- [MAVLink Protocol](https://mavlink.io/) - Inspiration for UAV messaging
- [IEEE 802.15.4](https://standards.ieee.org/standard/802_15_4-2020.html) - Wireless sensor networks

---

## Contact & Support

- **Repository:** https://github.com/Monarch666/ProtocolV1
- **Issues:** https://github.com/Monarch666/ProtocolV1/issues
- **Discussions:** https://github.com/Monarch666/ProtocolV1/discussions

---
