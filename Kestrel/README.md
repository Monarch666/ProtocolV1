# Kestrel Protocol

Kestrel is a high-performance, secure, and compliance-ready aerospace telemetry and command protocol tailored for UAV and GCS networking.

## Security & Architectural Features
- **Compress-Then-Encrypt Pipeline**: Employs LZ4 compression immediately prior to Poly1305+ChaCha20 encryption. Ensures maximum link utilization while protecting against CRIME/BREACH vulnerabilities.
- **Deep Anti-Replay Subsystem**: Implements a 64-packet window natively bound to the 32-bit cryptographically-signed sequence/nonce counter. Defeats replay injection vulnerabilities permanently without breaking legacy wire compatibility.
- **Kestrel Legion Module**: Expands node addressing limits up to 8,192 simultaneous autonomous peers. Built cleanly atop standard Kestrel without altering core message semantics.
- **Aerospace Compliance Ready**: Implemented components mapped directly to DO-362A, DO-377A, IEC 62443-4-2, and JARUS SORA OSO#06 standards.

## Compilation Targets
Compile all endpoints cleanly utilizing GCC. Standard build targets include `simulator`, `receiver`, and `benchmark`.
```bash
make receiver
make simulator
make benchmark
make legion_test
make iec62443_test
```

## Security Testing
Run the comprehensive suite (including proxy adversarial injection mapping) via the PowerShell orchestrator:
```powershell
powershell -ExecutionPolicy Bypass -File testing\final_validation.ps1
```
