# UAVLink Protocol

UAVLink is a compact, secure, binary protocol for UAV telemetry and command/control links.
It is designed for real-time operation on constrained links and embedded hardware where packet
size, deterministic behavior, and operational robustness are critical.

## 1) What This Protocol Is

UAVLink is an application-layer protocol with the following goals:

- Carry telemetry, commands, and acknowledgements in one coherent message model.
- Protect confidentiality and integrity using ChaCha20-Poly1305 AEAD.
- Establish session keys dynamically using authenticated X25519 ECDH handshake.
- Resist replay through sequence-window tracking and nonce state persistence.
- Support large mission payload transfer through fragmentation and reassembly.
- Keep framing compact and stream-parseable for UART/UDP style transport loops.

This repository contains a working GCS and UAV simulator implementation using UDP
transport, plus protocol library code and performance/optimization modules.

## 2) Core Capabilities

- AEAD encryption and authentication (ChaCha20-Poly1305, 128-bit tag).
- X25519 session key negotiation with identity signatures and ACK confirmation.
- Replay protection using sliding sequence window in parser.
- Priority and stream classification for traffic shaping.
- Message serialization/deserialization for telemetry and control domains.
- Fragment split/reassembly for larger mission payloads.
- Optional compression/optimization modules for bandwidth reduction.
- Optional hardware crypto path modules for embedded acceleration scenarios.

## 3) Protocol Structure

The protocol frame consists of:

1. Base header (4 bytes, bit-packed fields)
2. Extended header (variable, includes routing/message metadata)
3. Payload (plain or encrypted)
4. CRC

Important constants from implementation:

- SOF: 0xA5
- Max parser payload buffer: 512 bytes
- AEAD MAC tag: 16 bytes

### 3.1 Base Header Semantics

The 4-byte base header packs:

- Payload length (12-bit)
- Priority (2-bit)
- Stream type (4-bit)
- Flags: encrypted, fragmented
- Sequence high bits

### 3.2 Extended Header Semantics

`ul_header_t` carries:

- source system/component ID
- target system ID
- message ID
- fragment index and total (if fragmented)
- nonce bytes (for encrypted packets)

This gives explicit routing and message typing while preserving compact base framing.

## 4) Message Model

Implemented message IDs include:

- HEARTBEAT
- ATTITUDE
- GPS_RAW
- BATTERY
- RC_INPUT
- CMD
- CMD_ACK
- MODE_CHANGE
- MISSION_ITEM
- KEY_EXCHANGE
- KEY_EXCHANGE_ACK
- BATCH

Implemented command IDs include:

- ARM
- DISARM
- TAKEOFF
- LAND
- RTL
- EMERGENCY

ACK result model includes accepted, rejected, unsupported, failed, and in-progress states.

## 5) How It Works End-to-End

### 5.1 Session Bootstrap

1. GCS and UAV load identity material and initialize parser/nonce/crypto contexts.
2. ECDH key exchange messages are transmitted with sequence tracking.
3. Signature checks validate peer identity.
4. Shared session key is derived and handshake ACK completes establishment.
5. Both sides transition to established state and begin encrypted command/telem flow.

### 5.2 Runtime Data Flow

- UAV sends telemetry streams (heartbeat, attitude, GPS, battery, etc.) to GCS.
- GCS sends command/control messages to UAV.
- UAV applies command/state transitions and returns command ACK.
- Parser enforces frame integrity, optional decryption, and replay checks.

### 5.3 Command and Mode Handling

- CMD messages are deserialized as command payload and processed by UAV command handler.
- MODE_CHANGE messages are handled in dedicated mode-change path.
- State transitions directly affect heartbeat armed/mode reporting.

### 5.4 Mission Fragmentation

- Large mission payloads are split into fragments.
- Receiver reassembles by fragment index/total with timeout management.
- Completed mission payload is parsed and stored.

## 6) Repository Layout (Core)

Core protocol and runtime implementation:

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

Non-core local artifacts (testing scripts, docs build files, local keys, local logs,
wireshark helpers) are intentionally excluded from GitHub by .gitignore policy.

## 7) Build and Run

From repository root:

```powershell
cd Protocol
mingw32-make
```

Generated binaries:

- uav_simulator.exe
- gcs_receiver.exe
- uavlink_benchmark.exe

Manual local run (single machine):

Terminal 1:

```powershell
.\uav_simulator.exe
```

Terminal 2:

```powershell
.\gcs_receiver.exe 127.0.0.1
```

Internal soak automation mode (GCS-side scheduler):

```powershell
.\gcs_receiver.exe --auto-soak
```

Default localhost UDP ports:

- 14552: UAV -> GCS telemetry and ACK path
- 14553: GCS -> UAV command path

## 8) Testing Performed

The project has been validated through functional, endurance, and fault-injection styles
of testing in local and interactive setups.

### 8.1 Functional Protocol Tests

- Handshake establishment correctness (key exchange + ACK completion)
- Command execution and ACK return path
- Mode-change path verification
- Heartbeat status/state coherence with armed + mode transitions
- Mission fragment reassembly and mission ACK path

### 8.2 Endurance and Stability Tests

- Quick demo stability checks
- Short stability runs
- Extended soak operation
- Internal auto-soak command cycling in GCS without window-injection dependencies

Observed validation snapshots during development included long-run windows with
continuous packet exchange and zero parser error accumulation on healthy runs.

### 8.3 Adversarial/Resilience-Oriented Workflows

- Replay and nonce safety behavior validation through nonce persistence model
- Packet impairment workflow support (loss/delay style scenarios)
- Fuzz-oriented parser stress tooling support in local testing assets

## 9) Recent Important Updates

Major updates integrated in the current state:

1. Command-path correctness fix in UAV runtime:
  - CMD now handled as command payload
  - MODE_CHANGE handled in dedicated message case
  - resolves heartbeat state inconsistency caused by mis-typed message parsing

2. Internal soak automation in GCS:
  - `--auto-soak` mode schedules command cycle inside GCS runtime
  - removes dependence on external key-injection/focus automation for soak tests

3. Repository hygiene and publish policy:
  - single root README policy
  - testing/docs/auxiliary/local key artifacts excluded from GitHub
  - core protocol repository footprint made cleaner and more professional

4. Encryption policy adjustment:
  - attitude stream encryption policy set to optional to align runtime behavior

## 10) Known Operational Considerations

- Port bind errors indicate stale owners on UDP ports 14552/14553.
- If bind fails, terminate stale processes and restart clean.
- Monitor scripts/windows can remain open even if child exe exits on bind error; always trust
  the executable error output first.

## 11) Intended Use

This codebase is intended as a practical secure UAV link reference implementation and
engineering baseline for further research, benchmarking, and controlled field integration.
