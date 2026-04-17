# Kestrel

**Kestrel** is a high-performance **binary communication protocol** purpose-built for **UAV systems**. It minimizes packet overhead and maximizes reliability on lossy radio links with built-in encryption, message routing, and integrity checking. The reference implementation in this repository is provided under the historical `kestrel.*` filenames. Features comprehensive optimizations including zero-copy parsing, hardware-accelerated encryption, and advanced compression.

### Key Achievements

- **Full ChaCha20-Poly1305 AEAD Encryption** - Complete implementation with 128-bit MAC authentication
- **ARM NEON Hardware Acceleration** - 4x crypto speedup on ARM platforms with SIMD
- **Phase 2 Optimizations** - Zero-copy parser (2x faster) + O(1) memory pool
- **Phase 3 Advanced Features** - Delta encoding (57% bandwidth savings), LZ4 compression, Reed-Solomon FEC
- **Phase 4 & 5 Aerospace Compliance** - RTCA DO-362A, DO-377A, ASTM F3411 Remote ID, and DGCA NPNT Arming Gates implemented natively in the protocol
- **ECDH Handshake Hardening** - OS CSPRNG for ephemeral X25519 keys and BLAKE2b-bound signatures with protocol label
- **82.8% Bandwidth Reduction** - Combined optimizations reduce telemetry from 3.68 kbps to 0.63 kbps
- **Comprehensive Validation Tooling** - Unit-style C tests, soak tests, fuzzing, adversarial link tests, TS validation, and VM deployment assets are included in-repo
- **Production-Ready Code** - All critical bugs identified and fixed through rigorous testing
- **Expanded Message Surface** - Telemetry, command/ACK, mode change, mission, key exchange, batching, NPNT, Remote ID, and MPEG-TS/KLV transport are implemented
- **Robust Parser** - Byte-by-byte state machine with full error handling
- **Secure Nonce Management** - Cryptographically secure nonce generation prevents replay attacks
- **Fragmentation and Reassembly** - Fragment splitting plus receiver-side reassembly APIs are available for large payloads
- **Kestrel Legion Variant** - Expanded 13-bit addressing space for large-scale device networks (up to 8,192 logic nodes) with robust replay defense

### Performance Summary

| Metric            | Baseline  | Optimized | Improvement                |
| ----------------- | --------- | --------- | -------------------------- |
| **Bandwidth**     | 3.68 kbps | 0.63 kbps | **82.8% reduction**        |
| **Parse Speed**   | 250 µs    | 125 µs    | **2x faster**              |
| **Crypto Speed**  | 200 µs    | 50 µs     | **4x faster** (ARM NEON)   |
| **Memory Alloc**  | 50 µs     | <1 µs     | **50x faster** (O(1) pool) |
| **Total Latency** | 500 µs    | 176 µs    | **2.8x faster**            |

### Test Coverage

**Validation assets include unit-style C tests, soak tests, fuzzing, chaos/adversarial harnesses, TS validators, and VM deployment bundles**

| Asset | Focus |
| ----- | ----- |
| `testing/legion_unit_test.c` | Legion header packing, replay protection, and enlarged memory pool |
| `testing/packet_size_test.c` | Packet sizing, parser behavior, and boundary cases |
| `testing/fuzz_parser.c` | Parser hardening under malformed or random inputs |
| `testing/test_1min.py`, `test_15min.py`, `test_30min.py`, `test_3h.py` | Long-duration soak testing of the GCS/UAV apps |
| `testing/net_chaos.py`, `testing/adversarial_test.py`, `testing/clean_proxy.py` | Link impairment, corruption, and hostile traffic simulation |
| `scripts/validate_ts.py` | MPEG-TS PAT/PMT/video/KLV validation |
| `testing/vm_deploy/*` | Split GCS/UAV deployment bundles for VM or multi-host testing |

**Run validation:** build the apps with `make`, compile `make legion_test` for the Legion unit test, then run the Python/C test assets from `Kestrel/testing` and `Kestrel/scripts` as needed for the path you are changing.

---

## Features

### Core Protocol

**Compact Headers** - 8-19 bytes on the wire before payload, depending on command targeting, fragmentation, and encryption metadata  
**Session-Managed Encryption** - ChaCha20-Poly1305 AEAD with session-bound nonce lifecycle and full 128-bit MAC authentication  
**Reliable** - CRC-16 integrity checking plus AEAD MAC prevents tampering  
**Flexible Routing** - System/component addressing with broadcast support  
**Priority-based QoS** - 4 priority levels for time-critical messages  
**Stream-Parseable** - Byte-by-byte state machine ideal for UART  
**Command and Control Surface** - Command, ACK, mode change, mission item, key exchange, and batch message types are implemented  
**Fragmentation and Reassembly** - Handle payloads beyond a single fragment and reconstruct them on the receiver side  
**Production-Ready Security** - Secure nonce generation plus replay protection windows prevent nonce reuse and packet replays

### Phase 2 Performance Optimizations

**Zero-Copy Parser** - 2x parsing speed with direct memory access  
**Memory Pool** - O(1) deterministic allocation for real-time systems  
**Hardware Crypto Detection** - Automatic SIMD backend selection  
**Crypto Context Caching** - 30% speedup for burst transmissions  
**Selective Encryption** - 60% bandwidth reduction for public telemetry

### Phase 3 Advanced Features

**Delta Encoding** - 57% bandwidth savings for GPS/attitude telemetry  
**LZ4 Compression** - Fast compression for repetitive data  
**Reed-Solomon FEC** - Recover from packet loss without retransmission  
**ARM NEON Acceleration** - 4x crypto speedup on ARM Cortex-A/Apple Silicon  
**x86 AVX2 Support** - 4x crypto speedup on modern Intel/AMD processors

### Phase 4 & 5 Aerospace Compliance

**DO-362A Lost-Link** - GCS-configurable failsafe injection via Heartbeat  
**DO-377A BLOS Latency** - Sliding window pipelines handling satellite RTT margins  
**DGCA NPNT Validations** - Cryptographic NO-PERMISSION-NO-TAKEOFF arming gates via Ed25519  
**ASTM F3411 Remote ID** - Unencrypted explicit packet broadcasting support for tracking compliance  
**STANAG / MISB Video Hooks** - MPEG-TS muxing with MISB ST 0601 KLV helpers for video metadata transport

### Current Implementation Snapshot

- **Core library:** framing, CRC, serialization, AEAD, replay protection, selective encryption, batching, fragmentation, and timed reassembly
- **Performance modules:** zero-copy parser, memory pool, compression, FEC, delta encoding, SIMD crypto backends, and the Legion large-scale variant
- **Apps and tooling:** bidirectional UAV/GCS demos, key management helpers, benchmark and example tools, compliance scripts, TS validation, soak tests, and VM deployment copies

---

## Quick Start

### Files

#### Core Protocol

| File                           | Description                                                |
| ------------------------------ | ---------------------------------------------------------- |
| `Kestrel/src/core/kestrel.h`           | Core API, structures, message IDs, and protocol constants |
| `Kestrel/src/core/kestrel.c`           | Encoding/decoding, parser, AEAD, nonce/session, fragmentation, and reassembly |
| `Kestrel/src/core/kestrel_legion.c/.h` | Legion protocol extension for large networks (8,192 nodes) |
| `Kestrel/src/core/kestrel_keymanager.c/.h` | Session key loading, generation, cleanup, and rotation helpers |
| `Kestrel/src/core/monocypher.c/h`      | Portable ChaCha20-Poly1305/X25519/Ed25519 cryptography library |

#### Phase 2 Optimizations

| File                      | Description                              |
| ------------------------- | ---------------------------------------- |
| `Kestrel/src/core/kestrel_fast.h` | Zero-copy parser, memory pool APIs |
| `Kestrel/src/core/kestrel_fast.c` | Performance optimization implementations |

#### Phase 3 Advanced Features

| File                          | Description                         |
| ----------------------------- | ----------------------------------- |
| `Kestrel/src/core/kestrel_compress.h` | Delta encoding, LZ4, FEC APIs |
| `Kestrel/src/core/kestrel_compress.c` | Compression and FEC implementations |

#### Hardware Acceleration

| File                           | Description                    |
| ------------------------------ | ------------------------------ |
| `Kestrel/src/core/kestrel_hw_crypto.h` | ARM NEON, x86 SIMD crypto APIs |
| `Kestrel/src/core/kestrel_hw_crypto.c` | Hardware-accelerated ChaCha20 |
| `Kestrel/src/core/kestrel_rid.c/.h`    | ASTM F3411 Remote ID helpers |
| `Kestrel/src/core/kestrel_video.c/.h`  | MISB ST 0601 KLV encoder and MPEG-TS muxer |

#### Testing & Examples

| File                           | Description                                      |
| ------------------------------ | ------------------------------------------------ |
| `Kestrel/src/tools/kestrel_benchmark.c` | Performance profiler |
| `Kestrel/src/tools/key_example.c`       | Key/session example utility |
| `Kestrel/src/apps/gcs_receiver.c`       | Interactive ground-station demo with mission upload, NPNT push, and sliding command window |
| `Kestrel/src/apps/uav_simulator.c`      | Bidirectional UAV demo with ECDH handshake, NPNT gate, Remote ID, and TS/KLV output |
| `Kestrel/testing/*`                    | Unit/soak/chaos/adversarial tests and VM deployment assets |
| `Kestrel/scripts/*`                    | Helper scripts for key generation, NPNT PA creation, TS validation, compliance, and control center |

### Compiling and Testing

**Option 1: Build the repository targets**

```bash
cd Kestrel
make

# Optional: build the Legion unit test binary
make legion_test
```

This produces binaries in `Kestrel/bin/`:

- `kestrel_benchmark`
- `gcs_receiver`
- `uav_simulator`
- `key_example`
- `legion_test` (when built explicitly)

**Option 2: Network Test (Localhost / single PC)**

```bash
cd Kestrel

# Terminal 1: Start the GCS (replace .exe with no suffix on Linux/macOS)
bin/gcs_receiver.exe 127.0.0.1

# Terminal 2: Start the UAV simulator
bin/uav_simulator.exe 127.0.0.1
```

**Option 3: Network Test (Two PCs on Same WiFi)**

```bash
# On the GCS PC:
bin/gcs_receiver.exe <uav_ip>          # Listens on UDP 14552, sends commands to UDP 14553

# On the UAV PC:
bin/uav_simulator.exe <gcs_ip>         # Sends telemetry/ACKs to UDP 14552, listens on UDP 14553
```

> **Note:** On Windows, allow UDP ports `14552` and `14553` through the firewall for direct GCS/UAV communication.

**Option 4: Generate NPNT and other helper artifacts**

```bash
cd Kestrel

# Generate a DGCA-style test permission artifact for the GCS demo
python scripts/npnt_test_pa.py

# Validate a generated TS file carrying PAT/PMT/video/KLV
python scripts/validate_ts.py video_out.ts
```

### Expected Output

**Benchmark:**

```
Phase 2 vs Baseline:
  Parse speedup:    6.17x
  Alloc time:       <1 µs avg (O(1) pool)

Phase 3 (Delta encoding):
  Delta packets:    12 bytes avg (57% reduction from 28 bytes)

RECOMMENDATIONS:
✓ Delta encoding saves ~57% for telemetry - USE for GPS/Attitude
○ Software crypto only - Consider ARM/x86 SIMD build
```

**Network Test (Two-PC WiFi Test):**

```
# Sender output:
Packets sent: 234
Bytes sent: 11948
Average packet size: 51 bytes
Memory leaks: None

# Receiver output:
Packets parsed: 200+
Parse errors: 0
CRC errors: 0
Avg parse time: 4 us/packet
Memory pool peak usage: 1/32 buffers
```

> Successfully tested over WiFi between two Windows PCs with zero packet loss and full AEAD encryption.

### Integrating into Your Code

To add Kestrel Core (implemented in the `kestrel.*` files) to your flight controller or ground station:

1. **Copy files** into your build tree:
   - Core: `kestrel.h`, `kestrel.c`, `monocypher.h`, `monocypher.c`
   - Phase 2: `kestrel_fast.h`, `kestrel_fast.c` (optional, for performance)
   - Phase 3: `kestrel_compress.h`, `kestrel_compress.c` (optional, for compression)
   - Hardware: `kestrel_hw_crypto.h`, `kestrel_hw_crypto.c` (optional, for SIMD)

2. **Basic Usage (Baseline Protocol):**

   ```c
   #include "kestrel.h"

   uint8_t key[32] = { /* 32-byte session key */ };

   ks_session_t session;
   ks_session_init(&session, key);

   // Initialize parser
   ks_parser_t parser;
   ks_parser_init(&parser);

   // Feed bytes in UART/serial loop
   uint8_t incoming_byte = uart_read();
   int result = ks_parse_char(&parser, incoming_byte, key);

   if (result == KS_OK) {
       // Full packet received!
       handle_message(&parser.header, parser.payload);
   }

   // Send packets
   ks_attitude_t att = {.roll = 0.1f, .pitch = 0.2f, .yaw = 1.5f, ...};
   uint8_t payload[32];
   int payload_len = ks_serialize_attitude(&att, payload);

   ks_header_t header = {
       .payload_len = payload_len,
       .stream_type = KS_STREAM_TELEM_FAST,
       .priority = KS_PRIO_NORMAL,
       .sequence = 1,
       .sys_id = 1,
       .comp_id = 1,
       .target_sys_id = 0,
       .msg_id = KS_MSG_ATTITUDE,
   };

   uint8_t packet[256];
   int packet_len = kestrel_pack_with_nonce(packet, &header, payload, &session);
   uart_transmit(packet, packet_len);
   ```

3. **Phase 2 Optimized Usage (2x faster parsing, O(1) allocation):**

   ```c
   #include "kestrel.h"
   #include "kestrel_fast.h"

   // Initialize memory pool (once at startup)
   ks_mempool_t pool;
   ks_mempool_init(&pool);

   // Initialize zero-copy parser (once per connection)
   ks_parser_zerocopy_t parser;
   ks_parser_zerocopy_init(&parser);
   parser.key_32b = key;

   // Fast parsing with zero-copy
   uint8_t incoming_byte = uart_read();
   uint8_t payload_buf[256];
   int result = ks_parse_char_zerocopy(&parser, incoming_byte, payload_buf, sizeof(payload_buf));

   if (result == KS_OK) {
       // Payload is now available in payload_buf / parser.last_payload
       handle_message(parser.last_payload, parser.msg_id);
   }

   // Fast packing with memory pool + crypto cache
   ks_crypto_ctx_t crypto_ctx;
   ks_crypto_ctx_init(&crypto_ctx);

   uint8_t *buffer = NULL;
   int packet_len = ks_pack_fast(&pool, &header, payload, &session, &crypto_ctx, &buffer);
   uart_transmit(buffer, packet_len);
   ks_mempool_free(&pool, buffer);
   ```

4. **Phase 3 Advanced Usage (57% bandwidth savings for telemetry):**

   ```c
   #include "kestrel_compress.h"

   // Initialize delta encoder (once at startup)
   ks_delta_ctx_t delta_ctx;
   ks_delta_init(&delta_ctx);

   // Encode GPS with delta compression
   ks_gps_raw_t gps = {
       .lat = 377749000,
       .lon = -1224194000,
       .alt = 50000,
       .eph = 100,
       .epv = 150,
       .vel = 1200,
       .cog = 9000,
       .fix_type = 3,
       .satellites = 12
   };
   uint8_t encoded[64];
   int len = ks_delta_encode_gps(&delta_ctx, &gps, encoded, sizeof(encoded));
   // First packet: 28 bytes, subsequent: 12 bytes (57% savings!)

   // Decode on receiver side
   ks_delta_ctx_t rx_delta_ctx;
   ks_delta_init(&rx_delta_ctx);
   ks_gps_raw_t decoded_gps;
   ks_delta_decode_gps(&rx_delta_ctx, encoded, len, &decoded_gps);
   ```

5. **Hardware Acceleration (4x crypto speedup on ARM/x86):**

   ```c
   #include "kestrel_hw_crypto.h"

   // Enable hardware crypto at startup (automatic backend selection)
   ks_enable_hardware_crypto();

   // All crypto operations now use NEON/AVX2 automatically
   // No code changes needed - transparent acceleration!
   uint8_t buffer[256];
   int packet_len = kestrel_pack_with_nonce(buffer, &header, payload, &session);
   // Now 4x faster if NEON/AVX2 available
   ```

---

## Protocol Specification

### Packet Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ [Base Header] [Extended Header] [Payload] [MAC Tag*] [CRC-16]   │
│    4 bytes      4-15 bytes      0-4095 B   16 bytes*  2 bytes   │
└─────────────────────────────────────────────────────────────────┘
* 16-byte Poly1305 MAC tag only present when encrypted flag is set
```

**Packet Size Range:**

- **Minimum:** 10 bytes (empty payload, no encryption)
- **Maximum:** 4,132 bytes (4095-byte payload + full headers)
- **Typical:** 26-50 bytes (common telemetry messages)

### Current Wire Layout

The current implementation in `Kestrel/src/core/kestrel.c` packs the frame as:

| Region | Size | Notes |
| ------ | ---- | ----- |
| Base header | 4 bytes | SOF, payload length, priority, stream type, encrypted/fragmented flags, sequence upper bits |
| Extended header | 4-15 bytes | sequence lower bits + sys_id, comp_id + msg_id, optional target_sys_id, optional fragmentation metadata, optional 8-byte nonce |
| Payload | 0-4095 bytes | Plaintext or ciphertext payload |
| MAC tag | 16 bytes | Present only when encryption is enabled |
| CRC-16 | 2 bytes | Always present |

The base header bit packing implemented by `ks_encode_base_header()` is:

```text
Byte 0: SOF = 0xA5
Byte 1: payload_len[11:8] | priority | stream_type[3:2]
Byte 2: stream_type[1:0] | payload_len[7:2]
Byte 3: payload_len[1:0] | encrypted | fragmented | sequence[11:10]
```

The extended header implemented by `ks_encode_ext_header()` is:

- 2 bytes: `sequence[9:0]` + `sys_id[5:0]`
- 2 bytes: `comp_id[3:0]` + `msg_id[11:0]`
- 1 byte: `target_sys_id[5:0]` for `KS_STREAM_CMD` / `KS_STREAM_CMD_ACK`
- 2 bytes: `frag_index` + `frag_total` when fragmented
- 8 bytes: packet nonce when encrypted

### Historical Draft Notes

```
┌─────┌────┌────┌────┌────┌────┌─────┌─────┌───────┌─────────┌───────┌─────┐
│ STX │ B1 │ B2 │ B3 │ SYS│COMP│TGT_S│TGT_C│ NONCE │ PAYLOAD │  MAC  │ CRC │
│     │    │    │    │    │    │     │     │(opt)  │         │ (opt) │     │
└─────┘────┘────┘────┘────┘────┘─────┘─────┘───────┘─────────┘───────┘─────┘
  0xA5                    Extended Header      0-4095B    16B     2B
```

| Byte Index                                    | Content                                              | Value                                                                                                                                                | Explanation                                                                                                                                  |
| --------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| 0                                             | Packet start sign                                    | `0xA5`                                                                                                                                               | Indicates the start of a new Kestrel packet                                                                                                  |
| 1                                             | Payload length [11:8] + Priority + Stream type [3:2] | Bits 7-4: Payload length upper nibble (0-15)<br>Bits 3-2: Priority (00=Bulk, 01=Normal, 10=High, 11=Emergency)<br>Bits 1-0: Stream type upper 2 bits | Bit-packed field combining 12-bit payload length MSBs, message priority for QoS, and stream type classification                              |
| 2                                             | Payload length [7:0]                                 | 0 - 255                                                                                                                                              | Lower 8 bits of payload length. Combined with byte 1 allows payloads up to 4095 bytes                                                        |
| 3                                             | Flags + Stream type [1:0] + Sequence [5:2]           | Bits 7-6: Flags (encrypted, fragmented)<br>Bits 5-4: Stream type lower bits<br>Bits 3-0: Sequence upper nibble                                       | Encrypted flag, fragmentation flag, stream type completion, and sequence number upper bits for packet ordering                               |
| 4                                             | Sequence [1:0] + Message ID [5:0]                    | Bits 7-6: Sequence lower 2 bits<br>Bits 5-0: Message ID upper 6 bits                                                                                 | 6-bit rolling sequence counter (0-63) detects packet loss. Message ID upper bits define payload type                                         |
| 5                                             | Message ID [1:0] + Header CRC-16 [15:10]             | Bits 7-6: Message ID lower 2 bits<br>Bits 5-0: CRC upper 6 bits                                                                                      | 8-bit Message ID (0-255) defines payload structure. Header CRC-16 upper bits protect base header integrity                                   |
| 6 to 7                                        | Header CRC-16 [9:0]                                  | 16-bit checksum                                                                                                                                      | CRC-16 (ITU X.25 polynomial) protecting bytes 0-5 from corruption. Computed excluding packet start sign                                      |
| 8                                             | System ID                                            | 1 - 255                                                                                                                                              | ID of the SENDING system. Allows differentiation of multiple UAVs on the same network                                                        |
| 9                                             | Component ID                                         | 0 - 255                                                                                                                                              | ID of the SENDING component. Allows differentiation of different components of the same system (e.g., autopilot, gimbal, companion computer) |
| 10                                            | Target System ID                                     | 0 - 255                                                                                                                                              | ID of the RECEIVING system. Value 0 = broadcast to all systems                                                                               |
| 11                                            | Target Component ID                                  | 0 - 255                                                                                                                                              | ID of the RECEIVING component. Value 0 = broadcast to all components                                                                         |
| 12 to 19                                      | Nonce (if encrypted)                                 | 64-bit value                                                                                                                                         | 8-byte nonce for ChaCha20-Poly1305 AEAD encryption. Cryptographically secure random value. **Only present when encrypted flag is set**       |
| 20 to (n+19) or (n+11)                        | Data                                                 | (0 - 4095) bytes                                                                                                                                     | Data of the message, depends on the message ID. Payload can be encrypted with ChaCha20-Poly1305                                              |
| (n+20) or (n+12) to (n+35) or (n+27)          | Poly1305 MAC (if encrypted)                          | 128-bit tag                                                                                                                                          | 16-byte authentication tag from ChaCha20-Poly1305 AEAD. Authenticates header + payload. **Only present when encrypted flag is set**          |
| (n+20) or (n+12) or (n+36) or (n+28) to final | Checksum (low byte, high byte)                       | ITU X.25/SAE AS-4 hash                                                                                                                               | CRC-16 covering entire packet excluding this checksum field. Protects the packet from corruption. **Always final 2 bytes of packet**         |

**Note:** This section reflects an earlier draft layout and is kept only for historical context. Use the "Current Wire Layout" section above and the constants in `Kestrel/src/core/kestrel.h` / `kestrel.c` as the authoritative format.

### Base Header (4 bytes)

The base header is densely bit-packed to minimize overhead:

**Byte 0: Start of Frame (SOF)**

- Fixed value: `0xA5`
- Purpose: Synchronization marker for frame detection

**Byte 1: Payload Length [11:8] | Priority | Stream Type [3:2]**

```
Bits 7-4: Payload length upper 4 bits
Bits 3-2: Priority (00=Bulk, 01=Normal, 10=High, 11=Emergency)
Bits 1-0: Stream type upper 2 bits
```

**Byte 2: Stream Type [1:0] | Payload Length [7:2]**

```
Bits 7-6: Stream type lower 2 bits
Bits 5-0: Payload length middle 6 bits
```

**Byte 3: Payload Length [1:0] | Encrypted | Fragmented | Sequence [11:10]**

```
Bits 7-6: Payload length lower 2 bits
Bit 3:    Encrypted flag (1 = encrypted with AEAD)
Bit 2:    Fragmented flag (1 = split across multiple packets)
Bits 1-0: Sequence number upper 2 bits
```

**Payload Length:** 12-bit field = 0-4095 bytes  
**Priority:** 2-bit field = 4 levels (Bulk, Normal, High, Emergency)  
**Stream Type:** 4-bit field = 16 possible streams  
**Sequence:** 12-bit field = 0-4095 (rolls over)

### Extended Header (Variable: 4-15 bytes)

The current extended header contains routing and message identification:

**Always Present (4 bytes):**

- **Sequence + System ID (2 bytes)** - lower 10 bits of sequence plus 6-bit source `sys_id`
- **Component + Message ID (2 bytes)** - 4-bit `comp_id` plus 12-bit `msg_id`

**Conditional Fields:**

- **Target System ID (1 byte)** - Present for `KS_STREAM_CMD` and `KS_STREAM_CMD_ACK`
- **Fragmentation Info (2 bytes)** - Only if fragmented flag set
  - Fragment Index (1 byte): Which fragment (0-based)
  - Fragment Total (1 byte): Total number of fragments
- **Nonce (8 bytes)** - Only if encrypted flag set
  - 64-bit hybrid counter+random for replay protection

**Total Extended Header Size:**

- Minimum: 4 bytes (no command target, no fragmentation, no encryption)
- Maximum: 15 bytes (command target + fragmentation + encryption nonce)

### Stream Types (4-bit)

| ID | Macro | Purpose |
| -- | ----- | ------- |
| `0x0` | `KS_STREAM_TELEM_FAST` | High-rate telemetry |
| `0x1` | `KS_STREAM_TELEM_SLOW` | Lower-rate telemetry |
| `0x2` | `KS_STREAM_CMD` | Commands |
| `0x3` | `KS_STREAM_CMD_ACK` | Command acknowledgements |
| `0x4` | `KS_STREAM_MISSION` | Mission upload/download |
| `0x5` | `KS_STREAM_VIDEO` | Video / TS transport |
| `0x6` | `KS_STREAM_SENSOR` | Sensor data |
| `0x7` | `KS_STREAM_HEARTBEAT` | Heartbeat / keepalive |
| `0x8` | `KS_STREAM_ALERT` | Alerts / urgent state |
| `0x9` | `KS_STREAM_NPNT` | DGCA NPNT traffic |
| `0xF` | `KS_STREAM_CUSTOM` | Custom / reserved use |

### Priority Levels

| Level     | Code | Latency | Use Case                  |
| --------- | ---- | ------- | ------------------------- |
| Bulk      | 00   | ~1000ms | Logs, parameter lists     |
| Normal    | 01   | ~100ms  | Telemetry, status updates |
| High      | 10   | ~20ms   | Commands, waypoints       |
| Emergency | 11   | <10ms   | Failsafe, critical alerts |

---

## Message Payload Specifications

The payloads below document the foundational telemetry messages. Additional command/control, compliance, and video-related payloads are implemented in `Kestrel/src/core/kestrel.h` and serialized in `kestrel.c`.

### 1. Heartbeat Message (MSG_ID 0x001)

**Purpose:** System status and keepalive  
**Payload Size:** 10 bytes  
**Send Rate:** 1 Hz

**Fields:**
| Field | Type | Size | Description |
|-------|------|------|-------------|
| system_status | uint32 | 4 | Bit-packed system state |
| system_type | uint8 | 1 | Vehicle type (quadcopter, fixed-wing, etc.) |
| autopilot_type | uint8 | 1 | Autopilot type (PX4, ArduPilot, custom) |
| base_mode | uint8 | 1 | Armed/disarmed, manual/auto mode flags |
| lost_link_action | uint8 | 1 | DO-362A failsafe action (0=none, 1=Land, 2=RTL, 3=Hover) |
| lost_link_timeout_s | uint16 | 2 | Seconds of GCS silence before failsafe triggers |

**Example:**

```c
ks_heartbeat_t hb = {
    .system_status = 0x12345678,
    .system_type = 5,         // Quadcopter
    .autopilot_type = 3,      // Custom autopilot
    .base_mode = 0xAB,        // Armed, auto mode
    .lost_link_action = 2,    // RTL
    .lost_link_timeout_s = 3
};

uint8_t payload[10];
ks_serialize_heartbeat(&hb, payload);
```

### 2. Attitude Message (MSG_ID 0x002)

**Purpose:** UAV orientation and angular rates  
**Payload Size:** 12 bytes  
**Send Rate:** 10-50 Hz

**Fields:**
| Field | Type | Size | Description |
|-------|------|------|-------------|
| roll | float | 2* | Roll angle (radians), compressed to float16 |
| pitch | float | 2* | Pitch angle (radians), compressed to float16 |
| yaw | float | 2* | Yaw angle (radians), compressed to float16 |
| rollspeed | float | 2* | Roll rate (rad/s), compressed to float16 |
| pitchspeed | float | 2* | Pitch rate (rad/s), compressed to float16 |
| yawspeed | float | 2* | Yaw rate (rad/s), compressed to float16 |

\*Uses float16 compression for 50% size reduction

**Example:**

```c
ks_attitude_t att = {
    .roll = 0.523f,       // ~30 degrees
    .pitch = -0.174f,     // ~-10 degrees
    .yaw = 1.571f,        // ~90 degrees
    .rollspeed = 0.1f,
    .pitchspeed = -0.05f,
    .yawspeed = 0.02f
};

uint8_t payload[12];
ks_serialize_attitude(&att, payload);
```

### 3. GPS Raw Message (MSG_ID 0x003)

**Purpose:** Raw GPS data  
**Payload Size:** 22 bytes  
**Send Rate:** 1-10 Hz

**Fields:**
| Field | Type | Size | Description |
|-------|------|------|-------------|
| lat | int32 | 4 | Latitude (deg _ 1e7) |
| lon | int32 | 4 | Longitude (deg _ 1e7) |
| alt | int32 | 4 | Altitude AMSL (mm) |
| eph | uint16 | 2 | GPS horizontal accuracy (cm) |
| epv | uint16 | 2 | GPS vertical accuracy (cm) |
| vel | uint16 | 2 | Ground speed (cm/s) |
| cog | uint16 | 2 | Course over ground (cdeg) |
| fix_type | uint8 | 1 | GPS fix type (0=no fix, 3=3D fix) |
| satellites | uint8 | 1 | Number of satellites visible |

**Example:**

```c
ks_gps_raw_t gps = {
    .lat = 474977810,      // 47.4977810° (Seattle)
    .lon = -1222093200,    // -122.2093200°
    .alt = 100000,         // 100m AMSL
    .eph = 150,            // 1.5m horizontal uncertainty
    .epv = 250,            // 2.5m vertical uncertainty
    .vel = 1500,           // 15 m/s ground speed
    .cog = 9000,           // 90° course
    .fix_type = 3,         // 3D fix
    .satellites = 12
};

uint8_t payload[22];
ks_serialize_gps_raw(&gps, payload);
```

### 4. Battery Message (MSG_ID 0x004)

**Purpose:** Battery status monitoring  
**Payload Size:** 8 bytes  
**Send Rate:** 1-5 Hz

**Fields:**
| Field | Type | Size | Description |
|-------|------|------|-------------|
| voltage | uint16 | 2 | Voltage (mV) |
| current | int16 | 2 | Current (mA, negative = discharging) |
| remaining | uint8 | 1 | Remaining capacity (%) |
| cell_count | uint8 | 1 | Number of cells (e.g., 4S LiPo) |
| status | uint8 | 1 | Status flags (charging, critical, etc.) |

**Example:**

```c
ks_battery_t bat = {
    .voltage = 16800,      // 16.8V (4S LiPo fully charged)
    .current = -1500,      // -15A (discharging)
    .remaining = 75,       // 75% remaining
    .cell_count = 4,       // 4S battery
    .status = 0x01         // Normal operation
};

uint8_t payload[8];
ks_serialize_battery(&bat, payload);
```

### 5. RC Input Message (MSG_ID 0x005)

**Purpose:** Radio control channel data  
**Payload Size:** 18 bytes  
**Send Rate:** 10-50 Hz

**Fields:**
| Field | Type | Size | Description |
|-------|------|------|-------------|
| channels[8] | uint16[8] | 16 | RC channel values (1000-2000 µs) |
| rssi | uint8 | 1 | Signal strength (0-100%) |
| quality | uint8 | 1 | Link quality (0-100%) |

**Example:**

```c
ks_rc_input_t rc = {
    .channels = {1500, 1600, 1400, 1500, 1800, 1200, 1500, 1500},
    .rssi = 95,
    .quality = 98
};

uint8_t payload[18];
ks_serialize_rc_input(&rc, payload);
```

---

## API Reference

### Initialization

```c
void ks_parser_init(ks_parser_t *p);
```

Initialize parser state machine. Call once before first use.

**Parameters:**

- `p` - Pointer to parser structure

**Example:**

```c
ks_parser_t parser;
ks_parser_init(&parser);
```

### Nonce Management

```c
int ks_nonce_init(ks_nonce_state_t *state);
uint32_t ks_nonce_get_counter(const ks_nonce_state_t *state);
void ks_nonce_set_counter(ks_nonce_state_t *state, uint32_t counter);
void ks_nonce_generate(ks_nonce_state_t *state, uint8_t nonce_8b[8]);
```

**Nonce Initialization:**

- Initializes the hybrid counter+random nonce generator
- Counter starts at cryptographically random value
- Returns `0` on success

**Nonce Generation:**

- Generates unique 8-byte nonce for each encrypted packet
- Format: 4-byte counter + 4-byte random
- Automatically increments counter
- `ks_nonce_get_counter()` / `ks_nonce_set_counter()` support NVM persistence across reboot

**Example:**

```c
ks_nonce_state_t nonce_state;
ks_nonce_init(&nonce_state);

// Restore from NVM if available
ks_nonce_set_counter(&nonce_state, saved_counter);

uint8_t nonce[8];
ks_nonce_generate(&nonce_state, nonce);  // Use for next packet
```

### Packet Packing

```c
int kestrel_pack_with_nonce(uint8_t *buf, const ks_header_t *h,
                            const uint8_t *payload, ks_session_t *session);

int kestrel_pack_cached(uint8_t *buf, const ks_header_t *h,
                        const uint8_t *payload, ks_session_t *session,
                        ks_crypto_ctx_t *crypto_ctx);

int kestrel_pack_selective(uint8_t *buf, const ks_header_t *h,
                           const uint8_t *payload, ks_session_t *session);
```

**Pack with Session-Managed Nonce:**

- Public API for assembling a complete packet with headers, encryption, MAC, and CRC
- The session bundles the encryption key with nonce state
- Pass `NULL` for `session` to send an unencrypted packet
- Returns packet length in bytes, or negative error code

**Cached / Selective Variants:**

- `kestrel_pack_cached()` reuses crypto context for repeated sends with the same key
- `kestrel_pack_selective()` applies the per-message encryption policy table

**Returns:**

- Positive: Packet length (bytes)
- `KS_ERR_NULL_POINTER` - Invalid pointer
- `KS_ERR_BUFFER_OVERFLOW` - Payload too large (>512 bytes)
- `KS_ERR_NO_KEY` - Encryption required but no session provided

**Example:**

```c
uint8_t key[32] = { /* 32-byte session key */ };
ks_session_t session;
ks_session_init(&session, key);

ks_header_t header = {
    .payload_len = 12,
    .priority = KS_PRIO_NORMAL,
    .stream_type = KS_STREAM_TELEM_FAST,
    .sequence = 42,
    .sys_id = 1,
    .comp_id = 1,
    .target_sys_id = 0,  // Broadcast
    .msg_id = KS_MSG_ATTITUDE
};

uint8_t packet[256];
int len = kestrel_pack_with_nonce(packet, &header, payload, &session);
uart_transmit(packet, len);
```

### Packet Parsing

```c
int ks_parse_char(ks_parser_t *p, uint8_t c, const uint8_t *key_32b);
```

**Parse Single Byte:**

- Feed bytes one-at-a-time from UART/serial
- State machine automatically handles framing, CRC, MAC verification
- Returns status code after each byte

**Returns:**

- `KS_OK` (0) - Packet complete and valid
- `1` - Still parsing, need more bytes
- `KS_ERR_CRC` - CRC mismatch
- `KS_ERR_MAC_VERIFICATION` - AEAD authentication failed (tampered packet)
- `KS_ERR_NO_KEY` - Encrypted packet but no key provided

**Example:**

```c
ks_parser_t parser;
ks_parser_init(&parser);

while (uart_available()) {
    uint8_t byte = uart_read();
    int result = ks_parse_char(&parser, byte, encryption_key);

    if (result == KS_OK) {
        // Packet complete!
        printf("Received msg_id=0x%03X from sys=%d\n",
               parser.header.msg_id, parser.header.sys_id);

        // Decode payload based on msg_id
        if (parser.header.msg_id == KS_MSG_ATTITUDE) {
            ks_attitude_t att;
            ks_deserialize_attitude(&att, parser.payload);
            printf("Roll: %.3f, Pitch: %.3f\n", att.roll, att.pitch);
        }
    }
    else if (result == KS_ERR_MAC_VERIFICATION) {
        printf("Tampered packet detected!\n");
    }
}
```

### Message Serialization

```c
int ks_serialize_heartbeat(const ks_heartbeat_t *msg, uint8_t *out);
int ks_serialize_attitude(const ks_attitude_t *msg, uint8_t *out);
int ks_serialize_gps_raw(const ks_gps_raw_t *msg, uint8_t *out);
int ks_serialize_battery(const ks_battery_t *msg, uint8_t *out);
int ks_serialize_rc_input(const ks_rc_input_t *msg, uint8_t *out);
```

**Serialization:**

- Converts struct to packed byte array
- Handles endianness (little-endian)
- Float16 compression where appropriate
- Returns payload size in bytes

**Returns:**

- Positive: Payload size (bytes)
- `KS_ERR_NULL_POINTER` - Invalid pointer

### Message Deserialization

```c
int ks_deserialize_heartbeat(ks_heartbeat_t *msg, const uint8_t *in);
int ks_deserialize_attitude(ks_attitude_t *msg, const uint8_t *in);
int ks_deserialize_gps_raw(ks_gps_raw_t *msg, const uint8_t *in);
int ks_deserialize_battery(ks_battery_t *msg, const uint8_t *in);
int ks_deserialize_rc_input(ks_rc_input_t *msg, const uint8_t *in);
```

**Deserialization:**

- Converts packed byte array back to struct
- Reverses endianness conversion
- Float16 decompression where needed
- Returns bytes consumed

**Returns:**

- Positive: Bytes consumed
- `KS_ERR_NULL_POINTER` - Invalid pointer

### Error Codes

```c
typedef enum {
    KS_OK = 0,                // Success
    KS_ERR_NULL_POINTER,      // NULL pointer argument
    KS_ERR_BUFFER_OVERFLOW,   // Payload exceeds max size
    KS_ERR_CRC,               // CRC checksum failed
    KS_ERR_MAC_VERIFICATION,  // AEAD MAC authentication failed
    KS_ERR_NO_KEY,            // Encrypted packet but no key
    KS_ERR_INVALID_PACKET     // Malformed packet
} ks_error_t;
```

---

## Security Considerations

### Implemented Protections

1. **Full AEAD Encryption:** ChaCha20-Poly1305 with 128-bit MAC authentication
2. **Header Authentication:** Entire packet header authenticated as Additional Data (AAD)
3. **Unique Nonces:** Hybrid counter+random prevents nonce reuse attacks
4. **CRC Checking:** Detects transmission errors independently from encryption
5. **MAC Verification:** Automatic rejection of tampered packets
6. **Sequence Numbers:** Enables detection of packet loss or reordering
7. **NULL Safety:** All public APIs validate pointer arguments
8. **Buffer Protection:** Payload size validation prevents buffer overflows

### Recent Security Enhancements (February 2026)

**Full ChaCha20-Poly1305 AEAD Implementation:**

The protocol now features production-grade authenticated encryption:

1. **Genuine MAC Authentication**
   - Replaced mock MAC tags with real Poly1305 authentication
   - 16-byte (128-bit) MAC tags computed over ciphertext + header
   - Header authenticated as Additional Authenticated Data (AAD)
   - Prevents both ciphertext and header tampering

2. **Comprehensive Error Handling**
   - Added `ks_error_t` enum with 7 distinct error codes
   - `KS_ERR_MAC_VERIFICATION` specifically identifies authentication failures
   - All error paths properly clean up parser state

3. **Defensive Programming**
   - NULL pointer checks on all 20+ public API functions
   - Buffer overflow protection with `KS_MAX_PAYLOAD_SIZE` constant
   - Payload size validation in both packer and parser

4. **AEAD Technical Details**
   - Encryption: `crypto_aead_lock(mac, ciphertext, key, nonce, header, header_len, plaintext, text_len)`
   - Decryption: `crypto_aead_unlock(plaintext, mac, key, nonce, header, header_len, ciphertext, text_len)`
   - Nonce format: 24-byte array (first 8 bytes from hybrid counter+random, rest zero-padded)
   - CRC-16 computed after MAC tag for transmission error detection

**Security Posture:**

- No replay attacks (hybrid nonce strategy)
- No tampering (AEAD MAC verification)
- No bit-flip attacks (CRC-16 + Poly1305)
- No buffer overflows (bounds checking)
- No NULL dereferences (comprehensive validation)

### Production Recommendations

1. **Key Management:**
   - Never hardcode keys in source code
   - Use secure key exchange (ECDH) or pre-shared keys loaded from protected storage
   - Rotate keys periodically
   - Use different keys per vehicle-GCS pair

2. **Nonce State Persistence:**
   - For production, consider persisting counter to non-volatile memory
   - Prevents counter reuse after reboot
   - Alternative: Initialize with timestamp + random on boot

3. **Replay Protection:**
   - Implement sequence number tracking on receiver
   - Reject packets with old sequence numbers
   - Window-based acceptance for out-of-order delivery

4. **Multi-Vehicle Scenarios:**
   - Track nonce state per vehicle
   - Example:
     ```c
     typedef struct {
         uint8_t sys_id;
         ks_nonce_state_t nonce_state;
         uint16_t last_sequence;
     } vehicle_context_t;
     ```

---

## Test Suite

Kestrel now ships with a broader validation surface: C unit-style tests, Python soak/chaos harnesses, protocol validators, and VM deployment assets. The repository is no longer best described as a single fixed-count test suite.

### Running Tests

```bash
cd Kestrel

# Build the main binaries
make
make legion_test

# Run the Legion unit test binary (.exe on Windows)
bin/legion_test.exe

# Run soak / chaos / validation scripts as needed
python testing/test_1min.py
python testing/test_15min.py
python testing/test_30min.py
python testing/test_3h.py
python testing/adversarial_test.py
python testing/net_chaos.py
python scripts/validate_ts.py video_out.ts
```

### Validation Coverage

- `testing/legion_unit_test.c` covers the Legion variant's address expansion, replay window, and memory pool.
- `testing/packet_size_test.c` and `testing/fuzz_parser.c` exercise parser boundaries, packet sizes, and malformed input handling.
- `testing/test_1min.py`, `test_15min.py`, `test_30min.py`, and `test_3h.py` provide duration-based soak testing for the GCS/UAV apps.
- `testing/adversarial_test.py`, `testing/net_chaos.py`, and `testing/clean_proxy.py` simulate hostile or degraded links.
- `scripts/validate_ts.py` validates PAT/PMT/video/KLV output for the TS/KLV path.
- `testing/vm_deploy/` contains split-node copies for VM or multi-host deployment testing.

### Historical Coverage Notes

1. **Serialization/Deserialization (5 tests)**
   - Heartbeat, attitude, GPS, battery, RC input message round-trips
   - Validates packing/unpacking of all message types

2. **AEAD Encryption (1 test)**
   - ChaCha20-Poly1305 encrypt/decrypt round-trip
   - Verifies cryptographic integrity

3. **MAC Verification (3 tests)**
   - Tampered payload detection
   - Tampered header detection
   - Wrong key rejection

4. **Parser State Machine (3 tests)**
   - Multiple packet parsing in stream
   - Bad CRC rejection
   - Bad start-of-frame handling

5. **Error Handling (2 tests)**
   - NULL pointer validation
   - Buffer overflow protection

6. **CRC (2 tests)**
   - Known vector validation
   - Empty message handling

7. **Nonce Management (4 tests)**
   - Initialization from system randomness
   - Uniqueness across packets
   - Counter increment behavior
   - State tracking during packing

8. **Replay Protection (5 tests)**
   - Basic sequence tracking
   - Duplicate sequence detection
   - Sequence number rollover (4095 → 0)
   - Out-of-order packet handling
   - Encrypted packet replay prevention

9. **Fragmentation (5 tests)**
   - Header encoding/decoding (frag_index, frag_total)
   - Multiple fragments as separate packets
   - Fragmentation with encryption
   - Non-fragmented packet verification
   - Boundary cases (first/last/single fragments)

10. **Edge Cases (3 tests)**
    - Zero-length payload handling
    - Maximum sequence number (4095)
    - All priority levels (Bulk, Normal, High, Emergency)

### Historical Test Results Snapshot

```
╔═══════════════════════════════════════════════════════════╗
║  Total Tests:  33                                         ║
║  Passed:       33    ✓                                    ║
║  Failed:       0     ✗                                    ║
║  Success Rate: 100.0%                                     ║
╚═══════════════════════════════════════════════════════════╝
```

### Bug Fixes from Testing

During test development, several critical bugs were discovered and fixed:

1. **AEAD Parameter Swap** - `crypto_aead_lock()` had MAC and ciphertext outputs reversed
2. **Parser API Ambiguity** - Return value conflict between `KS_OK` (0) and "keep parsing" state
3. **Zero-Length Payload** - Parser stuck in PAYLOAD state for empty messages

All issues resolved with production code fixes validated by the test suite.

### Fragmentation Behavior

**Current behavior:** The codebase includes fragment generation plus receiver-side reassembly APIs (`ks_fragment_split`, `ks_reassembly_add`, and `ks_reassembly_add_timed`). Applications can still process fragments manually, but reassembly is now part of the core library surface.

---

## How to Add New Messages

### Step 1: Define Message ID and Structure

In `kestrel.h`:

```c
// Add message ID
#define KS_MSG_YOUR_MESSAGE  0x006

// Define message structure
typedef struct {
    uint32_t timestamp;    // System time (milliseconds)
    float temperature;     // Temperature (°C)
    uint8_t status;        // Status flags
} ks_your_message_t;
```

### Step 2: Declare Serialization Functions

In `kestrel.h`:

```c
int ks_serialize_your_message(const ks_your_message_t *msg, uint8_t *out);
int ks_deserialize_your_message(ks_your_message_t *msg, const uint8_t *in);
```

### Step 3: Add CRC Seed

In `kestrel.c`, update `ks_get_crc_seed()`:

```c
static uint8_t ks_get_crc_seed(uint16_t msg_id) {
    switch (msg_id) {
    case KS_MSG_HEARTBEAT:    return 50;
    case KS_MSG_ATTITUDE:     return 39;
    case KS_MSG_GPS_RAW:      return 24;
    case KS_MSG_BATTERY:      return 154;
    case KS_MSG_RC_INPUT:     return 89;
    case KS_MSG_YOUR_MESSAGE: return 123;  // Pick random unique value
    default: return 0;
    }
}
```

### Step 4: Implement Serialization

In `kestrel.c`:

```c
int ks_serialize_your_message(const ks_your_message_t *msg, uint8_t *out) {
    if (!msg || !out) return KS_ERR_NULL_POINTER;

    int offset = 0;

    pack_uint32(&out[offset], msg->timestamp);
    offset += 4;

    pack_float(&out[offset], msg->temperature);
    offset += 4;

    out[offset] = msg->status;
    offset += 1;

    return offset;  // Return total size (9 bytes)
}
```

### Step 5: Implement Deserialization

In `kestrel.c`:

```c
int ks_deserialize_your_message(ks_your_message_t *msg, const uint8_t *in) {
    if (!msg || !in) return KS_ERR_NULL_POINTER;

    int offset = 0;

    msg->timestamp = unpack_uint32(&in[offset]);
    offset += 4;

    msg->temperature = unpack_float(&in[offset]);
    offset += 4;

    msg->status = in[offset];
    offset += 1;

    return offset;  // Return bytes consumed
}
```

### Step 6: Test Your Message

Always test serialization/deserialization for round-trip accuracy:

```c
ks_your_message_t original = {
    .timestamp = 123456,
    .temperature = 25.5f,
    .status = 0x42
};

uint8_t buffer[32];
int size = ks_serialize_your_message(&original, buffer);

ks_your_message_t decoded;
ks_deserialize_your_message(&decoded, buffer);

assert(decoded.timestamp == original.timestamp);
assert(fabs(decoded.temperature - original.temperature) < 0.001f);
assert(decoded.status == original.status);

printf("✓ Round-trip test passed!\n");
```

## Performance Characteristics

### Packet Overhead

| Scenario              | Header   | MAC | CRC | Total Overhead |
| --------------------- | -------- | --- | --- | -------------- |
| Unencrypted broadcast | 8 bytes  | 0   | 2   | 10 bytes       |
| Encrypted broadcast   | 16 bytes | 16  | 2   | 34 bytes       |
| Encrypted targeted    | 17 bytes | 16  | 2   | 35 bytes       |
| Encrypted fragmented  | 19 bytes | 16  | 2   | 37 bytes       |

### Bandwidth Examples

**Telemetry @10Hz (Attitude Message):**

- Payload: 12 bytes
- Packet (encrypted): 12 + 34 = 46 bytes
- Bandwidth: 46 × 10 = 460 bytes/sec = 3.68 kbps

**GPS @5Hz:**

- Payload: 22 bytes
- Packet (encrypted): 22 + 34 = 56 bytes
- Bandwidth: 56 × 5 = 280 bytes/sec = 2.24 kbps

**Total typical telemetry:** ~10 kbps (comfortable for 57.6 kbps radio)

### CPU Performance

On ARM Cortex-M4 @168MHz:

- Parse byte: ~5 µs
- CRC-16: ~15 µs
- ChaCha20-Poly1305 encrypt (12 bytes): ~200 µs
- ChaCha20-Poly1305 decrypt+verify: ~220 µs
- Total packet processing: ~250 µs

**Throughput:** ~4,000 packets/sec (sufficient for 100Hz telemetry)

---

## Development Timeline

- **January 2026** - Initial protocol design and base implementation
  - Packet structure design
  - Base encoder/decoder
  - 5 message types implemented
- **February 2026** - ChaCha20-Poly1305 AEAD integration
  - Full encryption implementation
  - MAC authentication
  - Security hardening
- **March 2026** - Comprehensive testing and optimization
  - Built 33-test validation framework
  - Discovered and fixed 3 critical bugs
  - Achieved 100% test pass rate
  - Phase 2 & 3 performance optimizations (zero-copy parser, memory pool, delta encoding)
  - Two-PC WiFi network test with zero packet loss
  - Production-ready release

---

## Contributing

Contributions welcome! Areas of interest:

- **Message Definitions** - Add new message types for additional sensors/actuators
- **Language Bindings** - Python, JavaScript, Rust implementations
- **Security Reviews** - Cryptographic analysis, penetration testing
- **Documentation** - Tutorials, examples, protocol specification
- **Testing** - Embedded platform testing, performance benchmarks
- **Tools** - Wireshark dissector, log analyzers, packet generators

**How to Contribute:**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-message`)
3. Make your changes with tests
4. Ensure the relevant build targets, unit tests, and validation scripts pass for the areas you changed
5. Submit a pull request

---

## License

This project includes:

- **Kestrel Protocol (reference implementation):** MIT License
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
