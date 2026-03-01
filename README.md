# UAVLink Protocol

UAVLink is a lightweight binary communication protocol purpose-built for UAV systems. It minimizes packet overhead and maximizes reliability on lossy radio links with built-in encryption, message routing, and integrity checking.

## Status: Production-Ready ✅

**Current Version:** 1.0 (March 2026)

### ✨ Key Achievements

- ✅ **Full ChaCha20-Poly1305 AEAD Encryption** - Complete implementation with 128-bit MAC authentication
- ✅ **Comprehensive Test Suite** - 33 tests across 10 categories with 100% pass rate
- ✅ **Production-Ready Code** - All critical bugs identified and fixed through rigorous testing
- ✅ **5 Message Types Implemented** - Heartbeat, Attitude, GPS, Battery, RC Input
- ✅ **Robust Parser** - Byte-by-byte state machine with full error handling
- ✅ **Secure Nonce Management** - Cryptographically secure nonce generation prevents replay attacks
- ✅ **Fragmentation Support** - Handle payloads up to 4095 bytes with built-in fragmentation

### 📊 Test Coverage

**33 Tests | 100% Pass Rate**

- Serialization/Deserialization (5 tests)
- AEAD Encryption (1 test)
- MAC Verification (3 tests)
- Parser State Machine (3 tests)
- Error Handling (2 tests)
- CRC (2 tests)
- Nonce Management (4 tests)
- Replay Protection (5 tests)
- Fragmentation (5 tests)
- Edge Cases (3 tests)

**Run tests:** `wsl make test`

## Usage

This project contains a complete C encoder and decoder for the UAVLink packet structure, with payload generation, struct serialization, CRC integrity checking, and ChaCha20-Poly1305 AEAD encryption using Monocypher.

### Files
- `uavlink.h`: Core API, structures, constants, and message definitions
- `uavlink.c`: Encoding/decoding implementation with secure nonce generation and AEAD
- `test_uavlink.c`: Comprehensive unit test suite (33 tests, 100% pass rate)
- `example.c`: Basic demonstration of attitude message encrypt/decrypt workflow
- `example_messages.c`: Comprehensive demo of all 5 implemented message types
- `monocypher.c/h`: Portable ChaCha20-Poly1305 cryptography library

### Bug Fixes from Testing Phase

During comprehensive testing, we identified and fixed 3 critical production bugs:

1. **AEAD Parameter Swap** - `crypto_aead_lock()` had MAC and ciphertext outputs reversed
2. **Parser API Ambiguity** - Return value conflict between `UL_OK` (0) and "keep parsing" state
3. **Zero-Length Payload Bug** - Parser stuck in PAYLOAD state for empty messages

All issues resolved and validated by the test suite.

### Compiling and Testing

You have several compilation options:

#### 1. Run Full Test Suite (Recommended)
```powershell
wsl make test
```
This compiles and runs all 33 unit tests, validating the entire protocol implementation.

#### 2. Build Example Demos
```powershell
wsl make
wsl ./example
wsl ./example_messages
```

#### 3. Native Windows Compilation (requires MinGW/MSVC)
```powershell
make
.\example.exe
```

### Expected Output

**Test Suite (`make test`):**
```
╔════════════════════════════════════════════════════════════╗
║         UAVLink Protocol Unit Test Suite v1.0             ║
╚════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. SERIALIZATION/DESERIALIZATION TESTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Running test_heartbeat_serialization...
  ✓ PASS
...

╔════════════════════════════════════════════════════════════╗
║                      TEST SUMMARY                          ║
╠════════════════════════════════════════════════════════════╣
║  Total Tests:  33                                          ║
║  Passed:       33    ✓                                     ║
║  Failed:       0     ✗                                     ║
║  Success Rate: 100.0%                                      ║
╚════════════════════════════════════════════════════════════╝

🎉 ALL TESTS PASSED! 🎉
```

**Example Program:**
When you run the `example` program, it will print:
1. The simulated **Attitude Payload Data**.
2. The **Transmitting Packet Bytes** with full AEAD encryption.
3. The **Decoded Attitude Payload** proving byte-by-byte parsing and decryption work correctly.

### Integrating into your own Code
To add this to your flight controller or ground station application:
1. Copy `uavlink.h`, `uavlink.c`, `monocypher.h`, and `monocypher.c` into your build tree.
2. Initialize a `ul_parser_t` instance using `ul_parser_init()`.
3. Inside your serial reading loop (UART Rx interrupt or background thread), simply feed arriving bytes one at a time into `ul_parse_char(parser, incoming_byte, key)`. 
4. The moment `ul_parse_char` returns `UL_OK` (0), a full packet has arrived and its contents are extracted into `parser.header` and `parser.payload`!

## Features

✅ **Compact Headers** - 8-16 byte headers with bit-packed fields  
✅ **Built-in Encryption** - ChaCha20-Poly1305 AEAD with full 128-bit MAC authentication  
✅ **Reliable** - CRC-16 integrity checking plus AEAD MAC prevents tampering  
✅ **Flexible Routing** - System/component addressing with broadcast support  
✅ **Priority-based QoS** - 4 priority levels for time-critical messages  
✅ **Stream-Parseable** - Byte-by-byte state machine ideal for UART  
✅ **Fragmentation Support** - Handle payloads up to 4095 bytes  
✅ **Production-Ready** - Secure nonce generation prevents replay attacks

## Documentation

For detailed protocol specification, message definitions, and API documentation, see:
**[Protocol/README.md](Protocol/README.md)**

## Development Timeline

- **January 2026** - Initial protocol design and base implementation
- **February 2026** - ChaCha20-Poly1305 AEAD integration
- **March 2026** - Comprehensive test suite development
  - Built 33-test validation framework
  - Discovered and fixed 3 critical bugs
  - Achieved 100% test pass rate
  - Production-ready release

## Contributing

Contributions welcome! Areas of interest:
- Additional message definitions
- Parser implementations in other languages (Python, JavaScript)
- Security reviews and improvements
- Documentation and examples
- Testing on embedded platforms

## License

This project includes:
- **UAVLink Protocol:** MIT License
- **Monocypher:** Dual-licensed BSD-2-Clause OR CC0-1.0 (public domain)

---

**UAVLink Protocol - Secure, Efficient, Reliable Communication for UAV Systems** 🚁
