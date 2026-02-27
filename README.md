# UAVLink Protocol

UAVLink is a lightweight binary communication protocol purpose-built for UAV systems. It minimizes packet overhead and maximizes reliability on lossy radio links.

## Usage

This project contains a simple C encoder and decoder for the UAVLink packet structure, complete with payload generation, struct serialization, CRC integrity checking, and zero-dependency ChaCha20 encryption using Monocypher.

### Files
- `uavlink.h`: Macro definitions, core API prototypes, payload structs, and parser state machine definition.
- `uavlink.c`: Encoding and decoding routines, float16 serialization implementations, and the byte-by-stream serial `ul_parse_char` logic.
- `example.c`: A demonstration program showing how to pack and parse an encrypted packet.
- `monocypher.c` / `.h`: Extremely portable cryptography backing the IETF stream cipher.

### Compiling and Testing

You have two main paths to compile and test the project:

#### 1. Using WSL (Since you are on Windows)
Since you are on a Windows machine but WSL (Ubuntu) is installed, you can compile and execute it using the Linux subsystem exactly like a flight companion computer would.
Open a PowerShell window in this directory (`Desktop\Protocol`) and run:
```powershell
wsl make
wsl ./example
```

#### 2. Native Compilation on Windows (requires a compiler)
If you install a Windows compiler toolchain like MinGW (GCC for Windows) or Visual Studio (MSVC / `cl.exe`), you can compile it natively:
```powershell
make
.\example.exe
```

### Expected Output
When you run the compiled `example` program, it will print:
1. The simulated **Attitude Payload Data**.
2. The **Transmitting Packet Bytes**, which will correctly be 34 bytes long with all headers, packed floats, MAC tag, and CRC-16 attached.
3. The **Decoded Attitude Payload** proving the parser accurately identified the start of frame, decrypted the payload in real-time byte-by-byte, and unpacked the data.

### Integrating into your own Code
To add this to your flight controller or ground station application:
1. Copy `uavlink.h`, `uavlink.c`, `monocypher.h`, and `monocypher.c` into your build tree.
2. Initialize a `ul_parser_t` instance using `ul_parser_init()`.
3. Inside your serial reading loop (UART Rx interrupt or background thread), simply feed arriving bytes one at a time into `ul_parse_char(parser, incoming_byte, key)`. 
4. The moment `ul_parse_char` returns `1`, a full packet has just arrived and its contents are safely extracted into `parser.header` and `parser.payload`!
