#ifndef KESTREL_H
#define KESTREL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Protocol Constants */
#define KS_MAX_PAYLOAD_SIZE 512 /* Maximum payload size in parser buffer */
#define KS_MAC_TAG_SIZE 16      /* Poly1305 MAC tag size (full 128-bit) */

/* Error Codes */
typedef enum
{
    KS_OK = 0,
    KS_ERR_CRC = -1,
    KS_ERR_NO_KEY = -2,
    KS_ERR_MAC_VERIFICATION = -3,
    KS_ERR_BUFFER_OVERFLOW = -4,
    KS_ERR_INVALID_HEADER = -5,
    KS_ERR_NULL_POINTER = -6
} ks_error_t;

/* Base header byte 0 */
#define KS_SOF 0xA5

/* Byte 1 */
#define KS_PLEN_HI_MASK 0xF0  /* bits 7:4 -> payload length [11:8] */
#define KS_PRIORITY_MASK 0x0C /* bits 3:2 */
#define KS_PRIORITY_SHIFT 2
#define KS_STYPE_HI_MASK 0x03 /* bits 1:0 -> stream type [3:2] */

/* Byte 2 */
#define KS_STYPE_LO_MASK 0xC0 /* bits 7:6 -> stream type [1:0] */
#define KS_STYPE_LO_SHIFT 6
#define KS_PLEN_MID_MASK 0x3F /* bits 5:0 -> payload length [7:2] */

/* Byte 3 */
#define KS_PLEN_LO_MASK 0xC0    /* bits 7:6 -> payload length [1:0] */
#define KS_FLAG_ENCRYPTED 0x08  /* bit 3 */
#define KS_FLAG_FRAGMENTED 0x04 /* bit 2 */
#define KS_SEQ_HI_MASK 0x03     /* bits 1:0 -> sequence [11:10] */

/* Priority Values */
#define KS_PRIO_BULK 0
#define KS_PRIO_NORMAL 1
#define KS_PRIO_HIGH 2
#define KS_PRIO_EMERGENCY 3

/* Stream Types */
#define KS_STREAM_TELEM_FAST 0x0
#define KS_STREAM_TELEM_SLOW 0x1
#define KS_STREAM_CMD 0x2
#define KS_STREAM_CMD_ACK 0x3
#define KS_STREAM_MISSION 0x4
#define KS_STREAM_VIDEO 0x5
#define KS_STREAM_SENSOR 0x6
#define KS_STREAM_HEARTBEAT 0x7
#define KS_STREAM_ALERT 0x8
#define KS_STREAM_CUSTOM 0xF

/* Parsed message header structure */
typedef struct
{
    uint16_t payload_len; // 12-bit
    uint8_t priority;     // 2-bit
    uint8_t stream_type;  // 4-bit
    bool encrypted;       // 1-bit
    bool fragmented;      // 1-bit
    uint16_t sequence;    // 12-bit

    // Extended Header
    uint8_t sys_id;        // 6-bit
    uint8_t comp_id;       // 4-bit
    uint8_t target_sys_id; // 6-bit (0 = broadcast)
    uint16_t msg_id;       // 12-bit

    // Fragmentation fields
    uint8_t frag_index;
    uint8_t frag_total;

    // Encryption nonces
    uint8_t nonce[8];
} ks_header_t;

/* Message IDs */
#define KS_MSG_HEARTBEAT 0x001
#define KS_MSG_ATTITUDE 0x002
#define KS_MSG_GPS_RAW 0x003
#define KS_MSG_BATTERY 0x004
#define KS_MSG_RC_INPUT 0x005
#define KS_MSG_CMD 0x006
#define KS_MSG_CMD_ACK 0x007
#define KS_MSG_MODE_CHANGE 0x008
#define KS_MSG_MISSION_ITEM 0x009
#define KS_MSG_KEY_EXCHANGE 0x00A
#define KS_MSG_KEY_EXCHANGE_ACK 0x00B
#define KS_MSG_BATCH 0x3FF /* Special message ID for message batching */

/* Command IDs (used in ks_command_t.command_id) */
#define KS_CMD_ARM 0x0001       /* Arm motors */
#define KS_CMD_DISARM 0x0002    /* Disarm motors */
#define KS_CMD_TAKEOFF 0x0003   /* Takeoff to altitude (param1 = alt in cm) */
#define KS_CMD_LAND 0x0004      /* Land at current position */
#define KS_CMD_RTL 0x0005       /* Return to launch */
#define KS_CMD_EMERGENCY 0x0006 /* Emergency stop */

/* ACK Result Codes (used in ks_command_ack_t.result) */
#define KS_ACK_OK 0x00          /* Command accepted */
#define KS_ACK_REJECTED 0x01    /* Command rejected (wrong state) */
#define KS_ACK_UNSUPPORTED 0x02 /* Unknown command ID */
#define KS_ACK_FAILED 0x03      /* Command failed */
#define KS_ACK_IN_PROGRESS 0x04 /* Command in progress */

/* Flight Modes (used in ks_mode_change_t.mode) */
#define KS_MODE_MANUAL 0x00
#define KS_MODE_STABILIZE 0x01
#define KS_MODE_ALT_HOLD 0x02
#define KS_MODE_LOITER 0x03
#define KS_MODE_AUTO 0x04
#define KS_MODE_RTL 0x05
#define KS_MODE_LAND 0x06

/* --- OPTIMIZATION: Selective Encryption Policies --- */
typedef enum
{
    KS_ENCRYPT_NEVER = 0,    /* Never encrypt (public telemetry) */
    KS_ENCRYPT_OPTIONAL = 1, /* Encrypt if key provided (medium sensitivity) */
    KS_ENCRYPT_ALWAYS = 2    /* Always encrypt (security-critical commands) */
} ks_encrypt_policy_t;

/* Kestrel State Machine Parser struct */
typedef enum
{
    KS_PARSE_STATE_IDLE,
    KS_PARSE_STATE_BASE_HDR,
    KS_PARSE_STATE_EXT_HDR,
    KS_PARSE_STATE_PAYLOAD,
    KS_PARSE_STATE_CRC
} ks_parse_state_t;

typedef struct
{
    ks_parse_state_t state;
    uint8_t buffer[512]; // Max packet size buffer
    uint16_t buf_idx;
    uint16_t expected_len;
    uint16_t header_len; // Store actual header length for AEAD

    // Extracted payload fields
    ks_header_t header;
    uint8_t payload[512]; // Must match buffer[512] to prevent overflow

    /* Replay protection: 32-packet sliding window keyed on sequence number */
    uint8_t replay_init;    /* 1 once first valid packet received */
    uint8_t last_seq;       /* Highest accepted sequence number    */
    uint32_t replay_window; /* Bitmap: bit i set => (last_seq - i) seen */

    /* Statistics / Link Quality */
    uint32_t rx_count;    /* Total packets successfully received */
    uint32_t error_count; /* Total packets with CRC/MAC errors */
} ks_parser_t;

/* --- Nonce State Management (for secure encryption) --- */

typedef struct
{
    uint32_t counter;    // Monotonically increasing counter
    uint8_t initialized; // 1 if initialized, 0 otherwise
    uint8_t reserved[3]; // Padding for alignment
} ks_nonce_state_t;

/* --- OPTIMIZATION: Crypto Context Caching --- */
typedef struct
{
    uint8_t last_key[32]; /* Last key used for caching */
    uint8_t valid;        /* 1 if cache is valid, 0 otherwise */
    uint8_t reserved[3];  /* Padding for alignment */
} ks_crypto_ctx_t;

/* --- OPTIMIZATION: Message Batching --- */
#define KS_BATCH_MAX_MESSAGES 8

typedef struct
{
    uint16_t msg_id;  /* Message ID */
    uint8_t length;   /* Payload length */
    uint8_t data[64]; /* Message data (max 64 bytes per message) */
} ks_batch_msg_t;

typedef struct
{
    uint8_t num_messages;                           /* Number of messages in batch */
    ks_batch_msg_t messages[KS_BATCH_MAX_MESSAGES]; /* Array of batched messages */
} ks_batch_t;

/* --- Core Message Payloads --- */

typedef struct
{
    uint32_t system_status;
    uint8_t system_type;
    uint8_t autopilot_type;
    uint8_t base_mode;
} ks_heartbeat_t;

/* Attitude angles as float32, rates packed into float16 over the wire */
typedef struct
{
    float roll;
    float pitch;
    float yaw;
    float rollspeed;
    float pitchspeed;
    float yawspeed;
} ks_attitude_t;

/* GPS raw data */
typedef struct
{
    int32_t lat;        // Latitude (degrees × 1e7)
    int32_t lon;        // Longitude (degrees × 1e7)
    int32_t alt;        // Altitude AMSL (mm)
    uint16_t eph;       // Horizontal position uncertainty (cm)
    uint16_t epv;       // Vertical position uncertainty (cm)
    uint16_t vel;       // Ground speed (cm/s)
    uint16_t cog;       // Course over ground (degrees × 100)
    uint8_t fix_type;   // GPS fix type (0=none, 2=2D, 3=3D, 4=DGPS, 5=RTK)
    uint8_t satellites; // Number of satellites visible
} ks_gps_raw_t;

/* Battery status */
typedef struct
{
    uint16_t voltage;   // Battery voltage (mV)
    int16_t current;    // Battery current (cA, negative=discharging)
    int16_t remaining;  // Remaining capacity (%, -1 if unknown)
    uint8_t cell_count; // Number of cells
    uint8_t status;     // Battery status flags
} ks_battery_t;

/* RC input channels */
typedef struct
{
    uint16_t channels[8]; // RC channel values (1000-2000 us, 0=disconnected)
    uint8_t rssi;         // Signal strength (0-100%)
    uint8_t quality;      // Link quality (0-100%)
} ks_rc_input_t;

/* --- Command & Control Messages --- */

/* ECDH Handshake States */
typedef enum
{
    KS_ECDH_IDLE = 0,         /* No handshake initiated */
    KS_ECDH_SENT_KEY = 1,     /* Sent our public key, waiting for peer's key */
    KS_ECDH_RECEIVED_KEY = 2, /* Received peer's key, sent ACK, waiting for peer's ACK */
    KS_ECDH_ESTABLISHED = 3   /* Both sides confirmed, session ready */
} ks_ecdh_state_t;

/* Session Key Exchange (ECDH Public Key) */
typedef struct
{
    uint8_t public_key[32]; // 256-bit X25519 public key
    uint8_t seq_num;        // Handshake sequence number (to detect duplicates)
    uint8_t signature[64];  // 512-bit Ed25519 signature
} ks_key_exchange_t;

/* Session Key Exchange ACK */
typedef struct
{
    uint8_t seq_num; // Echo the sequence number we're acknowledging
    uint8_t status;  // 0 = OK, 1 = Error
} ks_key_exchange_ack_t;

/* Generic command (GCS -> UAV) */
typedef struct
{
    uint16_t command_id; // Command ID (KS_CMD_ARM, etc.)
    uint16_t param1;     // Parameter 1 (command-specific)
    uint16_t param2;     // Parameter 2 (command-specific)
    uint16_t param3;     // Parameter 3 (command-specific)
} ks_command_t;

/* Command acknowledgement (UAV -> GCS) */
typedef struct
{
    uint16_t command_id; // Command ID being acknowledged
    uint8_t result;      // Result code (KS_ACK_OK, etc.)
    uint8_t progress;    // Progress 0-100% (for KS_ACK_IN_PROGRESS)
} ks_command_ack_t;

/* Flight mode change request (GCS -> UAV) */
typedef struct
{
    uint8_t mode;     // Target flight mode (KS_MODE_MANUAL, etc.)
    uint8_t reserved; // Reserved for future use
} ks_mode_change_t;

/* Mission item / waypoint (GCS -> UAV) */
typedef struct
{
    uint16_t seq;         // Waypoint sequence number (0-based)
    uint8_t frame;        // Coordinate frame (0=global, 1=relative)
    uint8_t command;      // Waypoint action (0=navigate, 1=loiter, 2=land)
    int32_t lat;          // Latitude (deg x 1e7)
    int32_t lon;          // Longitude (deg x 1e7)
    int32_t alt;          // Altitude (mm)
    uint16_t speed;       // Desired speed (cm/s, 0 = default)
    uint16_t loiter_time; // Loiter time at waypoint (seconds)
} ks_mission_item_t;

/* --- Fragment Reassembly --- */
#define KS_FRAG_MAX_PAYLOAD 256  // Max payload per fragment
#define KS_FRAG_MAX_FRAGMENTS 16 // Max fragments per message
#define KS_FRAG_MAX_TOTAL 4096   // Max reassembled payload (256 * 16)
#define KS_FRAG_TIMEOUT_MS 5000  // Reassembly timeout

typedef struct
{
    uint8_t num_fragments;     // Total fragments generated
    uint8_t payloads[16][256]; // Fragment payloads
    uint16_t payload_lens[16]; // Length of each fragment
    ks_header_t headers[16];   // Pre-filled headers per fragment
} ks_fragment_set_t;

int ks_fragment_split(const ks_header_t *base_header,
                      const uint8_t *payload, size_t payload_len,
                      ks_fragment_set_t *out);

typedef struct
{
    bool active;            // Slot in use
    uint16_t msg_id;        // Message ID being reassembled
    uint8_t sys_id;         // Source system ID
    uint8_t frag_total;     // Expected fragment count
    bool received[16];      // Which fragments arrived
    uint8_t data[4096];     // Reassembled payload buffer
    uint16_t frag_lens[16]; // Length of each received fragment
    uint8_t frags_received; // Count of received fragments
    uint32_t start_time_ms; // Timeout tracking
} ks_reassembly_slot_t;

typedef struct
{
    ks_reassembly_slot_t slots[4]; // 4 concurrent reassembly slots
} ks_reassembly_ctx_t;

void ks_reassembly_init(ks_reassembly_ctx_t *ctx);
int ks_reassembly_add(ks_reassembly_ctx_t *ctx, const ks_header_t *hdr,
                      const uint8_t *payload, uint16_t payload_len,
                      uint8_t *output, uint16_t *output_len);

/* --- Function Prototypes --- */

/* Initialize a parser */
void ks_parser_init(ks_parser_t *p);

/* Parse a single byte from a serial stream. Returns 1 if a complete valid packet was received.
   If decryption key is non-null, handles decryption automatically. */
int ks_parse_char(ks_parser_t *p, uint8_t c, const uint8_t *key_32b);

/* Pack a complete message into a byte buffer ready for wire transmission.
   Returns the total packet length (header + payload + CRC).
   If key is non-null, payload is encrypted. */
int kestrel_pack(uint8_t *buf, const ks_header_t *h, const uint8_t *payload, const uint8_t *key_32b);

/* Serialize specific messages to a raw byte buffer */
int ks_serialize_heartbeat(const ks_heartbeat_t *hb, uint8_t *payload_buf);
int ks_deserialize_heartbeat(ks_heartbeat_t *hb, const uint8_t *payload_buf);

int ks_serialize_attitude(const ks_attitude_t *att, uint8_t *payload_buf);
int ks_deserialize_attitude(ks_attitude_t *att, const uint8_t *payload_buf);

int ks_serialize_gps_raw(const ks_gps_raw_t *gps, uint8_t *payload_buf);
int ks_deserialize_gps_raw(ks_gps_raw_t *gps, const uint8_t *payload_buf);

int ks_serialize_battery(const ks_battery_t *bat, uint8_t *payload_buf);
int ks_deserialize_battery(ks_battery_t *bat, const uint8_t *payload_buf);

int ks_serialize_rc_input(const ks_rc_input_t *rc, uint8_t *payload_buf);
int ks_deserialize_rc_input(ks_rc_input_t *rc, const uint8_t *payload_buf);

int ks_serialize_key_exchange(const ks_key_exchange_t *kx, uint8_t *payload_buf);
int ks_deserialize_key_exchange(ks_key_exchange_t *kx, const uint8_t *payload_buf);

int ks_serialize_key_exchange_ack(const ks_key_exchange_ack_t *ack, uint8_t *payload_buf);
int ks_deserialize_key_exchange_ack(ks_key_exchange_ack_t *ack, const uint8_t *payload_buf);

int ks_serialize_command(const ks_command_t *cmd, uint8_t *payload_buf);
int ks_deserialize_command(ks_command_t *cmd, const uint8_t *payload_buf);

int ks_serialize_command_ack(const ks_command_ack_t *ack, uint8_t *payload_buf);
int ks_deserialize_command_ack(ks_command_ack_t *ack, const uint8_t *payload_buf);

int ks_serialize_mode_change(const ks_mode_change_t *mode, uint8_t *payload_buf);
int ks_deserialize_mode_change(ks_mode_change_t *mode, const uint8_t *payload_buf);

int ks_serialize_mission_item(const ks_mission_item_t *item, uint8_t *payload_buf);
int ks_deserialize_mission_item(ks_mission_item_t *item, const uint8_t *payload_buf);

/* CRC Computations */
void ks_crc_init(uint16_t *crcAccum);
void ks_crc_accumulate(uint8_t data, uint16_t *crcAccum);
uint8_t ks_get_crc_seed(uint16_t msg_id);

/* Encode the base 4-byte header */
void ks_encode_base_header(uint8_t *buf, const ks_header_t *h);

/* Decode the base 4-byte header */
int ks_decode_base_header(const uint8_t *buf, ks_header_t *h);

/* Encode the extended header. Returns the number of bytes written. */
int ks_encode_ext_header(uint8_t *buf, const ks_header_t *h);

/* Decode the extended header. Returns the number of bytes read. */
int ks_decode_ext_header(const uint8_t *buf, ks_header_t *h);

/* --- Nonce Management Functions --- */

/* Initialize nonce state. Must be called before first use. */
void ks_nonce_init(ks_nonce_state_t *state);

/* Get the current 32-bit nonce counter for NVM persistence. */
uint32_t ks_nonce_get_counter(const ks_nonce_state_t *state);

/* Set the 32-bit nonce counter from NVM storage.
   Call this immediately after ks_nonce_init() at system boot. */
void ks_nonce_set_counter(ks_nonce_state_t *state, uint32_t counter);

/* Generate a secure nonce using hybrid approach (counter + random).
   Combines a 32-bit counter with 32 bits of random data for maximum security.
   The nonce buffer must be at least 8 bytes. */
void ks_nonce_generate(ks_nonce_state_t *state, uint8_t nonce[8]);

/* Advanced: Pack with nonce state management.
   Automatically generates and uses a secure nonce from the state.
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_with_nonce(uint8_t *buf, const ks_header_t *h, const uint8_t *payload,
                            const uint8_t *key_32b, ks_nonce_state_t *nonce_state);

/* --- OPTIMIZATION API Functions --- */

/* Initialize crypto context cache */
void ks_crypto_ctx_init(ks_crypto_ctx_t *ctx);

/* OPTIMIZATION: Pack with crypto context caching (30% faster for consecutive packets)
   Reuses crypto context if same key as previous packet.
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_cached(uint8_t *buf, const ks_header_t *h, const uint8_t *payload,
                        const uint8_t *key_32b, ks_nonce_state_t *nonce_state,
                        ks_crypto_ctx_t *crypto_ctx);

/* OPTIMIZATION: Pack with selective encryption based on message policy
   Automatically applies encryption policy based on message ID.
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_selective(uint8_t *buf, const ks_header_t *h, const uint8_t *payload,
                           const uint8_t *key_32b, ks_nonce_state_t *nonce_state);

/* OPTIMIZATION: Pack multiple messages into a single batched packet (18% bandwidth reduction)
   Aggregates multiple small messages into one packet.
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_batch(uint8_t *buf, const ks_batch_t *batch,
                       const uint8_t *key_32b, ks_nonce_state_t *nonce_state,
                       uint8_t priority);

/* Deserialize a received batch payload into a ks_batch_t structure.
   @param payload     Decrypted/decrypted batch payload bytes
   @param payload_len Number of bytes in payload
   @param batch_out   Output structure (caller-allocated)
   @return 0 on success, negative on malformed input */
int ks_deserialize_batch(const uint8_t *payload, uint16_t payload_len,
                         ks_batch_t *batch_out);

/* Get encryption policy for a message ID */
ks_encrypt_policy_t ks_get_encrypt_policy(uint16_t msg_id);

/* Set encryption policy for a message ID (can override defaults) */
void ks_set_encrypt_policy(uint16_t msg_id, ks_encrypt_policy_t policy);

#endif
