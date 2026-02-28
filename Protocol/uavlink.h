#ifndef UAVLINK_H
#define UAVLINK_H

#include <stdint.h>
#include <stdbool.h>

/* Base header byte 0 */
#define UL_SOF 0xA5

/* Byte 1 */
#define UL_PLEN_HI_MASK 0xF0  /* bits 7:4 -> payload length [11:8] */
#define UL_PRIORITY_MASK 0x0C /* bits 3:2 */
#define UL_PRIORITY_SHIFT 2
#define UL_STYPE_HI_MASK 0x03 /* bits 1:0 -> stream type [3:2] */

/* Byte 2 */
#define UL_STYPE_LO_MASK 0xC0 /* bits 7:6 -> stream type [1:0] */
#define UL_STYPE_LO_SHIFT 6
#define UL_PLEN_MID_MASK 0x3F /* bits 5:0 -> payload length [7:2] */

/* Byte 3 */
#define UL_PLEN_LO_MASK 0xC0    /* bits 7:6 -> payload length [1:0] */
#define UL_FLAG_ENCRYPTED 0x08  /* bit 3 */
#define UL_FLAG_FRAGMENTED 0x04 /* bit 2 */
#define UL_SEQ_HI_MASK 0x03     /* bits 1:0 -> sequence [11:10] */

/* Priority Values */
#define UL_PRIO_BULK 0
#define UL_PRIO_NORMAL 1
#define UL_PRIO_HIGH 2
#define UL_PRIO_EMERGENCY 3

/* Stream Types */
#define UL_STREAM_TELEM_FAST 0x0
#define UL_STREAM_TELEM_SLOW 0x1
#define UL_STREAM_CMD 0x2
#define UL_STREAM_CMD_ACK 0x3
#define UL_STREAM_MISSION 0x4
#define UL_STREAM_VIDEO 0x5
#define UL_STREAM_SENSOR 0x6
#define UL_STREAM_HEARTBEAT 0x7
#define UL_STREAM_ALERT 0x8
#define UL_STREAM_CUSTOM 0xF

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
} ul_header_t;

/* Message IDs */
#define UL_MSG_HEARTBEAT 0x001
#define UL_MSG_ATTITUDE 0x002
#define UL_MSG_GPS_RAW 0x003
#define UL_MSG_BATTERY 0x004
#define UL_MSG_RC_INPUT 0x005
#define UL_MSG_CMD 0x006

/* UAVLink State Machine Parser struct */
typedef enum
{
    UL_PARSE_STATE_IDLE,
    UL_PARSE_STATE_BASE_HDR,
    UL_PARSE_STATE_EXT_HDR,
    UL_PARSE_STATE_PAYLOAD,
    UL_PARSE_STATE_CRC
} ul_parse_state_t;

typedef struct
{
    ul_parse_state_t state;
    uint8_t buffer[512]; // Max packet size buffer
    uint16_t buf_idx;
    uint16_t expected_len;

    // Extracted payload fields
    ul_header_t header;
    uint8_t payload[256];
} ul_parser_t;

/* --- Nonce State Management (for secure encryption) --- */

typedef struct
{
    uint32_t counter;    // Monotonically increasing counter
    uint8_t initialized; // 1 if initialized, 0 otherwise
    uint8_t reserved[3]; // Padding for alignment
} ul_nonce_state_t;

/* --- Core Message Payloads --- */

typedef struct
{
    uint32_t system_status;
    uint8_t system_type;
    uint8_t autopilot_type;
    uint8_t base_mode;
} ul_heartbeat_t;

/* Attitude angles as float32, rates packed into float16 over the wire */
typedef struct
{
    float roll;
    float pitch;
    float yaw;
    float rollspeed;
    float pitchspeed;
    float yawspeed;
} ul_attitude_t;

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
} ul_gps_raw_t;

/* Battery status */
typedef struct
{
    uint16_t voltage;   // Battery voltage (mV)
    int16_t current;    // Battery current (cA, negative=discharging)
    int16_t remaining;  // Remaining capacity (%, -1 if unknown)
    uint8_t cell_count; // Number of cells
    uint8_t status;     // Battery status flags
} ul_battery_t;

/* RC input channels */
typedef struct
{
    uint16_t channels[8]; // RC channel values (1000-2000 us, 0=disconnected)
    uint8_t rssi;         // Signal strength (0-100%)
    uint8_t quality;      // Link quality (0-100%)
} ul_rc_input_t;

/* --- Function Prototypes --- */

/* Initialize a parser */
void ul_parser_init(ul_parser_t *p);

/* Parse a single byte from a serial stream. Returns 1 if a complete valid packet was received.
   If decryption key is non-null, handles decryption automatically. */
int ul_parse_char(ul_parser_t *p, uint8_t c, const uint8_t *key_32b);

/* Pack a complete message into a byte buffer ready for wire transmission.
   Returns the total packet length (header + payload + CRC).
   If key is non-null, payload is encrypted. */
int uavlink_pack(uint8_t *buf, const ul_header_t *h, const uint8_t *payload, const uint8_t *key_32b);

/* Serialize specific messages to a raw byte buffer */
int ul_serialize_heartbeat(const ul_heartbeat_t *hb, uint8_t *payload_buf);
int ul_deserialize_heartbeat(ul_heartbeat_t *hb, const uint8_t *payload_buf);

int ul_serialize_attitude(const ul_attitude_t *att, uint8_t *payload_buf);
int ul_deserialize_attitude(ul_attitude_t *att, const uint8_t *payload_buf);

int ul_serialize_gps_raw(const ul_gps_raw_t *gps, uint8_t *payload_buf);
int ul_deserialize_gps_raw(ul_gps_raw_t *gps, const uint8_t *payload_buf);

int ul_serialize_battery(const ul_battery_t *bat, uint8_t *payload_buf);
int ul_deserialize_battery(ul_battery_t *bat, const uint8_t *payload_buf);

int ul_serialize_rc_input(const ul_rc_input_t *rc, uint8_t *payload_buf);
int ul_deserialize_rc_input(ul_rc_input_t *rc, const uint8_t *payload_buf);

/* CRC Computations */
void ul_crc_init(uint16_t *crcAccum);
void ul_crc_accumulate(uint8_t data, uint16_t *crcAccum);

/* Encode the base 4-byte header */
void ul_encode_base_header(uint8_t *buf, const ul_header_t *h);

/* Decode the base 4-byte header */
int ul_decode_base_header(const uint8_t *buf, ul_header_t *h);

/* Encode the extended header. Returns the number of bytes written. */
int ul_encode_ext_header(uint8_t *buf, const ul_header_t *h);

/* Decode the extended header. Returns the number of bytes read. */
int ul_decode_ext_header(const uint8_t *buf, ul_header_t *h);

/* --- Nonce Management Functions --- */

/* Initialize nonce state. Must be called before first use. */
void ul_nonce_init(ul_nonce_state_t *state);

/* Generate a secure nonce using hybrid approach (counter + random).
   Combines a 32-bit counter with 32 bits of random data for maximum security.
   The nonce buffer must be at least 8 bytes. */
void ul_nonce_generate(ul_nonce_state_t *state, uint8_t nonce[8]);

/* Advanced: Pack with nonce state management.
   Automatically generates and uses a secure nonce from the state.
   Returns the total packet length (header + payload + CRC). */
int uavlink_pack_with_nonce(uint8_t *buf, const ul_header_t *h, const uint8_t *payload,
                            const uint8_t *key_32b, ul_nonce_state_t *nonce_state);

#endif
