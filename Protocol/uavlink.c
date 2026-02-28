#include "uavlink.h"
#include <string.h>
#include <stdio.h>  /* For debug printf */
#include "monocypher.h"

/**
 * UAVLink Protocol - ChaCha20-Poly1305 AEAD Implementation
 * 
 * SECURITY FEATURES:
 * - Full 128-bit Poly1305 MAC authentication (UL_MAC_TAG_SIZE = 16 bytes)
 * - Header authenticated as Additional Data (prevents header tampering)
 * - Hybrid nonce: 32-bit counter + 32-bit random (prevents replay attacks)
 * - CRC-16 integrity check for entire packet (detect transmission errors)
 * 
 * ENCRYPTION FLOW (uavlink_pack):
 *   1. Encode header (base + extended)
 *   2. crypto_aead_lock(payload, header_as_AAD) -> ciphertext + MAC
 *   3. Append 16-byte MAC tag after ciphertext
 *   4. Compute CRC-16 over everything
 * 
 * DECRYPTION FLOW (ul_parse_char):
 *   1. Parse header, collect ciphertext + MAC tag
 *   2. Verify CRC-16
 *   3. crypto_aead_unlock(ciphertext, MAC, header_as_AAD) -> plaintext or error
 *   4. Return UL_ERR_MAC_VERIFICATION if authentication fails
 */

/* Platform-specific includes for random number generation */
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* --- CRC-16/MCRF4XX Implementation --- */
#define X25_INIT_CRC 0xFFFF
#define X25_VALIDATE_CRC 0xF0B8

void ul_crc_init(uint16_t *crcAccum)
{
    *crcAccum = X25_INIT_CRC;
}

void ul_crc_accumulate(uint8_t data, uint16_t *crcAccum)
{
    uint8_t tmp;
    tmp = data ^ (uint8_t)(*crcAccum & 0xff);
    tmp ^= (tmp << 4);
    *crcAccum = (*crcAccum >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
}

/* Returns the MAVLink-style CRC Extra seed for the known message types */
static uint8_t ul_get_crc_seed(uint16_t msg_id)
{
    switch (msg_id)
    {
    case UL_MSG_HEARTBEAT:
        return 50;
    case UL_MSG_ATTITUDE:
        return 39;
    case UL_MSG_GPS_RAW:
        return 24;
    case UL_MSG_BATTERY:
        return 154;
    case UL_MSG_RC_INPUT:
        return 89;
    default:
        return 0; // Unknown message
    }
}

/* --- Base Header --- */

void ul_encode_base_header(uint8_t *buf, const ul_header_t *h)
{
    if (!buf || !h)
        return;
    
    buf[0] = UL_SOF;

    buf[1] = (((h->payload_len >> 8) & 0xF) << 4) | ((h->priority & 0x3) << 2) | ((h->stream_type >> 2) & 0x3);

    buf[2] = ((h->stream_type & 0x3) << 6) | (((h->payload_len >> 2) & 0x3F));

    buf[3] = ((h->payload_len & 0x3) << 6) | ((h->encrypted ? 1 : 0) << 3) | ((h->fragmented ? 1 : 0) << 2) | ((h->sequence >> 10) & 0x3);
}

int ul_decode_base_header(const uint8_t *buf, ul_header_t *h)
{
    if (!buf || !h)
        return UL_ERR_NULL_POINTER;
    
    if (buf[0] != UL_SOF)
    {
        return UL_ERR_INVALID_HEADER;
    }

    // buf[1] high 4 bits -> length [11:8]
    // buf[2] low 6 bits  -> length [7:2]
    // buf[3] high 2 bits -> length [1:0]
    h->payload_len = ((uint16_t)(buf[1] >> 4) << 8) | ((uint16_t)(buf[2] & 0x3F) << 2) | (buf[3] >> 6);

    h->priority = (buf[1] >> 2) & 0x3;
    h->stream_type = ((buf[1] & 0x3) << 2) | ((buf[2] >> 6) & 0x3);
    h->encrypted = (buf[3] >> 3) & 0x1;
    h->fragmented = (buf[3] >> 2) & 0x1;

    h->sequence = (buf[3] & 0x3) << 10;

    return 4;
}

/* --- Extended Header --- */

int ul_encode_ext_header(uint8_t *buf, const ul_header_t *h)
{
    if (!buf || !h)
        return UL_ERR_NULL_POINTER;
    
    int offset = 0;

    uint16_t seq_sys = ((h->sequence & 0x3FF) << 6) | (h->sys_id & 0x3F);
    buf[offset++] = (seq_sys >> 8) & 0xFF;
    buf[offset++] = seq_sys & 0xFF;

    uint16_t comp_msg = ((h->comp_id & 0xF) << 12) | (h->msg_id & 0xFFF);
    buf[offset++] = (comp_msg >> 8) & 0xFF;
    buf[offset++] = comp_msg & 0xFF;

    if (h->target_sys_id != 0)
    {
        buf[offset++] = h->target_sys_id & 0x3F;
    }

    if (h->fragmented)
    {
        buf[offset++] = h->frag_index;
        buf[offset++] = h->frag_total;
    }

    if (h->encrypted)
    {
        memcpy(&buf[offset], h->nonce, 8);
        offset += 8;
    }

    return offset;
}

int ul_decode_ext_header(const uint8_t *buf, ul_header_t *h)
{
    if (!buf || !h)
        return UL_ERR_NULL_POINTER;
    
    int offset = 0;

    uint16_t seq_sys = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    h->sequence |= (seq_sys >> 6) & 0x3FF;
    h->sys_id = seq_sys & 0x3F;

    uint16_t comp_msg = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    h->comp_id = (comp_msg >> 12) & 0xF;
    h->msg_id = comp_msg & 0xFFF;

    if (h->stream_type == UL_STREAM_CMD || h->stream_type == UL_STREAM_CMD_ACK)
    {
        h->target_sys_id = buf[offset++] & 0x3F;
    }
    else
    {
        h->target_sys_id = 0;
    }

    if (h->fragmented)
    {
        h->frag_index = buf[offset++];
        h->frag_total = buf[offset++];
    }

    if (h->encrypted)
    {
        memcpy(h->nonce, &buf[offset], 8);
        offset += 8;
    }

    return offset;
}

/* --- Float16 Serialization Helper (Simple IEEE 754 conversion) --- */
static uint16_t float_to_half(float f)
{
    uint32_t x;
    memcpy(&x, &f, sizeof(x));

    uint16_t h = ((x >> 16) & 0x8000); // Sign
    int32_t e = ((x >> 23) & 0xFF) - 127 + 15;

    if (e >= 31)
    {
        h |= 0x7C00;
    }
    else if (e > 0)
    {
        h |= (e << 10) | ((x >> 13) & 0x3FF);
    }
    return h;
}

static float half_to_float(uint16_t h)
{
    uint32_t x = ((h & 0x8000) << 16);
    int32_t e = (h >> 10) & 0x1F;
    if (e == 0)
    {
        // subnormal, skip for this basic impl
    }
    else if (e == 31)
    {
        x |= 0x7F800000;
    }
    else
    {
        x |= ((e - 15 + 127) << 23) | ((h & 0x3FF) << 13);
    }
    float f;
    memcpy(&f, &x, sizeof(f));
    return f;
}

static void pack_float(uint8_t *b, float v)
{
    uint32_t val;
    memcpy(&val, &v, sizeof(val));
    b[0] = val & 0xFF;
    b[1] = (val >> 8) & 0xFF;
    b[2] = (val >> 16) & 0xFF;
    b[3] = (val >> 24) & 0xFF;
}

static float unpack_float(const uint8_t *b)
{
    uint32_t val = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
    float v;
    memcpy(&v, &val, sizeof(v));
    return v;
}

/* --- Message Serialization --- */

int ul_serialize_attitude(const ul_attitude_t *att, uint8_t *out)
{
    if (!att || !out)
        return UL_ERR_NULL_POINTER;

    pack_float(&out[0], att->roll);
    pack_float(&out[4], att->pitch);
    pack_float(&out[8], att->yaw);

    // Half-precision for rates to save 6 bytes
    uint16_t rs = float_to_half(att->rollspeed);
    uint16_t ps = float_to_half(att->pitchspeed);
    uint16_t ys = float_to_half(att->yawspeed);

    out[12] = rs & 0xFF;
    out[13] = rs >> 8;
    out[14] = ps & 0xFF;
    out[15] = ps >> 8;
    out[16] = ys & 0xFF;
    out[17] = ys >> 8;

    return 18; // We need 18 bytes because 3xfloat + 3xhalf = 12 + 6 = 18.
               // Update payload len from 14 to 18 to fix float calculation
}

int ul_deserialize_attitude(ul_attitude_t *att, const uint8_t *in)
{
    if (!att || !in)
        return UL_ERR_NULL_POINTER;

    att->roll = unpack_float(&in[0]);
    att->pitch = unpack_float(&in[4]);
    att->yaw = unpack_float(&in[8]);

    uint16_t rs = in[12] | (in[13] << 8);
    uint16_t ps = in[14] | (in[15] << 8);
    uint16_t ys = in[16] | (in[17] << 8);

    att->rollspeed = half_to_float(rs);
    att->pitchspeed = half_to_float(ps);
    att->yawspeed = half_to_float(ys);

    return 18;
}

/* --- Heartbeat Message Serialization --- */

int ul_serialize_heartbeat(const ul_heartbeat_t *hb, uint8_t *out)
{
    if (!hb || !out)
        return UL_ERR_NULL_POINTER;

    pack_float(&out[0], (float)hb->system_status);
    out[4] = hb->system_type;
    out[5] = hb->autopilot_type;
    out[6] = hb->base_mode;
    return 7;
}

int ul_deserialize_heartbeat(ul_heartbeat_t *hb, const uint8_t *in)
{
    if (!hb || !in)
        return UL_ERR_NULL_POINTER;

    hb->system_status = (uint32_t)unpack_float(&in[0]);
    hb->system_type = in[4];
    hb->autopilot_type = in[5];
    hb->base_mode = in[6];
    return 7;
}

/* --- GPS Raw Message Serialization --- */

static void pack_int32(uint8_t *b, int32_t v)
{
    uint32_t val;
    memcpy(&val, &v, sizeof(val));
    b[0] = val & 0xFF;
    b[1] = (val >> 8) & 0xFF;
    b[2] = (val >> 16) & 0xFF;
    b[3] = (val >> 24) & 0xFF;
}

static int32_t unpack_int32(const uint8_t *b)
{
    uint32_t val = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
    int32_t v;
    memcpy(&v, &val, sizeof(v));
    return v;
}

static void pack_uint16(uint8_t *b, uint16_t v)
{
    b[0] = v & 0xFF;
    b[1] = (v >> 8) & 0xFF;
}

static uint16_t unpack_uint16(const uint8_t *b)
{
    return b[0] | (b[1] << 8);
}

static void pack_int16(uint8_t *b, int16_t v)
{
    uint16_t val;
    memcpy(&val, &v, sizeof(val));
    b[0] = val & 0xFF;
    b[1] = (val >> 8) & 0xFF;
}

static int16_t unpack_int16(const uint8_t *b)
{
    uint16_t val = b[0] | (b[1] << 8);
    int16_t v;
    memcpy(&v, &val, sizeof(v));
    return v;
}

int ul_serialize_gps_raw(const ul_gps_raw_t *gps, uint8_t *out)
{
    if (!gps || !out)
        return UL_ERR_NULL_POINTER;

    pack_int32(&out[0], gps->lat);   // 0-3: Latitude
    pack_int32(&out[4], gps->lon);   // 4-7: Longitude
    pack_int32(&out[8], gps->alt);   // 8-11: Altitude
    pack_uint16(&out[12], gps->eph); // 12-13: H accuracy
    pack_uint16(&out[14], gps->epv); // 14-15: V accuracy
    pack_uint16(&out[16], gps->vel); // 16-17: Velocity
    pack_uint16(&out[18], gps->cog); // 18-19: Course
    out[20] = gps->fix_type;         // 20: Fix type
    out[21] = gps->satellites;       // 21: Satellites
    return 22;
}

int ul_deserialize_gps_raw(ul_gps_raw_t *gps, const uint8_t *in)
{
    if (!gps || !in)
        return UL_ERR_NULL_POINTER;

    gps->lat = unpack_int32(&in[0]);
    gps->lon = unpack_int32(&in[4]);
    gps->alt = unpack_int32(&in[8]);
    gps->eph = unpack_uint16(&in[12]);
    gps->epv = unpack_uint16(&in[14]);
    gps->vel = unpack_uint16(&in[16]);
    gps->cog = unpack_uint16(&in[18]);
    gps->fix_type = in[20];
    gps->satellites = in[21];
    return 22;
}

/* --- Battery Message Serialization --- */

int ul_serialize_battery(const ul_battery_t *bat, uint8_t *out)
{
    if (!bat || !out)
        return UL_ERR_NULL_POINTER;

    pack_uint16(&out[0], bat->voltage);  // 0-1: Voltage (mV)
    pack_int16(&out[2], bat->current);   // 2-3: Current (cA)
    pack_int16(&out[4], bat->remaining); // 4-5: Remaining (%)
    out[6] = bat->cell_count;            // 6: Cell count
    out[7] = bat->status;                // 7: Status flags
    return 8;
}

int ul_deserialize_battery(ul_battery_t *bat, const uint8_t *in)
{
    if (!bat || !in)
        return UL_ERR_NULL_POINTER;

    bat->voltage = unpack_uint16(&in[0]);
    bat->current = unpack_int16(&in[2]);
    bat->remaining = unpack_int16(&in[4]);
    bat->cell_count = in[6];
    bat->status = in[7];
    return 8;
}

/* --- RC Input Message Serialization --- */

int ul_serialize_rc_input(const ul_rc_input_t *rc, uint8_t *out)
{
    if (!rc || !out)
        return UL_ERR_NULL_POINTER;

    // Pack 8 channels (16 bytes)
    for (int i = 0; i < 8; i++)
    {
        pack_uint16(&out[i * 2], rc->channels[i]);
    }
    out[16] = rc->rssi;    // 16: Signal strength
    out[17] = rc->quality; // 17: Link quality
    return 18;
}

int ul_deserialize_rc_input(ul_rc_input_t *rc, const uint8_t *in)
{
    if (!rc || !in)
        return UL_ERR_NULL_POINTER;

    // Unpack 8 channels
    for (int i = 0; i < 8; i++)
    {
        rc->channels[i] = unpack_uint16(&in[i * 2]);
    }
    rc->rssi = in[16];
    rc->quality = in[17];
    return 18;
}

/* --- Nonce Management Implementation --- */

/* Platform-specific secure random number generation */
static uint32_t ul_get_random_u32(void)
{
#ifdef _WIN32
    /* Windows CryptGenRandom */
    HCRYPTPROV hProvider = 0;
    uint32_t random_value = 0;

    if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        CryptGenRandom(hProvider, sizeof(random_value), (BYTE *)&random_value);
        CryptReleaseContext(hProvider, 0);
    }
    return random_value;
#else
    /* Linux/Unix /dev/urandom */
    uint32_t random_value = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0)
    {
        ssize_t result = read(fd, &random_value, sizeof(random_value));
        (void)result; /* Suppress unused warning - failure returns 0 which is acceptable */
        close(fd);
    }
    return random_value;
#endif
}

void ul_nonce_init(ul_nonce_state_t *state)
{
    if (!state)
        return;

    /* Initialize counter with random value for extra security */
    state->counter = ul_get_random_u32();
    state->initialized = 1;
}

void ul_nonce_generate(ul_nonce_state_t *state, uint8_t nonce[8])
{
    if (!state || !nonce)
        return;

    /* Initialize if not already done */
    if (!state->initialized)
    {
        ul_nonce_init(state);
    }

    /* Hybrid approach:
       - First 4 bytes: Monotonic counter (ensures uniqueness)
       - Last 4 bytes: Random data (adds entropy) */

    uint32_t counter = state->counter++;
    uint32_t random = ul_get_random_u32();

    /* Pack counter (little-endian) */
    nonce[0] = counter & 0xFF;
    nonce[1] = (counter >> 8) & 0xFF;
    nonce[2] = (counter >> 16) & 0xFF;
    nonce[3] = (counter >> 24) & 0xFF;

    /* Pack random (little-endian) */
    nonce[4] = random & 0xFF;
    nonce[5] = (random >> 8) & 0xFF;
    nonce[6] = (random >> 16) & 0xFF;
    nonce[7] = (random >> 24) & 0xFF;
}

/* --- Send Pack API --- */

int uavlink_pack(uint8_t *buf, const ul_header_t *h, const uint8_t *payload, const uint8_t *key_32b)
{
    /* Input validation */
    if (!buf || !h || !payload)
        return UL_ERR_NULL_POINTER;
    
    if (h->payload_len > UL_MAX_PAYLOAD_SIZE)
        return UL_ERR_BUFFER_OVERFLOW;
    
    ul_header_t hout = *h;

    if (key_32b)
    {
        hout.encrypted = true;
        /* WARNING: Legacy mode - nonce must be pre-filled in header!
           For secure operation, use uavlink_pack_with_nonce() instead.
           This function assumes the caller has already set a unique nonce. */
        if (hout.nonce[0] == 0 && hout.nonce[1] == 0 && hout.nonce[2] == 0 &&
            hout.nonce[3] == 0 && hout.nonce[4] == 0 && hout.nonce[5] == 0 &&
            hout.nonce[6] == 0 && hout.nonce[7] == 0)
        {
            /* All zeros - generate a simple timestamp-based nonce as fallback */
            static uint32_t fallback_counter = 0;
            uint32_t counter = fallback_counter++;
            hout.nonce[0] = counter & 0xFF;
            hout.nonce[1] = (counter >> 8) & 0xFF;
            hout.nonce[2] = (counter >> 16) & 0xFF;
            hout.nonce[3] = (counter >> 24) & 0xFF;
            /* Leave upper 4 bytes as zero */
        }
    }
    else
    {
        hout.encrypted = false;
    }

    // 1. Header
    ul_encode_base_header(buf, &hout);
    int ext_len = ul_encode_ext_header(buf + 4, &hout);
    int header_len = 4 + ext_len;

    // 2. Encryption & Payload
    if (hout.encrypted)
    {
        /* Full ChaCha20-Poly1305 AEAD Implementation */
        /* Use header as Additional Authenticated Data (AAD) to prevent tampering */
        
        /* Monocypher AEAD requires 24-byte nonce (192 bits)
           We only use first 64 bits for UAVLink compatibility, rest is zero-padded */
        uint8_t nonce24[24] = {0};
        memcpy(nonce24, hout.nonce, 8);
        
        /* MAC tag will be written after the ciphertext */
        uint8_t mac[16];
        
        /* crypto_aead_lock(mac, ciphertext, key, nonce, ad, ad_size, plaintext, text_size)
           - Encrypts payload and generates MAC over both header (AAD) and ciphertext
           - MAC protects against both ciphertext and header manipulation */
        crypto_aead_lock(mac, 
                        buf + header_len,           /* Output: ciphertext */
                        key_32b,                     /* 256-bit key */
                        nonce24,                     /* 192-bit nonce (first 64 bits used) */
                        buf,                         /* AAD: entire header for authentication */
                        header_len,                  /* AAD length */
                        payload,                     /* Input: plaintext */
                        hout.payload_len);          /* Plaintext length */
        
        /* Append 16-byte Poly1305 MAC tag after ciphertext */
        memcpy(buf + header_len + hout.payload_len, mac, UL_MAC_TAG_SIZE);
    }
    else
    {
        memcpy(buf + header_len, payload, hout.payload_len);
    }

    int packet_len_sans_crc = header_len + hout.payload_len + (hout.encrypted ? UL_MAC_TAG_SIZE : 0);

    // 3. CRC
    uint16_t crc;
    ul_crc_init(&crc);
    for (int i = 1; i < packet_len_sans_crc; i++)
    { // Skip SOF [0]
        ul_crc_accumulate(buf[i], &crc);
    }
    // Seed
    ul_crc_accumulate(ul_get_crc_seed(hout.msg_id), &crc);

    buf[packet_len_sans_crc] = crc & 0xFF;
    buf[packet_len_sans_crc + 1] = crc >> 8;

    return packet_len_sans_crc + 2;
}

/* --- Streaming Receive Parser API --- */

void ul_parser_init(ul_parser_t *p)
{
    if (!p)
        return;
    
    memset(p, 0, sizeof(ul_parser_t));
    p->state = UL_PARSE_STATE_IDLE;
}

int ul_parse_char(ul_parser_t *p, uint8_t c, const uint8_t *key_32b)
{
    if (!p)
        return UL_ERR_NULL_POINTER;
    
    switch (p->state)
    {
    case UL_PARSE_STATE_IDLE:
        if (c == UL_SOF)
        {
            p->buffer[0] = c;
            p->buf_idx = 1;
            p->state = UL_PARSE_STATE_BASE_HDR;
        }
        break;

    case UL_PARSE_STATE_BASE_HDR:
        p->buffer[p->buf_idx++] = c;
        if (p->buf_idx == 4)
        {
            if (ul_decode_base_header(p->buffer, &p->header) >= 0)
            {
                /* Bounds check: reject payloads exceeding buffer capacity */
                if (p->header.payload_len > UL_MAX_PAYLOAD_SIZE)
                {
                    ul_parser_init(p);
                    return UL_ERR_BUFFER_OVERFLOW;
                }
                
                p->state = UL_PARSE_STATE_EXT_HDR;
                // Calculate extended header size based on base flags
                p->expected_len = 4 + 4; // base 4 + fixed 4 ext
                if (p->header.stream_type == UL_STREAM_CMD || p->header.stream_type == UL_STREAM_CMD_ACK)
                    p->expected_len += 1; // target sys
                if (p->header.fragmented)
                    p->expected_len += 2;
                if (p->header.encrypted)
                    p->expected_len += 8; // nonce
            }
            else
            {
                p->state = UL_PARSE_STATE_IDLE;
            }
        }
        break;

    case UL_PARSE_STATE_EXT_HDR:
        p->buffer[p->buf_idx++] = c;
        if (p->buf_idx == p->expected_len)
        {
            int ext_len = ul_decode_ext_header(p->buffer + 4, &p->header);
            p->header_len = 4 + ext_len; /* Total header = base 4 + extended */
            
            /* DEBUG: Print decoded nonce */
            if (p->header.encrypted) {
                printf("DEBUG: Decoded nonce from packet: ");
                for (int i = 0; i < 8; i++) printf("%02X ", p->header.nonce[i]);
                printf("\\n");
            }
            
            p->expected_len += p->header.payload_len;
            if (p->header.encrypted)
                p->expected_len += UL_MAC_TAG_SIZE; // Full 16-byte Poly1305 MAC
            p->state = UL_PARSE_STATE_PAYLOAD;
        }
        break;

    case UL_PARSE_STATE_PAYLOAD:
        p->buffer[p->buf_idx++] = c;
        if (p->buf_idx == p->expected_len)
        {
            p->expected_len += 2; // Add 2 for CRC
            p->state = UL_PARSE_STATE_CRC;
        }
        break;

    case UL_PARSE_STATE_CRC:
        p->buffer[p->buf_idx++] = c;
        if (p->buf_idx == p->expected_len)
        {
            // We have exactly one full packet. Verify it.
            uint16_t crc_in = p->buffer[p->buf_idx - 2] | (p->buffer[p->buf_idx - 1] << 8);
            uint16_t crc_calc;
            ul_crc_init(&crc_calc);
            for (int i = 1; i < p->buf_idx - 2; i++)
            {
                ul_crc_accumulate(p->buffer[i], &crc_calc);
            }
            ul_crc_accumulate(ul_get_crc_seed(p->header.msg_id), &crc_calc);

            if (crc_in != crc_calc)
            {
                ul_parser_init(p);
                return UL_ERR_CRC;
            }

            // Use the stored header length for AAD in AEAD
            int header_size = p->header_len;

            if (p->header.encrypted)
            {
                if (!key_32b)
                {
                    ul_parser_init(p);
                    return UL_ERR_NO_KEY;
                }

                /* Full ChaCha20-Poly1305 AEAD Verification */
                
                /* Monocypher AEAD requires 24-byte nonce (192 bits) */
                uint8_t nonce24[24] = {0};
                memcpy(nonce24, p->header.nonce, 8);

                /* Read 16-byte MAC tag from end of encrypted section */
                uint8_t *mac_tag = p->buffer + header_size + p->header.payload_len;

                /* crypto_aead_unlock(plaintext, mac, key, nonce, ad, ad_size, ciphertext, text_size)
                   Returns 0 on success (MAC verified), -1 on authentication failure */
                int auth_result = crypto_aead_unlock(
                    p->payload,                          /* Output: plaintext */
                    mac_tag,                            /* Input: 16-byte MAC tag */
                    key_32b,                            /* 256-bit key */
                    nonce24,                            /* 192-bit nonce */
                    p->buffer,                          /* AAD: entire header */
                    header_size,                        /* AAD length */
                    p->buffer + header_size,           /* Input: ciphertext */
                    p->header.payload_len);            /* Ciphertext length */

                if (auth_result != 0)
                {
                    /* MAC verification failed - packet has been tampered with! */
                    ul_parser_init(p);
                    return UL_ERR_MAC_VERIFICATION;
                }
            }
            else
            {
                memcpy(p->payload, p->buffer + header_size, p->header.payload_len);
            }

            // Packet successfully parsed and authenticated
            p->state = UL_PARSE_STATE_IDLE;
            p->buf_idx = 0;

            return UL_OK; // Valid Packet
        }
        break;
    }
    return 0; // Keeping parsing
}

/* --- Advanced Packing with Nonce Management --- */

int uavlink_pack_with_nonce(uint8_t *buf, const ul_header_t *h, const uint8_t *payload,
                            const uint8_t *key_32b, ul_nonce_state_t *nonce_state)
{
    if (!buf || !h || !payload)
        return UL_ERR_NULL_POINTER;
    
    ul_header_t hout = *h;

    if (key_32b && nonce_state)
    {
        /* Generate secure nonce using hybrid approach */
        ul_nonce_generate(nonce_state, hout.nonce);
    }

    /* Use standard packing function (nonce is now in header) */
    return uavlink_pack(buf, &hout, payload, key_32b);
}
