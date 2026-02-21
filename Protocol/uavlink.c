#include "uavlink.h"
#include <string.h>
#include "monocypher.h"

/* --- CRC-16/MCRF4XX Implementation --- */
#define X25_INIT_CRC 0xFFFF
#define X25_VALIDERATE_CRC 0xF0B8

void ul_crc_init(uint16_t *crcAccum) {
    *crcAccum = X25_INIT_CRC;
}

void ul_crc_accumulate(uint8_t data, uint16_t *crcAccum) {
    uint8_t tmp;
    tmp = data ^ (uint8_t)(*crcAccum & 0xff);
    tmp ^= (tmp << 4);
    *crcAccum = (*crcAccum >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4);
}

/* Returns the MAVLink-style CRC Extra seed for the known message types */
static uint8_t ul_get_crc_seed(uint16_t msg_id) {
    switch (msg_id) {
        case UL_MSG_ATTITUDE: return 39;
        case UL_MSG_HEARTBEAT: return 50;
        default: return 0; // Unknown message
    }
}

/* --- Base Header --- */

void ul_encode_base_header(uint8_t *buf, const ul_header_t *h) {
    buf[0] = UL_SOF;
    
    buf[1] = (((h->payload_len >> 8) & 0xF) << 4)
           | ((h->priority & 0x3) << 2)
           | ((h->stream_type >> 2) & 0x3);
           
    buf[2] = ((h->stream_type & 0x3) << 6)
           | (((h->payload_len >> 2) & 0x3F));
           
    buf[3] = ((h->payload_len & 0x3) << 6)
           | ((h->encrypted ? 1:0) << 3)
           | ((h->fragmented ? 1:0) << 2)
           | ((h->sequence >> 10) & 0x3);
}

int ul_decode_base_header(const uint8_t *buf, ul_header_t *h) {
    if (buf[0] != UL_SOF) {
        return -1;
    }
    
    // buf[1] high 4 bits -> length [11:8]
    // buf[2] low 6 bits  -> length [7:2]
    // buf[3] high 2 bits -> length [1:0]
    h->payload_len = ((uint16_t)(buf[1] >> 4) << 8) | ((uint16_t)(buf[2] & 0x3F) << 2) | (buf[3] >> 6);
    
    h->priority    = (buf[1] >> 2) & 0x3;
    h->stream_type = ((buf[1] & 0x3) << 2) | ((buf[2] >> 6) & 0x3);
    h->encrypted   = (buf[3] >> 3) & 0x1;
    h->fragmented  = (buf[3] >> 2) & 0x1;
    
    h->sequence    = (buf[3] & 0x3) << 10;
    
    return 4;
}

/* --- Extended Header --- */

int ul_encode_ext_header(uint8_t *buf, const ul_header_t *h) {
    int offset = 0;
    
    uint16_t seq_sys = ((h->sequence & 0x3FF) << 6) | (h->sys_id & 0x3F);
    buf[offset++] = (seq_sys >> 8) & 0xFF;
    buf[offset++] = seq_sys & 0xFF;
    
    uint16_t comp_msg = ((h->comp_id & 0xF) << 12) | (h->msg_id & 0xFFF);
    buf[offset++] = (comp_msg >> 8) & 0xFF;
    buf[offset++] = comp_msg & 0xFF;
    
    if (h->target_sys_id != 0) {
        buf[offset++] = h->target_sys_id & 0x3F;
    }
    
    if (h->fragmented) {
        buf[offset++] = h->frag_index;
        buf[offset++] = h->frag_total;
    }
    
    if (h->encrypted) {
        memcpy(&buf[offset], h->nonce, 8);
        offset += 8;
    }
    
    return offset;
}

int ul_decode_ext_header(const uint8_t *buf, ul_header_t *h) {
    int offset = 0;
    
    uint16_t seq_sys = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    h->sequence |= (seq_sys >> 6) & 0x3FF;
    h->sys_id = seq_sys & 0x3F;
    
    uint16_t comp_msg = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    h->comp_id = (comp_msg >> 12) & 0xF;
    h->msg_id = comp_msg & 0xFFF;
    
    if (h->stream_type == UL_STREAM_CMD || h->stream_type == UL_STREAM_CMD_ACK) {
        h->target_sys_id = buf[offset++] & 0x3F;
    } else {
        h->target_sys_id = 0;
    }
    
    if (h->fragmented) {
        h->frag_index = buf[offset++];
        h->frag_total = buf[offset++];
    }
    
    if (h->encrypted) {
        memcpy(h->nonce, &buf[offset], 8);
        offset += 8;
    }
    
    return offset;
}

/* --- Float16 Serialization Helper (Simple IEEE 754 conversion) --- */
static uint16_t float_to_half(float f) {
    uint32_t x;
    memcpy(&x, &f, sizeof(x));
    
    uint16_t h = ((x >> 16) & 0x8000); // Sign
    int32_t e = ((x >> 23) & 0xFF) - 127 + 15;
    
    if (e >= 31) {
        h |= 0x7C00; 
    } else if (e > 0) {
        h |= (e << 10) | ((x >> 13) & 0x3FF);
    }
    return h;
}

static float half_to_float(uint16_t h) {
    uint32_t x = ((h & 0x8000) << 16);
    int32_t e = (h >> 10) & 0x1F;
    if (e == 0) {
        // subnormal, skip for this basic impl
    } else if (e == 31) {
        x |= 0x7F800000;
    } else {
        x |= ((e - 15 + 127) << 23) | ((h & 0x3FF) << 13);
    }
    float f;
    memcpy(&f, &x, sizeof(f));
    return f;
}

static void pack_float(uint8_t *b, float v) {
    uint32_t val;
    memcpy(&val, &v, sizeof(val));
    b[0] = val & 0xFF;
    b[1] = (val >> 8) & 0xFF;
    b[2] = (val >> 16) & 0xFF;
    b[3] = (val >> 24) & 0xFF;
}

static float unpack_float(const uint8_t *b) {
    uint32_t val = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
    float v;
    memcpy(&v, &val, sizeof(v));
    return v;
}

/* --- Message Serialization --- */

int ul_serialize_attitude(const ul_attitude_t *att, uint8_t *out) {
    pack_float(&out[0], att->roll);
    pack_float(&out[4], att->pitch);
    pack_float(&out[8], att->yaw);
    
    // Half-precision for rates to save 6 bytes
    uint16_t rs = float_to_half(att->rollspeed);
    uint16_t ps = float_to_half(att->pitchspeed);
    uint16_t ys = float_to_half(att->yawspeed);
    
    out[12] = rs & 0xFF; out[13] = rs >> 8;
    out[14] = ps & 0xFF; out[15] = ps >> 8;
    out[16] = ys & 0xFF; out[17] = ys >> 8;
    
    return 18; // We need 18 bytes because 3xfloat + 3xhalf = 12 + 6 = 18.
               // Update payload len from 14 to 18 to fix float calculation
}

int ul_deserialize_attitude(ul_attitude_t *att, const uint8_t *in) {
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

/* --- Send Pack API --- */

int uavlink_pack(uint8_t *buf, const ul_header_t *h, const uint8_t *payload, const uint8_t *key_32b) {
    ul_header_t hout = *h;
    
    if (key_32b) {
        hout.encrypted = true;
        // In a real system you must increment the nonce! Using fixed for demo.
        for(int i=0; i<8; i++) hout.nonce[i] = i; 
    } else {
        hout.encrypted = false;
    }
    
    // 1. Header
    ul_encode_base_header(buf, &hout);
    int ext_len = ul_encode_ext_header(buf + 4, &hout);
    int header_len = 4 + ext_len;
    
    // 2. Encryption & Payload
    if (hout.encrypted) {
        // Since we are mocking the truncated MAC handling for this demo, 
        // we use the raw IETF stream cipher directly for symmetric encrypt/decrypt.
        uint8_t nonce12[12] = {0};
        memcpy(nonce12, hout.nonce, 8);
        crypto_chacha20_ietf(buf + header_len, payload, hout.payload_len, key_32b, nonce12, 0);
        
        // Mock MAC tag (8 bytes)
        memset(buf + header_len + hout.payload_len, 0xAA, 8);
        header_len += 8; // Tag overhead
    } else {
        memcpy(buf + header_len, payload, hout.payload_len);
    }
    
    int packet_len_sans_crc = header_len + hout.payload_len;
    
    // 3. CRC
    uint16_t crc;
    ul_crc_init(&crc);
    for (int i = 1; i < packet_len_sans_crc; i++) { // Skip SOF [0]
        ul_crc_accumulate(buf[i], &crc);
    }
    // Seed
    ul_crc_accumulate(ul_get_crc_seed(hout.msg_id), &crc);
    
    buf[packet_len_sans_crc] = crc & 0xFF;
    buf[packet_len_sans_crc + 1] = crc >> 8;
    
    return packet_len_sans_crc + 2;
}

/* --- Streaming Receive Parser API --- */

void ul_parser_init(ul_parser_t *p) {
    memset(p, 0, sizeof(ul_parser_t));
    p->state = UL_PARSE_STATE_IDLE;
}

int ul_parse_char(ul_parser_t *p, uint8_t c, const uint8_t *key_32b) {
    switch (p->state) {
        case UL_PARSE_STATE_IDLE:
            if (c == UL_SOF) {
                p->buffer[0] = c;
                p->buf_idx = 1;
                p->state = UL_PARSE_STATE_BASE_HDR;
            }
            break;
            
        case UL_PARSE_STATE_BASE_HDR:
            p->buffer[p->buf_idx++] = c;
            if (p->buf_idx == 4) {
                if (ul_decode_base_header(p->buffer, &p->header) >= 0) {
                    p->state = UL_PARSE_STATE_EXT_HDR;
                    // Calculate extended header size based on base flags
                    p->expected_len = 4 + 4; // base 4 + fixed 4 ext
                    if (p->header.stream_type == UL_STREAM_CMD || p->header.stream_type == UL_STREAM_CMD_ACK) p->expected_len += 1; // target sys
                    if (p->header.fragmented) p->expected_len += 2;
                    if (p->header.encrypted) p->expected_len += 8; // nonce
                } else {
                    p->state = UL_PARSE_STATE_IDLE;
                }
            }
            break;
            
        case UL_PARSE_STATE_EXT_HDR:
            p->buffer[p->buf_idx++] = c;
            if (p->buf_idx == p->expected_len) {
                ul_decode_ext_header(p->buffer + 4, &p->header);
                p->expected_len += p->header.payload_len;
                if (p->header.encrypted) p->expected_len += 8; // Auth Tag is trailing
                p->state = UL_PARSE_STATE_PAYLOAD;
            }
            break;
            
        case UL_PARSE_STATE_PAYLOAD:
            p->buffer[p->buf_idx++] = c;
            if (p->buf_idx == p->expected_len) {
                p->expected_len += 2; // Add 2 for CRC
                p->state = UL_PARSE_STATE_CRC;
            }
            break;
            
        case UL_PARSE_STATE_CRC:
            p->buffer[p->buf_idx++] = c;
            if (p->buf_idx == p->expected_len) {
                // We have exactly one full packet. Verify it.
                uint16_t crc_in = p->buffer[p->buf_idx - 2] | (p->buffer[p->buf_idx - 1] << 8);
                uint16_t crc_calc;
                ul_crc_init(&crc_calc);
                for (int i = 1; i < p->buf_idx - 2; i++) {
                    ul_crc_accumulate(p->buffer[i], &crc_calc);
                }
                ul_crc_accumulate(ul_get_crc_seed(p->header.msg_id), &crc_calc);
                
                ul_parse_state_t old_state = p->state;
                if (crc_in != crc_calc) {
                    ul_parser_init(p); 
                    return -1; // CRC Error
                }
                
                // header_size is the base 4 bytes + extended header Length
                int header_size = 4;
                if (p->header.stream_type == UL_STREAM_CMD || p->header.stream_type == UL_STREAM_CMD_ACK) header_size += 1;
                if (p->header.fragmented) header_size += 2;
                if (p->header.encrypted) header_size += 8;
                
                if (p->header.encrypted) {
                    if (!key_32b) { ul_parser_init(p); return -2; } // Missing key
                    
                    uint8_t mac[16] = {0};
                    memcpy(mac, p->buffer + p->expected_len - 2 - 8, 8); // Read truncated tag
                    
                    uint8_t nonce12[12] = {0};
                    memcpy(nonce12, p->header.nonce, 8);
                    
                    // The raw stream cipher outputs to p->payload
                    crypto_chacha20_ietf(p->payload, p->buffer + header_size, p->header.payload_len, key_32b, nonce12, 0); 
                } else {
                    memcpy(p->payload, p->buffer + header_size, p->header.payload_len);
                }
                
                int valid_len = p->header.payload_len;
                // DO NOT zero the parser state out completely here, or the caller loses the payload!
                // Just reset the state machine index for the next run.
                p->state = UL_PARSE_STATE_IDLE;
                p->buf_idx = 0;
                
                return 1; // Valid Packet
            }
            break;
    }
    return 0; // Keeping parsing
}
