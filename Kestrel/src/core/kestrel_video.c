#include "kestrel_video.h"
#include <string.h>

/* Universal Label for MISB ST 0601 Local Set */
static const uint8_t st0601_ul[16] = {
    0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01,
    0x0E, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00
};

static uint16_t bcc_16(const uint8_t *data, size_t size) {
    uint16_t bcc = 0xFFFF; // Init for ST 0601
    for (size_t i = 0; i < size; i++) {
        bcc ^= ((uint16_t)data[i] << 8);
        for (int j = 0; j < 8; j++) {
            if (bcc & 0x8000)
                bcc = (bcc << 1) ^ 0x1021;
            else
                bcc = (bcc << 1);
        }
    }
    return bcc;
}

static int encode_ber_len(uint8_t *buf, size_t len) {
    if (len < 128) {
        buf[0] = (uint8_t)len;
        return 1;
    } else if (len <= 0xFF) {
        buf[0] = 0x81;
        buf[1] = (uint8_t)len;
        return 2;
    } else if (len <= 0xFFFF) {
        buf[0] = 0x82;
        buf[1] = (uint8_t)(len >> 8);
        buf[2] = (uint8_t)(len & 0xFF);
        return 3;
    }
    return 0; // Unsupported
}

static int write_tlv(uint8_t *buf, uint8_t tag, const uint8_t *val, uint8_t val_len) {
    buf[0] = tag;
    int len_bytes = encode_ber_len(&buf[1], val_len);
    memcpy(&buf[1 + len_bytes], val, val_len);
    return 1 + len_bytes + val_len;
}

static void pack_uint64(uint8_t *buf, uint64_t v) {
    for (int i = 0; i < 8; i++) buf[7 - i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}
static void pack_uint32(uint8_t *buf, uint32_t v) {
    for (int i = 0; i < 4; i++) buf[3 - i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}
static void pack_uint16(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)((v >> 8) & 0xFF);
    buf[1] = (uint8_t)(v & 0xFF);
}

int ks_klv_build_st0601(uint8_t *out, size_t out_max, const ks_klv_uav_state_t *state) {
    if (!out || !state || out_max < 256) return -1;
    
    uint8_t payload[256];
    int pos = 0;
    uint8_t tmp[8];
    
    // Tag 0x41: LS Version Number = 0x11 (17)
    tmp[0] = 0x11;
    pos += write_tlv(&payload[pos], 0x41, tmp, 1);
    
    // Tag 0x02: Precision Time Stamp (8 bytes)
    pack_uint64(tmp, state->timestamp_us);
    pos += write_tlv(&payload[pos], 0x02, tmp, 8);
    
    // Tag 0x03: Mission ID
    if (state->mission_id) {
        size_t mlen = strlen(state->mission_id);
        if (mlen > 32) mlen = 32;
        pos += write_tlv(&payload[pos], 0x03, (const uint8_t *)state->mission_id, (uint8_t)mlen);
    }
    
    // Tag 0x05: Platform Heading Angle (2 bytes). Range 0 to 360 mapped to 0 to 65535
    uint16_t heading = (uint16_t)((state->heading_deg / 360.0f) * 65535.0f);
    pack_uint16(tmp, heading);
    pos += write_tlv(&payload[pos], 0x05, tmp, 2);
    
    // Tag 0x06: Platform Pitch Angle (2 bytes). Range -20 to 20 mapped to -32767 to 32767
    int16_t pitch = (int16_t)((state->pitch_deg / 20.0f) * 32767.0f);
    pack_uint16(tmp, (uint16_t)pitch);
    pos += write_tlv(&payload[pos], 0x06, tmp, 2);
    
    // Tag 0x07: Platform Roll Angle (2 bytes). Range -50 to 50
    int16_t roll = (int16_t)((state->roll_deg / 50.0f) * 32767.0f);
    pack_uint16(tmp, (uint16_t)roll);
    pos += write_tlv(&payload[pos], 0x07, tmp, 2);
    
    // Tag 0x0D: Sensor Latitude (4 bytes).
    float lat_deg = state->lat_e7 / 1e7f;
    int32_t sl_lat = (int32_t)((lat_deg / 90.0f) * 2147483647.0f);
    pack_uint32(tmp, sl_lat);
    pos += write_tlv(&payload[pos], 0x0D, tmp, 4);

    // Tag 0x0E: Sensor Longitude (4 bytes).
    float lon_deg = state->lon_e7 / 1e7f;
    int32_t sl_lon = (int32_t)((lon_deg / 180.0f) * 2147483647.0f);
    pack_uint32(tmp, sl_lon);
    pos += write_tlv(&payload[pos], 0x0E, tmp, 4);
    
    // Tag 0x0F: Sensor True Altitude (2 bytes). Range -900 to 19000
    uint16_t alt = (uint16_t)(((state->alt_msl_m + 900.0f) / 19900.0f) * 65535.0f);
    pack_uint16(tmp, alt);
    pos += write_tlv(&payload[pos], 0x0F, tmp, 2);
    
    // Tag 0x29: Ground Speed (2 bytes). 0 to 655.35 m/s. (speed * 100)
    uint16_t spd = (uint16_t)(state->speed_mps * 100.0f); 
    pack_uint16(tmp, spd);
    pos += write_tlv(&payload[pos], 0x29, tmp, 2);

    // Pre-calculate full size
    uint8_t len_bytes[4];
    // +4 accounts for the checksum tag (1 byte), length (1 byte), CRC value (2 bytes)
    int len_len = encode_ber_len(len_bytes, pos + 4); 
    
    int t_out = 0;
    memcpy(&out[t_out], st0601_ul, 16); t_out += 16;
    memcpy(&out[t_out], len_bytes, len_len); t_out += len_len;
    memcpy(&out[t_out], payload, pos); t_out += pos;
    
    // Add Checksum (Tag 0x01, Len 2)
    out[t_out++] = 0x01;
    out[t_out++] = 0x02;
    uint16_t crc = bcc_16(out, t_out);
    out[t_out++] = (uint8_t)((crc >> 8) & 0xFF);
    out[t_out++] = (uint8_t)(crc & 0xFF);
    
    return t_out;
}

int ks_klv_verify_checksum(const uint8_t *klv_packet, size_t len) {
    if (len < 20) return -1;
    if (klv_packet[len - 4] != 0x01 || klv_packet[len - 3] != 0x02) return -1;
    
    uint16_t pkt_crc = ((uint16_t)klv_packet[len - 2] << 8) | klv_packet[len - 1];
    uint16_t calc_crc = bcc_16(klv_packet, len - 2);
    
    return (pkt_crc == calc_crc) ? 0 : -1;
}

/* --- Minimal MPEG-TS Muxer --- */
void ks_ts_mux_init(ks_ts_mux_t *mux) {
    memset(mux, 0, sizeof(ks_ts_mux_t));
}

static void build_ts_header(uint8_t *buf, uint16_t pid, uint8_t pusi, uint8_t afc, uint8_t *cc) {
    buf[0] = 0x47;
    buf[1] = (pusi ? 0x40 : 0x00) | (uint8_t)((pid >> 8) & 0x1F);
    buf[2] = (uint8_t)(pid & 0xFF);
    buf[3] = ((afc & 0x3) << 4) | (*cc & 0x0F);
    *cc = (*cc + 1) & 0x0F;
}

int ks_ts_mux_write_pat_pmt(ks_ts_mux_t *mux, uint8_t *buf) {
    // Generate PAT
    memset(buf, 0xFF, KS_TS_PACKET_SIZE);
    build_ts_header(buf, KS_TS_PID_PAT, 1, 1, &mux->cc_pat); // AFC=1 (payload only)
    buf[4] = 0x00; // Pointer field
    
    static const uint8_t static_pat[] = {
        0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 
        0x00, 0x00, 0x01, 0xf0, 0x00, 0x2a, 0xb1, 0x04, 0x92
    };
    memcpy(&buf[5], static_pat, sizeof(static_pat));
    
    // Generate PMT immediately at buf+188
    uint8_t *pmt_buf = buf + KS_TS_PACKET_SIZE;
    memset(pmt_buf, 0xFF, KS_TS_PACKET_SIZE);
    build_ts_header(pmt_buf, KS_TS_PID_PMT, 1, 1, &mux->cc_pmt);
    pmt_buf[4] = 0x00; // Pointer
    
    // PMT: PID 256 -> 0x1B (H264), PID 257 -> 0x15 (Metadata). PCR PID = 256
    static const uint8_t static_pmt[] = {
        0x02, 0xb0, 0x17, 0x00, 0x01, 0xc1, 0x00, 
        0x00, 0xe1, 0x00, 0xf0, 0x00, 
        0x1b, 0xe1, 0x00, 0xf0, 0x00, // Video 256
        0x15, 0xe1, 0x01, 0xf0, 0x00, // KLV 257
        0x2e, 0xfe, 0x06, 0xda // Hardcoded CRC
    };
    memcpy(&pmt_buf[5], static_pmt, sizeof(static_pmt));
    
    return KS_TS_PACKET_SIZE * 2;
}

int ks_ts_mux_write_pes(ks_ts_mux_t *mux, uint16_t pid, uint8_t stream_id, 
                        uint64_t pts_us, const uint8_t *payload, size_t payload_len,
                        uint8_t *buf, size_t max_out) {
    if (!payload || payload_len == 0 || !buf) return 0;
    
    uint8_t *cc_ptr = (pid == KS_TS_PID_VIDEO) ? &mux->cc_video : &mux->cc_klv;
    size_t written = 0;
    int is_first = 1;
    size_t payload_offset = 0;
    
    // PTS is 33-bit value based on 90kHz clock
    uint64_t pts_90k = (pts_us * 90) / 1000;
    
    while(payload_offset < payload_len) {
        if (written + KS_TS_PACKET_SIZE > max_out) break;
        
        uint8_t *ts = &buf[written];
        memset(ts, 0xFF, KS_TS_PACKET_SIZE);
        
        size_t ts_cap = KS_TS_PACKET_SIZE - 4; 
        uint8_t afc = 1; 
        int has_pes_hdr = is_first;
        
        size_t pes_hdr_len = 14; 
        size_t available_payload_space = ts_cap;
        
        if (has_pes_hdr) {
            available_payload_space -= pes_hdr_len; 
        }
        
        size_t remain = payload_len - payload_offset;
        
        if (remain < available_payload_space) {
            afc = 3; // adapt + payload
            size_t pad_len = available_payload_space - remain;
            if (pad_len == 1) {
                ts[4] = 0; // length 0
                ts_cap -= 1;
            } else {
                ts[4] = (uint8_t)(pad_len - 1); 
                ts[5] = 0x00; // flags 
                for (size_t i = 0; i < pad_len - 2; i++) ts[6+i] = 0xFF;
                ts_cap -= pad_len;
            }
        }
        
        build_ts_header(ts, pid, is_first ? 1 : 0, afc, cc_ptr);
        int p = KS_TS_PACKET_SIZE - ts_cap;
        
        if (has_pes_hdr) {
            ts[p++] = 0x00; ts[p++] = 0x00; ts[p++] = 0x01; // PES Prefix
            ts[p++] = stream_id;
            
            // PES length (0 for unbounded video, exact for KLV)
            uint16_t plen = (stream_id == 0xE0) ? 0 : (uint16_t)(payload_len + 8);
            ts[p++] = (uint8_t)((plen >> 8) & 0xFF);
            ts[p++] = (uint8_t)(plen & 0xFF);
            
            ts[p++] = 0x80; // flags 1
            ts[p++] = 0x80; // PTS only flag
            ts[p++] = 0x05; // PES header data length
            
            ts[p++] = 0x21 | (uint8_t)(((pts_90k >> 30) & 0x07) << 1);
            ts[p++] = (uint8_t)((pts_90k >> 22) & 0xFF);
            ts[p++] = 0x01 | (uint8_t)(((pts_90k >> 15) & 0x7F) << 1);
            ts[p++] = (uint8_t)((pts_90k >> 7) & 0xFF);
            ts[p++] = 0x01 | (uint8_t)((pts_90k & 0x7F) << 1);
        }
        
        size_t chunk = (KS_TS_PACKET_SIZE - p);
        if (chunk > remain) chunk = remain;
        
        memcpy(&ts[p], &payload[payload_offset], chunk);
        payload_offset += chunk;
        
        written += KS_TS_PACKET_SIZE;
        is_first = 0;
    }
    
    return written;
}
