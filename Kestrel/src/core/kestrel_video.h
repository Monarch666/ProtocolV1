#ifndef KESTREL_VIDEO_H
#define KESTREL_VIDEO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Input state for KLV encoder */
typedef struct {
    uint64_t timestamp_us;   /* Precision UTC timestamp (microseconds) */
    const char *mission_id;  /* ASCII mission identifier string        */
    float heading_deg;       /* Platform heading (0-360 deg)           */
    float pitch_deg;         /* Platform pitch  (+/- 20 deg)           */
    float roll_deg;          /* Platform roll   (+/- 50 deg)           */
    int32_t lat_e7;          /* Sensor latitude  (degrees x 1e7)       */
    int32_t lon_e7;          /* Sensor longitude (degrees x 1e7)       */
    float alt_msl_m;         /* Sensor altitude above MSL (metres)     */
    float speed_mps;         /* Ground speed (m/s)                     */
} ks_klv_uav_state_t;

/* Build a full MISB ST 0601 Local Set KLV packet into out[].
 * Returns total byte count written, or -1 on error. */
int ks_klv_build_st0601(uint8_t *out, size_t out_max, const ks_klv_uav_state_t *state);

/* Verify the ST 0601 checksum (last 4 bytes).
 * Returns 0 if valid, -1 if invalid. */
int ks_klv_verify_checksum(const uint8_t *klv_packet, size_t len);

/* --- Minimal MPEG-TS Muxer --- */
#define KS_TS_PACKET_SIZE 188
#define KS_TS_PID_PAT 0
#define KS_TS_PID_PMT 4096
#define KS_TS_PID_VIDEO 256
#define KS_TS_PID_KLV 257

typedef struct {
    uint8_t cc_pat;
    uint8_t cc_pmt;
    uint8_t cc_video;
    uint8_t cc_klv;
} ks_ts_mux_t;

void ks_ts_mux_init(ks_ts_mux_t *mux);

/* Pack PAT and PMT into a 376-byte buffer (2 TS packets) */
int ks_ts_mux_write_pat_pmt(ks_ts_mux_t *mux, uint8_t *buf);

/* Pack a PES payload (KLV or H.264) into TS packets into max_out.
 * Returns bytes written (which will be a multiple of 188). */
int ks_ts_mux_write_pes(ks_ts_mux_t *mux, uint16_t pid, uint8_t stream_id, 
                        uint64_t pts, const uint8_t *payload, size_t payload_len,
                        uint8_t *buf, size_t max_out);

#ifdef __cplusplus
}
#endif

#endif /* KESTREL_VIDEO_H */
