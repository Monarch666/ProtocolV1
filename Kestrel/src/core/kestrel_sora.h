/*
 * =============================================================================
 *  kestrel_sora.h — JARUS SORA OSO#06 Cyber Safety Compliance Shim
 *
 *  Standard:   JARUS SORA (Specific Operations Risk Assessment), Annex E
 *              Operational Safety Objective #06 — C2 Link Cyber Security
 *
 *  Requirement: The C2 link must guarantee Confidentiality, Integrity, and
 *               Mutual Authentication (CIA triad) at a robustness level
 *               matching the SAIL (Specific Assurance and Integrity Level).
 *
 *  Design:     Pure additive shim — zero changes to kestrel.c / kestrel.h.
 *              Hooks into existing error return codes (KS_ERR_REPLAY,
 *              KS_ERR_MAC_VERIFICATION) and ECDH state-machine transitions.
 *
 *  Compliance mapping:
 *    Confidentiality   → ChaCha20-Poly1305 session (kestrel core, always on)
 *    Integrity         → Poly1305 128-bit MAC     (kestrel core, always on)
 *    Anti-replay       → 32-bit sliding window    (kestrel core, always on)
 *    Mutual auth       → X25519 ECDH + Ed25519 sig (kestrel handshake)
 *    Security logging  → THIS MODULE               ← OSO#06 gap being filled
 *
 *  Usage:
 *    #include "kestrel_sora.h"
 *    // At startup:
 *    ks_sora_init();
 *    // On any ks_parse_char / ks_parse_char_zerocopy return value:
 *    ks_sora_on_parse_result(result, sys_id, sequence, get_time_ms());
 *    // On ECDH events:
 *    ks_sora_log(KS_SORA_MUTUAL_AUTH_OK, get_time_ms(), sys_id, sequence, 0);
 *    // Query compliance:
 *    if (ks_sora_is_compliant()) { ... }
 *    // Dump audit log to stdout:
 *    ks_sora_dump();
 * =============================================================================
 */

#ifndef KESTREL_SORA_H
#define KESTREL_SORA_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- SORA Event Types ---- */
typedef enum {
    KS_SORA_REPLAY_REJECTED  = 0x01,  /* Packet rejected by replay window    */
    KS_SORA_MAC_FAIL         = 0x02,  /* Poly1305 MAC authentication failure  */
    KS_SORA_MUTUAL_AUTH_OK   = 0x03,  /* ECDH + EdDSA handshake succeeded     */
    KS_SORA_MUTUAL_AUTH_FAIL = 0x04,  /* EdDSA signature verification failed  */
    KS_SORA_KEY_ROTATED      = 0x05,  /* Session key rotated / established    */
    KS_SORA_LINK_ANOMALY     = 0x06,  /* Unexplained link gap (SSPR-4 analog) */
    KS_SORA_NO_KEY           = 0x07,  /* Encrypted packet received w/o key    */
} ks_sora_event_t;

/* ---- Ring Buffer Entry ---- */
#define KS_SORA_RING_SIZE  64u        /* Must be power of 2 */

typedef struct {
    uint32_t timestamp_ms;            /* Monotonic millisecond timestamp      */
    uint8_t  event;                   /* ks_sora_event_t value                */
    uint8_t  sys_id;                  /* Source system ID (UAV=1, GCS=255)    */
    uint16_t _pad1;                   /* Alignment padding                    */
    uint32_t sequence;                /* 32-bit packet sequence/nonce counter */
    uint8_t  result;                  /* 0=OK / non-zero=error code           */
    uint8_t  _pad2[3];                /* Alignment padding                    */
} ks_sora_record_t;                   /* 16 bytes per record                  */

/* ---- Compliance Context ---- */
typedef struct {
    ks_sora_record_t ring[KS_SORA_RING_SIZE]; /* Circular event log           */
    uint32_t head;                    /* Next write index (wraps with mask)   */
    uint32_t total_logged;            /* Total events ever logged (no wraps)  */

    /* Running counters for fast compliance check */
    uint32_t auth_ok_count;           /* Successful mutual auth events        */
    uint32_t auth_fail_count;         /* Failed EdDSA / MITM events           */
    uint32_t mac_fail_count;          /* MAC verification failures            */
    uint32_t replay_count;            /* Replay-rejected events               */
    uint32_t key_rotated_count;       /* Session key rotations                */
    uint32_t link_anomaly_count;      /* Link gap / interference events       */
} ks_sora_ctx_t;

/*
 * SORA compliance thresholds.
 * Tune these per deployment SAIL level:
 *   SAIL I-II  → thresholds are advisory (soft warning)
 *   SAIL III+  → thresholds trigger operational response
 *
 * A MAC fail count > 3 without a corresponding auth_ok is a strong
 * indicator of an active MITM attack and MUST trigger link termination.
 */
#define KS_SORA_MAC_FAIL_THRESHOLD   3u   /* Max MAC failures before non-compliant */
#define KS_SORA_REPLAY_THRESHOLD     10u  /* Max replays before non-compliant       */
#define KS_SORA_AUTH_REQUIRED        1u   /* Min successful mutual auth events      */

/* ---- Public API ---- */

/**
 * Initialise the SORA compliance context.
 * Call once at startup before any parse or log calls.
 * Thread-safety: not thread-safe — single-threaded embedded use only.
 */
void ks_sora_init(ks_sora_ctx_t *ctx);

/**
 * Log a security event into the ring buffer.
 *
 * @param ctx          Compliance context
 * @param event        Event type (ks_sora_event_t)
 * @param timestamp_ms Current time in milliseconds (from get_time_ms())
 * @param sys_id       Source system ID (1=UAV, 255=GCS)
 * @param sequence     Packet sequence number at time of event (0 if unknown)
 * @param result       Error code or 0 for success
 */
void ks_sora_log(ks_sora_ctx_t *ctx, ks_sora_event_t event,
                 uint32_t timestamp_ms, uint8_t sys_id,
                 uint32_t sequence, uint8_t result);

/**
 * Convenience helper: call this directly with the return value of
 * ks_parse_char() or ks_parse_char_zerocopy().  Automatically maps
 * negative error codes to the correct SORA event type.
 *
 * @param ctx          Compliance context
 * @param parse_result Return value from ks_parse_char / ks_parse_char_zerocopy
 * @param sys_id       Source system ID
 * @param sequence     Sequence number from parsed header (use 0 if not decoded yet)
 * @param timestamp_ms Current time
 */
void ks_sora_on_parse_result(ks_sora_ctx_t *ctx, int parse_result,
                             uint8_t sys_id, uint32_t sequence,
                             uint32_t timestamp_ms);

/**
 * Evaluate OSO#06 compliance based on logged events.
 *
 * Returns true  if:
 *   - At least one successful mutual authentication has occurred
 *   - MAC failure count is below KS_SORA_MAC_FAIL_THRESHOLD
 *   - Replay rejection count is below KS_SORA_REPLAY_THRESHOLD
 *   - No unmitigated auth failure (auth_fail not followed by auth_ok)
 *
 * Returns false if any of the above conditions are violated.
 *
 * IMPORTANT: Returns false if ks_sora_init() has not been called yet
 * (auth_ok_count == 0 on fresh context).
 */
bool ks_sora_is_compliant(const ks_sora_ctx_t *ctx);

/**
 * Print the full ring buffer contents to stdout.
 * Intended for ground audit logging, not for flight-critical paths.
 */
void ks_sora_dump(const ks_sora_ctx_t *ctx);

/**
 * Return a one-line human-readable SORA status string for telemetry display.
 * Format: "SORA OSO#06: [COMPLIANT|NON-COMPLIANT] auth=N mac_fail=N replay=N"
 * Writes into buf (caller provides, min 128 bytes). Returns buf pointer.
 */
const char *ks_sora_status_str(const ks_sora_ctx_t *ctx, char *buf, int buf_len);

/**
 * Return a read-only pointer to the raw counters for external monitoring.
 * Caller must not modify the returned structure.
 */
const ks_sora_ctx_t *ks_sora_get_ctx(const ks_sora_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* KESTREL_SORA_H */
