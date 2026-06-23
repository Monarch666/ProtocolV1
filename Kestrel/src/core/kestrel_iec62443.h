/*
 * =============================================================================
 *  kestrel_iec62443.h — IEC 62443-4-2 OT Cybersecurity Compliance Shim
 *
 *  Standard:  IEC 62443-4-2 (Industrial Cybersecurity for OT Components)
 *  Target:    Security Level 2 (SL 2) — Intentional attack, simple means
 *
 *  CR Coverage:
 *    CR 1.5  — Authenticator management (key lifecycle, expiry, revocation)
 *    CR 1.9  — Strength of public key authentication (SL level assertion)
 *    CR 2.8  — Auditable security events (14 event types in ring buffer)
 *    CR 2.9  — Audit storage capacity (128-record ring + overflow detection)
 *    CR 2.10 — Response to audit processing failures (overflow flag → GCS alert)
 *    CR 3.9  — Protection of audit information (BLAKE2b-keyed chained MAC)
 *    CR 6.1  — Audit log accessibility (file persistence + GCS query protocol)
 *    CR 6.2  — Continuous monitoring (sliding-window link anomaly detection)
 *    CR 7.1  — Denial of service protection (1-second sliding window rate limiter)
 *
 *  Design:    Pure additive shim — zero changes to kestrel.c / kestrel_fast.c
 *             / monocypher.c.  Uses Monocypher 4.0.2 crypto_blake2b_keyed()
 *             for audit integrity; no new crypto dependency introduced.
 *
 *  Key ID:    XOR-fold of all 32 key bytes into one byte.  Deterministic and
 *             stateless — the same key always maps to the same ID across
 *             reboots, which allows audit records to be correlated back to
 *             specific keys without storing extra state.
 *
 *  Audit Integrity (CR 3.9):
 *             Chained BLAKE2b-keyed MAC:
 *               MAC[0]  = BLAKE2b_{audit_key}("KS_IEC62443_v1")    [init vector]
 *               MAC[i]  = BLAKE2b_{MAC[i-1]}(record[i])
 *             Tamper with any record → chain MAC diverges from the recomputed
 *             value.  crypto_verify16() provides constant-time comparison.
 *
 *  Audit Persistence (CR 2.9 / 6.1):
 *             Opens logs/kestrel_audit.log in append mode at init.
 *             Every event is flushed as a human-readable text line immediately.
 *             The logs directory is created automatically if absent.
 *
 *  Usage:
 *    #include "kestrel_iec62443.h"
 *    ks_iec62443_ctx_t iec;
 *    ks_iec62443_init(&iec, get_time_ms(), "logs");
 *    // On every received packet:
 *    if (!ks_iec62443_dos_check(&iec, get_time_ms())) { return; } // drop
 *    int res = ks_parse_char(&parser, byte, key);
 *    ks_iec62443_monitor_update(&iec, res, get_time_ms());
 *    // After ECDH auth:
 *    ks_iec62443_audit(&iec, KS_AUDIT_AUTH_OK, key_id, sys_id, 0, now_ms);
 * =============================================================================
 */

#ifndef KESTREL_IEC62443_H
#define KESTREL_IEC62443_H

#include <stdint.h>
#include <stdbool.h>
/* NOTE: <stdio.h> is intentionally NOT included here — it triggers wchar_t
 * ordering bugs in old MinGW (6.x) when combined with <windows.h>.
 * The log_file_handle member is kept as void* (opaque FILE*) so callers
 * and platform headers never see <stdio.h> from this include chain. */
#include "kestrel.h"
#include "kestrel_keymanager.h"  /* ks_key_lifecycle_t, ks_lc_* functions */

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * § 1  Standard Metadata
 * ========================================================================= */

#define KS_IEC62443_SL_TARGET    2u    /* Compliance target: SL 2              */
#define KS_IEC62443_VERSION      1u    /* Shim module revision                 */

/*
 * CR status bitmask — each bit represents one Component Requirement.
 * Set in ctx->cr_status when the corresponding CR is actively satisfied.
 */
#define KS_CR15_LIFECYCLE        (1u << 0)  /* CR 1.5  — Key lifecycle        */
#define KS_CR19_SL_ASSERT        (1u << 1)  /* CR 1.9  — SL assertion          */
#define KS_CR28_AUDIT            (1u << 3)  /* CR 2.8  — Auditable events      */
#define KS_CR29_CAPACITY         (1u << 4)  /* CR 2.9  — Storage capacity      */
#define KS_CR39_INTEGRITY        (1u << 5)  /* CR 3.9  — Audit log integrity   */
#define KS_CR61_ACCESSIBILITY    (1u << 6)  /* CR 6.1  — Log accessibility     */
#define KS_CR62_MONITOR          (1u << 7)  /* CR 6.2  — Continuous monitoring */
#define KS_CR71_DOS              (1u << 8)  /* CR 7.1  — DoS protection        */

/* =========================================================================
 * § 2  Audit Event Types  (CR 2.8)
 * ========================================================================= */

typedef enum {
    KS_AUDIT_KEY_GENERATED   = 0x01, /* New key generated from CSPRNG          */
    KS_AUDIT_KEY_LOADED      = 0x02, /* Key loaded from file or environment    */
    KS_AUDIT_KEY_ROTATED     = 0x03, /* Atomic key rotation completed          */
    KS_AUDIT_KEY_REVOKED     = 0x04, /* Key revoked by GCS KS_MSG_KEY_REVOKE  */
    KS_AUDIT_KEY_EXPIRED     = 0x05, /* Key rejected: max_lifetime exceeded    */
    KS_AUDIT_KEY_WEAR_LIMIT  = 0x06, /* Key rejected: packet wear limit hit    */
    KS_AUDIT_AUTH_OK         = 0x07, /* ECDH + Ed25519 mutual auth succeeded   */
    KS_AUDIT_AUTH_FAIL       = 0x08, /* Ed25519 signature verification failed  */
    KS_AUDIT_MAC_FAIL        = 0x09, /* Poly1305 MAC verification failed       */
    KS_AUDIT_REPLAY_REJECT   = 0x0A, /* Packet rejected by anti-replay window  */
    KS_AUDIT_FLOOD_DETECT    = 0x0B, /* Packet rate exceeded DoS threshold     */
    KS_AUDIT_ANOMALY_DETECT  = 0x0C, /* Link error rate above anomaly limit    */
    KS_AUDIT_SL_ASSERT_FAIL  = 0x0D, /* Command blocked: SL below required    */
    KS_AUDIT_INTEGRITY_WARN  = 0x0E, /* Audit chain MAC mismatch detected      */
} ks_audit_event_t;

/** Return a short human-readable name string for an audit event. */
const char *ks_audit_event_str(ks_audit_event_t event);

/* =========================================================================
 * § 3  Audit Ring Buffer  (CR 2.8, CR 2.9, CR 3.9, CR 6.1)
 * ========================================================================= */

#define KS_AUDIT_RING_SIZE   128u   /* Must be a power of 2.  128×20 = 2560 B  */
#define KS_AUDIT_MAC_SIZE     16u   /* BLAKE2b-keyed chain MAC output (bytes)  */
#define KS_AUDIT_KEY_SIZE     16u   /* Secret HMAC key for the audit chain     */

typedef struct {
    uint32_t timestamp_ms;  /* Monotonic ms timestamp at event time            */
    uint8_t  event;         /* ks_audit_event_t value                          */
    uint8_t  key_id;        /* XOR-folded key ID (0xFF = no associated key)    */
    uint8_t  sys_id;        /* Source system ID  (1=UAV, 255=GCS, 0=internal)  */
    uint8_t  result;        /* 0 = success, non-zero = error code              */
    uint64_t packet_count;  /* ctx->total_rx at the moment of the event        */
} ks_audit_record_t;        /* 20 bytes per record                             */

typedef struct {
    ks_audit_record_t  ring[KS_AUDIT_RING_SIZE]; /* Circular event log        */
    uint32_t           head;          /* Next-write index (increments freely)  */
    uint32_t           total_logged;  /* All-time event count (never wraps)    */
    bool               overflow;      /* true once total_logged > RING_SIZE    */

    /* CR 3.9: Chained BLAKE2b-keyed MAC over all records in insertion order  */
    uint8_t  chain_mac[KS_AUDIT_MAC_SIZE]; /* Rolling MAC state               */
    uint8_t  audit_key[KS_AUDIT_KEY_SIZE]; /* Secret HMAC key (CSPRNG, init)  */

    /* CR 6.1: File-backed persistent log */
    void    *log_file_handle; /* Opaque FILE* — cast in kestrel_iec62443.c   */
} ks_audit_ctx_t;

/* =========================================================================
 * § 4  DoS Rate Limiter  (CR 7.1)
 * ========================================================================= */

#define KS_FLOOD_WINDOW_MS    1000u  /* 1-second sliding window duration       */
#define KS_FLOOD_MAX_PKTS     200u   /* Maximum acceptable packets per second  */
#define KS_FLOOD_ALERT_PCT     80u   /* Audit alert at 80 % of threshold       */

typedef struct {
    uint32_t window_start_ms; /* Timestamp of current window's opening        */
    uint32_t pkt_count;       /* Packets observed in the current window        */
    uint32_t total_alerts;    /* All-time flood-alert count                    */
    bool     flood_active;    /* true = currently above the flood threshold    */
} ks_dos_guard_t;

/* =========================================================================
 * § 5  Continuous Link Monitor  (CR 6.2)
 * ========================================================================= */

#define KS_ANOMALY_WINDOW_PKTS   50u  /* Sliding window size (packet count)   */
#define KS_ANOMALY_ERROR_PCT     20u  /* Alert threshold: > 20 % error rate   */

typedef struct {
    uint32_t window_rx;         /* Packets counted in current window           */
    uint32_t window_err;        /* Error packets in current window             */
    uint8_t  error_rate_pct;    /* Current error rate 0-100                   */
    bool     anomaly_active;    /* true = anomaly threshold breached           */
} ks_monitor_t;

/* =========================================================================
 * § 6  Combined IEC 62443-4-2 Context
 * ========================================================================= */

typedef struct ks_iec62443_ctx_s {
    ks_audit_ctx_t  audit;    /* CR 2.8 / 2.9 / 3.9 / 6.1                     */
    ks_dos_guard_t  dos;      /* CR 7.1                                         */
    ks_monitor_t    monitor;  /* CR 6.2                                         */
    uint16_t        cr_status;/* Bitmask of currently-passing CRs               */
    uint64_t        total_rx; /* Total packets ever seen (used in audit records) */
} ks_iec62443_ctx_t;

/* =========================================================================
 * § 7  Public API
 * ========================================================================= */

/**
 * Initialise the full IEC 62443-4-2 compliance context.
 *
 * @param ctx      Compliance context (caller allocated, may be on stack/static)
 * @param now_ms   Current monotonic timestamp in milliseconds
 * @param log_dir  Directory for audit log persistence (e.g. "logs").
 *                 Pass NULL to disable file persistence (RAM-only mode).
 *                 The directory is created automatically if it does not exist.
 *
 * Generates a 16-byte BLAKE2b chain key from the platform CSPRNG.
 * Call once at startup before any other ks_iec62443_* functions.
 */
void ks_iec62443_init(ks_iec62443_ctx_t *ctx, uint32_t now_ms,
                      const char *log_dir);

/**
 * Flush and close the persistent audit log file.
 * Zeroes the audit key from memory.
 * Call at application shutdown / SIGTERM handler.
 */
void ks_iec62443_destroy(ks_iec62443_ctx_t *ctx);

/**
 * CR 2.8: Log an audit event into the ring buffer.
 *
 * Atomically extends the BLAKE2b chain MAC (CR 3.9) and immediately flushes
 * the record to the log file if persistence is enabled (CR 6.1).
 *
 * @param ctx       Compliance context
 * @param event     Event type (ks_audit_event_t)
 * @param key_id    Key identifier — use ks_iec62443_key_id() to derive from key.
 *                  Pass 0xFF if the event has no associated key.
 * @param sys_id    Source system ID  (1=UAV, 255=GCS, 0=internal)
 * @param result    0 = success; non-zero = relevant error code
 * @param now_ms    Current monotonic timestamp in milliseconds
 */
void ks_iec62443_audit(ks_iec62443_ctx_t *ctx, ks_audit_event_t event,
                       uint8_t key_id, uint8_t sys_id, uint8_t result,
                       uint32_t now_ms);

/**
 * CR 7.1: Feed one received packet into the DoS rate limiter.
 *
 * Returns true  — packet is within rate limits, proceed normally.
 * Returns false — packet rate exceeds KS_FLOOD_MAX_PKTS/s; caller should drop.
 *
 * Also increments ctx->total_rx (used in audit record packet_count field).
 * Automatically logs KS_AUDIT_FLOOD_DETECT when the alert threshold (80 %) is
 * first crossed within a window.
 */
bool ks_iec62443_dos_check(ks_iec62443_ctx_t *ctx, uint32_t now_ms);

/**
 * CR 6.2: Feed a ks_parse_char() return value into the link anomaly monitor.
 *
 * Complete packets (parse_result > 0) and errors (parse_result < 0) are
 * counted. Incomplete/partial bytes (parse_result == 0) are ignored.
 * Logs KS_AUDIT_ANOMALY_DETECT on the first threshold breach per window.
 *
 * Returns true if an anomaly is currently active.
 */
bool ks_iec62443_monitor_update(ks_iec62443_ctx_t *ctx, int parse_result,
                                uint32_t now_ms);

/**
 * CR 3.9: Verify the audit log's BLAKE2b chain MAC integrity.
 *
 * Recomputes the chain MAC from the initial vector over all records currently
 * in the ring and compares it with ctx->audit.chain_mac using a constant-time
 * comparison (crypto_verify16).
 *
 * Returns true  — chain is intact; no tampering detected.
 * Returns false — chain MAC mismatch; possible in-memory tampering.
 *
 * NOTE: The chain MAC is a runtime guarantee only.  It does not survive
 * across reboots because the audit_key is generated from CSPRNG at init.
 * The persistent log file (kestrel_audit.log) provides cross-reboot records.
 */
bool ks_iec62443_audit_integrity_ok(const ks_iec62443_ctx_t *ctx);

/**
 * CR 6.1: Print the most recent `last_n` audit records to stdout.
 *
 * Pass 0 to dump all records currently in the ring (up to RING_SIZE).
 * Intended for ground export and GCS manual audit review.
 */
void ks_iec62443_audit_dump(const ks_iec62443_ctx_t *ctx, uint32_t last_n);

/**
 * CR 2.9: Returns true if the audit ring has ever overflowed (records lost).
 * The caller should send KS_MSG_SEC_STATUS to the GCS alerting of this.
 */
bool ks_iec62443_audit_overflow(const ks_iec62443_ctx_t *ctx);

/**
 * Compute an 8-bit key ID by XOR-folding all 32 bytes of a session key.
 *
 * The same 32-byte key always produces the same ID — deterministic, stateless,
 * and consistent across reboots.  Used to correlate audit records back to
 * specific keys when reviewing the persistent log after a reboot.
 */
uint8_t ks_iec62443_key_id(const uint8_t key[32]);

/**
 * Compliance status string for telemetry / GCS display.
 *
 * Format: "IEC62443-4-2 SL2: [OK|WARN] CR=0x%04X audit=%u overflow=%s
 *          dos_alerts=%u anomaly=%s integrity=%s"
 *
 * Writes into caller-provided buf (minimum 192 bytes).  Returns buf.
 */
const char *ks_iec62443_status_str(const ks_iec62443_ctx_t *ctx,
                                   char *buf, int buf_len);

#ifdef __cplusplus
}
#endif

#endif /* KESTREL_IEC62443_H */
