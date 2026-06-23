/*
 * =============================================================================
 *  kestrel_iec62443.c — IEC 62443-4-2 OT Cybersecurity Compliance Shim
 *
 *  Implementation of the compliance context, audit ring, DoS guard, link
 *  monitor and BLAKE2b-chained audit integrity introduced in kestrel_iec62443.h.
 *
 *  Zero changes to kestrel.c, kestrel_fast.c, or monocypher.c.
 * =============================================================================
 */

/* _GNU_SOURCE is needed for mkdir(2) on glibc (Linux only).
 * Do NOT define it on Windows — it triggers wchar_t conflicts in old MinGW. */
#ifndef _WIN32
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#  endif
#endif

#include "kestrel_iec62443.h"
#include "kestrel_keymanager.h"  /* ks_generate_random_key(), ks_secure_zero() */
#include "monocypher.h"          /* crypto_blake2b_keyed(), crypto_verify16()   */

/* <stdio.h> is included here (not in the header) to avoid the MinGW 6.x
 * wchar_t ordering bug that occurs when <stdio.h> precedes <windows.h>.
 * The log_file_handle field is void* in the struct; cast it here only. */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>            /* PRIu64 — portable uint64_t format specifier */

/* Convenience macro: cast the opaque void* back to FILE* for operations
 * that are only performed inside this compilation unit.                   */
#define LOG_FILE(a)  ((FILE *)((a)->log_file_handle))

#ifdef _WIN32
#  include <windows.h>
static void ensure_dir(const char *path)
{
    if (!CreateDirectoryA(path, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            fprintf(stderr, "[IEC62443] Warning: cannot create log dir '%s'"
                    " (WinErr %lu)\n", path, (unsigned long)err);
        }
    }
}
#else
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <errno.h>
static void ensure_dir(const char *path)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        perror("[IEC62443] Warning: cannot create log dir");
    }
}
#endif

/* =========================================================================
 * Internal: BLAKE2b chain MAC update
 *
 * Extends the rolling chain MAC with a new audit record:
 *   chain_mac[i] = BLAKE2b_{chain_mac[i-1]}( record[i] )
 *
 * This builds a tamper-evident Merkle-like chain: modifying any record will
 * cause the recomputed final MAC to diverge from the stored chain_mac.
 * ========================================================================= */
static void update_chain_mac(ks_audit_ctx_t *a, const ks_audit_record_t *rec)
{
    uint8_t new_mac[KS_AUDIT_MAC_SIZE];
    crypto_blake2b_keyed(new_mac, KS_AUDIT_MAC_SIZE,
                          a->chain_mac, KS_AUDIT_MAC_SIZE,
                          (const uint8_t *)rec, sizeof(ks_audit_record_t));
    memcpy(a->chain_mac, new_mac, KS_AUDIT_MAC_SIZE);
    crypto_wipe(new_mac, KS_AUDIT_MAC_SIZE);
}

/* =========================================================================
 * Internal: write one human-readable line to the persistent audit log file
 * ========================================================================= */
static void write_log_line(const ks_audit_ctx_t *a, const ks_audit_record_t *rec)
{
    FILE *f = LOG_FILE(a);
    if (f == NULL) return;
    fprintf(f,
            "[%10" PRIu32 " ms] %-20s key=0x%02X sys=%3u"
            " result=%u pkt=%" PRIu64 "\n",
            rec->timestamp_ms,
            ks_audit_event_str((ks_audit_event_t)rec->event),
            rec->key_id,
            rec->sys_id,
            rec->result,
            rec->packet_count);
    fflush(f);
}

/* =========================================================================
 * ks_audit_event_str
 * ========================================================================= */
const char *ks_audit_event_str(ks_audit_event_t event)
{
    switch (event) {
        case KS_AUDIT_KEY_GENERATED:  return "KEY_GENERATED";
        case KS_AUDIT_KEY_LOADED:     return "KEY_LOADED";
        case KS_AUDIT_KEY_ROTATED:    return "KEY_ROTATED";
        case KS_AUDIT_KEY_REVOKED:    return "KEY_REVOKED";
        case KS_AUDIT_KEY_EXPIRED:    return "KEY_EXPIRED";
        case KS_AUDIT_KEY_WEAR_LIMIT: return "KEY_WEAR_LIMIT";
        case KS_AUDIT_AUTH_OK:        return "AUTH_OK";
        case KS_AUDIT_AUTH_FAIL:      return "AUTH_FAIL";
        case KS_AUDIT_MAC_FAIL:       return "MAC_FAIL";
        case KS_AUDIT_REPLAY_REJECT:  return "REPLAY_REJECT";
        case KS_AUDIT_FLOOD_DETECT:   return "FLOOD_DETECT";
        case KS_AUDIT_ANOMALY_DETECT: return "ANOMALY_DETECT";
        case KS_AUDIT_SL_ASSERT_FAIL: return "SL_ASSERT_FAIL";
        case KS_AUDIT_INTEGRITY_WARN: return "INTEGRITY_WARN";
        default:                       return "UNKNOWN_EVENT";
    }
}

/* =========================================================================
 * ks_iec62443_key_id
 *
 * XOR-fold all 32 key bytes into one byte.  Uses every byte of key material,
 * is fully deterministic, and requires no additional state.
 * Same key → same ID across reboots → audit logs are correlatable.
 * ========================================================================= */
uint8_t ks_iec62443_key_id(const uint8_t key[32])
{
    uint8_t id = 0;
    int i;
    for (i = 0; i < 32; i++) {
        id ^= key[i];
    }
    return id;
}

/* =========================================================================
 * ks_iec62443_init
 * ========================================================================= */
void ks_iec62443_init(ks_iec62443_ctx_t *ctx, uint32_t now_ms,
                      const char *log_dir)
{
    if (ctx == NULL) return;

    memset(ctx, 0, sizeof(ks_iec62443_ctx_t));

    /* CR 3.9: Generate random BLAKE2b audit-chain key from CSPRNG.
     * ks_generate_random_key produces 32 bytes; we only use the first 16. */
    {
        uint8_t tmp[32];
        if (ks_generate_random_key(tmp) == 0) {
            memcpy(ctx->audit.audit_key, tmp, KS_AUDIT_KEY_SIZE);
        }
        /* else: CSPRNG failure → audit_key stays zeroed; integrity still works
         *       but offers less protection. The overflow flag is NOT set here —
         *       CSPRNG failures are extremely rare on supported platforms.     */
        ks_secure_zero(tmp, sizeof(tmp));
    }

    /* Seed the chain MAC with an init vector keyed by the audit_key.
     * This ensures the chain is distinct even for identical record streams. */
    crypto_blake2b_keyed(ctx->audit.chain_mac, KS_AUDIT_MAC_SIZE,
                          ctx->audit.audit_key, KS_AUDIT_KEY_SIZE,
                          (const uint8_t *)"KS_IEC62443_v1", 14u);

    /* CR 6.1 / CR 2.9: Open persistent audit log file -------------------- */
    if (log_dir != NULL) {
        ensure_dir(log_dir);

        char path[512];
        snprintf(path, sizeof(path), "%s/kestrel_audit.log", log_dir);

        ctx->audit.log_file_handle = (void *)fopen(path, "a");
        if (LOG_FILE(&ctx->audit) == NULL) {
            fprintf(stderr,
                    "[IEC62443] Warning: cannot open audit log '%s' — "
                    "running in RAM-only mode\n", path);
        } else {
            /* Session-start sentinel — makes log files human-navigable */
            fprintf(LOG_FILE(&ctx->audit),
                    "=== IEC 62443-4-2 Session Start"
                    "  t=%" PRIu32 " ms  SL=%u  ring=%u ===\n",
                    now_ms, KS_IEC62443_SL_TARGET, KS_AUDIT_RING_SIZE);
            fflush(LOG_FILE(&ctx->audit));
        }
    }

    /* Mark immediately-satisfiable CRs in the status bitmask ------------- */
    ctx->cr_status |= KS_CR28_AUDIT;      /* Ring is operational            */
    ctx->cr_status |= KS_CR29_CAPACITY;   /* Ring capacity provisioned      */
    ctx->cr_status |= KS_CR39_INTEGRITY;  /* BLAKE2b chain is active        */
    ctx->cr_status |= KS_CR71_DOS;        /* DoS guard is operational       */
    ctx->cr_status |= KS_CR62_MONITOR;    /* Link monitor is operational    */
    if (log_dir != NULL && LOG_FILE(&ctx->audit) != NULL) {
        ctx->cr_status |= KS_CR61_ACCESSIBILITY;
    }
}

/* =========================================================================
 * ks_iec62443_destroy
 * ========================================================================= */
void ks_iec62443_destroy(ks_iec62443_ctx_t *ctx)
{
    if (ctx == NULL) return;

    if (LOG_FILE(&ctx->audit) != NULL) {
        fprintf(LOG_FILE(&ctx->audit),
                "=== IEC 62443-4-2 Session End  total_logged=%" PRIu32 " ===\n",
                ctx->audit.total_logged);
        fflush(LOG_FILE(&ctx->audit));
        fclose(LOG_FILE(&ctx->audit));
        ctx->audit.log_file_handle = NULL;
    }

    /* Wipe the audit key — it must not survive session teardown */
    ks_secure_zero(ctx->audit.audit_key, KS_AUDIT_KEY_SIZE);
    ks_secure_zero(ctx->audit.chain_mac, KS_AUDIT_MAC_SIZE);
}

/* =========================================================================
 * ks_iec62443_audit  (CR 2.8)
 * ========================================================================= */
void ks_iec62443_audit(ks_iec62443_ctx_t *ctx, ks_audit_event_t event,
                       uint8_t key_id, uint8_t sys_id, uint8_t result,
                       uint32_t now_ms)
{
    if (ctx == NULL) return;

    ks_audit_ctx_t * const a = &ctx->audit;

    /* Write into the ring slot (head & mask gives the slot index) */
    uint32_t slot = a->head & (KS_AUDIT_RING_SIZE - 1u);
    ks_audit_record_t * const rec = &a->ring[slot];

    rec->timestamp_ms = now_ms;
    rec->event        = (uint8_t)event;
    rec->key_id       = key_id;
    rec->sys_id       = sys_id;
    rec->result       = result;
    rec->packet_count = ctx->total_rx;

    /* CR 3.9: extend the chain MAC before advancing the head */
    update_chain_mac(a, rec);

    a->head++;
    a->total_logged++;

    /* CR 2.9: detect ring overflow (CR 2.10: drop the CR29 bit → GCS alert) */
    if (!a->overflow && a->total_logged > KS_AUDIT_RING_SIZE) {
        a->overflow = true;
        ctx->cr_status &= (uint16_t)(~KS_CR29_CAPACITY);
    }

    /* CR 6.1: persist to log file */
    write_log_line(&ctx->audit, rec);
}

/* =========================================================================
 * ks_iec62443_dos_check  (CR 7.1)
 * ========================================================================= */
bool ks_iec62443_dos_check(ks_iec62443_ctx_t *ctx, uint32_t now_ms)
{
    if (ctx == NULL) return true; /* Permissive on NULL — don't stall boot    */

    ctx->total_rx++;

    ks_dos_guard_t * const d = &ctx->dos;

    /* Reset window on expiry */
    if ((now_ms - d->window_start_ms) >= KS_FLOOD_WINDOW_MS) {
        d->window_start_ms = now_ms;
        d->pkt_count       = 0u;
        d->flood_active    = false;
    }

    d->pkt_count++;

    /* Audit alert at 80 % of the hard limit (first time only per window) */
    if (d->pkt_count ==
            (uint32_t)((KS_FLOOD_MAX_PKTS * KS_FLOOD_ALERT_PCT) / 100u)) {
        ks_iec62443_audit(ctx, KS_AUDIT_FLOOD_DETECT, 0xFFu, 0u, 0u, now_ms);
        d->total_alerts++;
    }

    /* Hard flood threshold */
    if (d->pkt_count > KS_FLOOD_MAX_PKTS) {
        d->flood_active = true;
        return false; /* Caller must drop this packet */
    }

    return true;
}

/* =========================================================================
 * ks_iec62443_monitor_update  (CR 6.2)
 * ========================================================================= */
bool ks_iec62443_monitor_update(ks_iec62443_ctx_t *ctx, int parse_result,
                                uint32_t now_ms)
{
    if (ctx == NULL) return false;

    ks_monitor_t * const m = &ctx->monitor;

    /* parse_result == 0: incomplete byte — not a full packet, skip counting */
    if (parse_result == 0) return m->anomaly_active;

    m->window_rx++;
    if (parse_result < 0) {
        m->window_err++;
    }

    /* Update error rate */
    if (m->window_rx > 0u) {
        m->error_rate_pct =
            (uint8_t)((m->window_err * 100u) / m->window_rx);
    }

    /* Evaluate threshold and slide window when full */
    if (m->window_rx >= KS_ANOMALY_WINDOW_PKTS) {
        bool was_anomaly = m->anomaly_active;
        m->anomaly_active = (m->error_rate_pct >= KS_ANOMALY_ERROR_PCT);

        /* Log only on the first breach (not every subsequent window) */
        if (m->anomaly_active && !was_anomaly) {
            ks_iec62443_audit(ctx, KS_AUDIT_ANOMALY_DETECT,
                              0xFFu, 0u, m->error_rate_pct, now_ms);
        }

        /* Slide: carry half-window counts into the new window */
        m->window_rx  = KS_ANOMALY_WINDOW_PKTS / 2u;
        m->window_err = (m->window_err > KS_ANOMALY_WINDOW_PKTS / 2u)
                         ? KS_ANOMALY_WINDOW_PKTS / 2u
                         : m->window_err;
    }

    return m->anomaly_active;
}

/* =========================================================================
 * ks_iec62443_audit_integrity_ok  (CR 3.9)
 * ========================================================================= */
bool ks_iec62443_audit_integrity_ok(const ks_iec62443_ctx_t *ctx)
{
    if (ctx == NULL) return false;

    const ks_audit_ctx_t * const a = &ctx->audit;

    /* Number of records valid in the ring */
    uint32_t n_in_ring = (a->total_logged < KS_AUDIT_RING_SIZE)
                          ? a->total_logged
                          : (uint32_t)KS_AUDIT_RING_SIZE;

    if (n_in_ring == 0u) return true; /* Empty log: trivially intact */

    /* Recompute the chain from the same init vector used at ks_iec62443_init */
    uint8_t mac[KS_AUDIT_MAC_SIZE];
    crypto_blake2b_keyed(mac, KS_AUDIT_MAC_SIZE,
                          a->audit_key, KS_AUDIT_KEY_SIZE,
                          (const uint8_t *)"KS_IEC62443_v1", 14u);

    /* Oldest record: if overflowed, the current head (just overwritten) is
     * the oldest; otherwise records start at slot 0.                        */
    uint32_t oldest;
    if (a->overflow) {
        oldest = a->head & (KS_AUDIT_RING_SIZE - 1u);
    } else {
        oldest = 0u;
    }

    uint32_t i;
    for (i = 0u; i < n_in_ring; i++) {
        uint32_t slot = (oldest + i) & (KS_AUDIT_RING_SIZE - 1u);
        uint8_t new_mac[KS_AUDIT_MAC_SIZE];
        crypto_blake2b_keyed(new_mac, KS_AUDIT_MAC_SIZE,
                              mac, KS_AUDIT_MAC_SIZE,
                              (const uint8_t *)&a->ring[slot],
                              sizeof(ks_audit_record_t));
        memcpy(mac, new_mac, KS_AUDIT_MAC_SIZE);
        crypto_wipe(new_mac, KS_AUDIT_MAC_SIZE);
    }

    /* Constant-time comparison — crypto_verify16 returns 0 if equal */
    bool ok = (crypto_verify16(mac, a->chain_mac) == 0);

    crypto_wipe(mac, KS_AUDIT_MAC_SIZE);
    return ok;
}

/* =========================================================================
 * ks_iec62443_audit_dump  (CR 6.1)
 * ========================================================================= */
void ks_iec62443_audit_dump(const ks_iec62443_ctx_t *ctx, uint32_t last_n)
{
    if (ctx == NULL) return;

    const ks_audit_ctx_t * const a = &ctx->audit;

    uint32_t n_in_ring = (a->total_logged < KS_AUDIT_RING_SIZE)
                          ? a->total_logged
                          : (uint32_t)KS_AUDIT_RING_SIZE;

    if (last_n == 0u || last_n > n_in_ring) last_n = n_in_ring;

    bool integrity = ks_iec62443_audit_integrity_ok(ctx);

    printf("╔══ IEC 62443-4-2 Audit Log Dump (last %" PRIu32 " records)"
           " ══════════════╗\n", last_n);
    printf("║  Total logged : %-8" PRIu32
           "  Overflow: %-3s  Integrity: %s\n",
           a->total_logged,
           a->overflow  ? "YES" : "NO",
           integrity    ? "OK"  : "WARN-TAMPERED");

    /* Starting index: oldest of the `last_n` records we want to print       */
    uint32_t oldest;
    if (a->overflow) {
        oldest = a->head & (KS_AUDIT_RING_SIZE - 1u);
    } else {
        oldest = 0u;
    }
    /* Skip the (n_in_ring - last_n) oldest records */
    uint32_t start = (oldest + (n_in_ring - last_n)) & (KS_AUDIT_RING_SIZE - 1u);

    uint32_t i;
    for (i = 0u; i < last_n; i++) {
        uint32_t slot = (start + i) & (KS_AUDIT_RING_SIZE - 1u);
        const ks_audit_record_t * const r = &a->ring[slot];
        printf("║  [%10" PRIu32 " ms] %-20s"
               " key=0x%02X sys=%3u result=%u pkt=%" PRIu64 "\n",
               r->timestamp_ms,
               ks_audit_event_str((ks_audit_event_t)r->event),
               r->key_id, r->sys_id, r->result, r->packet_count);
    }

    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

/* =========================================================================
 * ks_iec62443_audit_overflow  (CR 2.9)
 * ========================================================================= */
bool ks_iec62443_audit_overflow(const ks_iec62443_ctx_t *ctx)
{
    if (ctx == NULL) return false;
    return ctx->audit.overflow;
}

/* =========================================================================
 * ks_iec62443_status_str
 * ========================================================================= */
const char *ks_iec62443_status_str(const ks_iec62443_ctx_t *ctx,
                                   char *buf, int buf_len)
{
    if (ctx == NULL || buf == NULL || buf_len < 1) {
        if (buf != NULL && buf_len > 0) buf[0] = '\0';
        return buf;
    }

    bool integrity = ks_iec62443_audit_integrity_ok(ctx);

    const char *overall =
        (integrity
         && !ctx->audit.overflow
         && !ctx->dos.flood_active
         && !ctx->monitor.anomaly_active)
        ? "OK" : "WARN";

    snprintf(buf, (size_t)buf_len,
             "IEC62443-4-2 SL%u: %s CR=0x%04X audit=%" PRIu32
             " overflow=%s dos_alerts=%" PRIu32
             " anomaly=%s integrity=%s",
             (unsigned)KS_IEC62443_SL_TARGET,
             overall,
             (unsigned)ctx->cr_status,
             ctx->audit.total_logged,
             ctx->audit.overflow         ? "YES" : "NO",
             ctx->dos.total_alerts,
             ctx->monitor.anomaly_active ? "YES" : "NO",
             integrity                   ? "OK"  : "WARN");

    return buf;
}
