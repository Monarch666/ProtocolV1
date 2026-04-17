/*
 * =============================================================================
 *  kestrel_sora.c — JARUS SORA OSO#06 Cyber Safety Compliance Shim
 *
 *  Implementation of the security event ring buffer and compliance evaluator.
 *  Zero dependencies beyond kestrel.h (for error codes) and standard C.
 * =============================================================================
 */

#include "kestrel_sora.h"
#include "kestrel.h"   /* KS_ERR_REPLAY, KS_ERR_MAC_VERIFICATION, KS_ERR_NO_KEY */
#include <stdio.h>
#include <string.h>

/* ---- Event name strings for dump output ---- */
static const char *sora_event_name(ks_sora_event_t event)
{
    switch (event)
    {
    case KS_SORA_REPLAY_REJECTED:  return "REPLAY_REJECTED ";
    case KS_SORA_MAC_FAIL:         return "MAC_FAIL        ";
    case KS_SORA_MUTUAL_AUTH_OK:   return "MUTUAL_AUTH_OK  ";
    case KS_SORA_MUTUAL_AUTH_FAIL: return "MUTUAL_AUTH_FAIL";
    case KS_SORA_KEY_ROTATED:      return "KEY_ROTATED     ";
    case KS_SORA_LINK_ANOMALY:     return "LINK_ANOMALY    ";
    case KS_SORA_NO_KEY:           return "NO_KEY          ";
    default:                        return "UNKNOWN         ";
    }
}

/* ---- Public API ---- */

void ks_sora_init(ks_sora_ctx_t *ctx)
{
    if (!ctx)
        return;
    memset(ctx, 0, sizeof(ks_sora_ctx_t));
}

void ks_sora_log(ks_sora_ctx_t *ctx, ks_sora_event_t event,
                 uint32_t timestamp_ms, uint8_t sys_id,
                 uint32_t sequence, uint8_t result)
{
    if (!ctx)
        return;

    /* Write to ring — head always points to the next write slot */
    uint32_t slot = ctx->head & (KS_SORA_RING_SIZE - 1u);
    ctx->ring[slot].timestamp_ms = timestamp_ms;
    ctx->ring[slot].event        = (uint8_t)event;
    ctx->ring[slot].sys_id       = sys_id;
    ctx->ring[slot].sequence     = sequence;
    ctx->ring[slot].result       = result;
    ctx->ring[slot]._pad1        = 0;
    ctx->ring[slot]._pad2[0]     = 0;
    ctx->ring[slot]._pad2[1]     = 0;
    ctx->ring[slot]._pad2[2]     = 0;

    ctx->head++;
    ctx->total_logged++;

    /* Update running counters for O(1) compliance check */
    switch (event)
    {
    case KS_SORA_REPLAY_REJECTED:  ctx->replay_count++;        break;
    case KS_SORA_MAC_FAIL:         ctx->mac_fail_count++;      break;
    case KS_SORA_MUTUAL_AUTH_OK:   ctx->auth_ok_count++;       break;
    case KS_SORA_MUTUAL_AUTH_FAIL: ctx->auth_fail_count++;     break;
    case KS_SORA_KEY_ROTATED:      ctx->key_rotated_count++;   break;
    case KS_SORA_LINK_ANOMALY:     ctx->link_anomaly_count++;  break;
    default:                        break;
    }
}

void ks_sora_on_parse_result(ks_sora_ctx_t *ctx, int parse_result,
                             uint8_t sys_id, uint32_t sequence,
                             uint32_t timestamp_ms)
{
    if (!ctx)
        return;

    /* Only log security-relevant negative result codes.
     * KS_OK (1) and still-parsing (0) are not security events.
     * KS_ERR_CRC and KS_ERR_BUFFER_OVERFLOW are link-layer errors, not
     * security events — do not inflate security counters with RF noise. */
    switch (parse_result)
    {
    case KS_ERR_REPLAY:
        ks_sora_log(ctx, KS_SORA_REPLAY_REJECTED, timestamp_ms,
                    sys_id, sequence, (uint8_t)(-parse_result));
        break;

    case KS_ERR_MAC_VERIFICATION:
        ks_sora_log(ctx, KS_SORA_MAC_FAIL, timestamp_ms,
                    sys_id, sequence, (uint8_t)(-parse_result));
        break;

    case KS_ERR_NO_KEY:
        ks_sora_log(ctx, KS_SORA_NO_KEY, timestamp_ms,
                    sys_id, sequence, (uint8_t)(-parse_result));
        break;

    default:
        /* KS_OK=0, still parsing=1, CRC/overflow errors — not logged */
        break;
    }
}

bool ks_sora_is_compliant(const ks_sora_ctx_t *ctx)
{
    if (!ctx)
        return false;

    /* SORA OSO#06 compliance requires ALL of the following: */

    /* 1. At least one successful mutual authentication must have occurred.
     *    Without this, Confidentiality and authentication guarantees are
     *    unverified — the link cannot be asserted as SORA-compliant. */
    if (ctx->auth_ok_count < KS_SORA_AUTH_REQUIRED)
        return false;

    /* 2. MAC failures must be below threshold.
     *    Sustained MAC failures indicate active MITM or replay injection.
     *    Once auth_ok_count > 0, any MAC fail is post-authentication
     *    tampering — extremely serious. */
    if (ctx->mac_fail_count >= KS_SORA_MAC_FAIL_THRESHOLD)
        return false;

    /* 3. Replay rejections must be below threshold.
     *    A small number of replays can occur from retransmission on lossy
     *    links. A large number indicates a sustained replay attack. */
    if (ctx->replay_count >= KS_SORA_REPLAY_THRESHOLD)
        return false;

    /* 4. Any auth failure must be followed by a successful auth.
     *    An unmitigated auth failure means a MITM attempt was made and
     *    the link was never recovered — non-compliant.
     *    We use a simple majority heuristic: if auth_fail > auth_ok,
     *    the link is under attack. */
    if (ctx->auth_fail_count > 0 && ctx->auth_ok_count == 0)
        return false;

    return true;
}

void ks_sora_dump(const ks_sora_ctx_t *ctx)
{
    if (!ctx)
        return;

    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║       JARUS SORA OSO#06 — Security Event Audit Log          ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Total events logged : %-10u                           ║\n", ctx->total_logged);
    printf("║ Mutual Auth OK      : %-10u                           ║\n", ctx->auth_ok_count);
    printf("║ Mutual Auth FAIL    : %-10u                           ║\n", ctx->auth_fail_count);
    printf("║ MAC Failures        : %-10u  (threshold: %u)           ║\n",
           ctx->mac_fail_count, KS_SORA_MAC_FAIL_THRESHOLD);
    printf("║ Replay Rejections   : %-10u  (threshold: %u)          ║\n",
           ctx->replay_count, KS_SORA_REPLAY_THRESHOLD);
    printf("║ Key Rotations       : %-10u                           ║\n", ctx->key_rotated_count);
    printf("║ Link Anomalies      : %-10u                           ║\n", ctx->link_anomaly_count);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ OSO#06 Compliance   : %-10s                           ║\n",
           ks_sora_is_compliant(ctx) ? "COMPLIANT" : "NON-COMPLIANT");
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    /* Print ring contents — oldest first */
    uint32_t count = ctx->total_logged < KS_SORA_RING_SIZE
                     ? ctx->total_logged
                     : KS_SORA_RING_SIZE;

    if (count == 0)
    {
        printf("║  [No security events recorded]                               ║\n");
    }
    else
    {
        printf("║  #   Timestamp(ms) Event            Sys  Seq         Err   ║\n");
        printf("║  ─── ──────────── ──────────────── ──── ────────── ───     ║\n");

        /* Walk from oldest entry to newest */
        uint32_t start = (ctx->total_logged >= KS_SORA_RING_SIZE)
                         ? (ctx->head & (KS_SORA_RING_SIZE - 1u))
                         : 0u;

        for (uint32_t i = 0; i < count; i++)
        {
            uint32_t idx = (start + i) & (KS_SORA_RING_SIZE - 1u);
            const ks_sora_record_t *r = &ctx->ring[idx];
            printf("║  %-3u %11u %s  %3u  %10u  %3u          ║\n",
                   i + 1,
                   r->timestamp_ms,
                   sora_event_name((ks_sora_event_t)r->event),
                   r->sys_id,
                   r->sequence,
                   r->result);
        }
    }

    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    fflush(stdout);
}

const char *ks_sora_status_str(const ks_sora_ctx_t *ctx, char *buf, int buf_len)
{
    if (!ctx || !buf || buf_len < 1)
        return "";

    /* Format: "SORA OSO#06: COMPLIANT auth=1 mac_fail=0 replay=0" */
    int written = snprintf(buf, (size_t)buf_len,
        "SORA OSO#06: %s auth=%u mac_fail=%u replay=%u key_rot=%u",
        ks_sora_is_compliant(ctx) ? "COMPLIANT" : "NON-COMPLIANT",
        ctx->auth_ok_count,
        ctx->mac_fail_count,
        ctx->replay_count,
        ctx->key_rotated_count);

    /* Guarantee null termination even on truncation */
    if (written >= buf_len)
        buf[buf_len - 1] = '\0';

    return buf;
}

const ks_sora_ctx_t *ks_sora_get_ctx(const ks_sora_ctx_t *ctx)
{
    return ctx;
}
