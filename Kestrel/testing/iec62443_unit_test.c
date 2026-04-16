/*
 * =============================================================================
 *  iec62443_unit_test.c — IEC 62443-4-2 Compliance Module Unit Test
 *
 *  Self-contained test executable. No network sockets, no key files.
 *  Exercises every public function in kestrel_iec62443.c and
 *  kestrel_keymanager.c (lifecycle section), and validates:
 *
 *    TEST 1  ks_iec62443_init: context zeroed, CRs marked, log file opened
 *    TEST 2  ks_iec62443_key_id: deterministic XOR-fold
 *    TEST 3  ks_lc_init: lifecycle record fields populated correctly
 *    TEST 4  ks_lc_is_valid: valid key accepted
 *    TEST 5  ks_lc_is_valid: expired key rejected
 *    TEST 6  ks_lc_is_valid: revoked key rejected
 *    TEST 7  ks_lc_is_valid: wear-limit key rejected
 *    TEST 8  ks_lc_assert_sl: SL assertion comparison
 *    TEST 9  ks_lc_touch_*: counters and last_used_ms update
 *    TEST 10 ks_generate_key_with_lifecycle: key is non-zero, lc populated
 *    TEST 11 ks_iec62443_audit: ring writes, total_logged, overflow flag
 *    TEST 12 ks_iec62443_audit_integrity_ok: clean chain passes
 *    TEST 13 ks_iec62443_audit_integrity_ok: tampered record fails
 *    TEST 14 ks_iec62443_dos_check: rate limiting at threshold
 *    TEST 15 ks_iec62443_monitor_update: anomaly detection
 *    TEST 16 ks_iec62443_audit_overflow: overflow flag + CR29 cleared
 *    TEST 17 ks_iec62443_status_str: format and content
 *    TEST 18 ks_iec62443_audit_dump: does not crash (smoke test)
 *    TEST 19 ks_rotate_with_lifecycle: key rotated, lifecycle reset
 *
 *  Build (from Kestrel/):
 *    gcc -Wall -Werror -O2 -Isrc/core \
 *        -o testing/iec62443_test \
 *        testing/iec62443_unit_test.c \
 *        src/core/kestrel.c src/core/kestrel_fast.c \
 *        src/core/kestrel_compress.c src/core/kestrel_hw_crypto.c \
 *        src/core/monocypher.c src/core/kestrel_keymanager.c \
 *        src/core/kestrel_sora.c src/core/kestrel_iec62443.c \
 *        -lm
 * =============================================================================
 */

#include "kestrel_iec62443.h"
#include "kestrel_keymanager.h"
#include "kestrel.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

/* ---- Minimal test framework ---- */
static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT(cond, msg)                                                    \
    do {                                                                     \
        g_tests_run++;                                                       \
        if (cond) {                                                          \
            g_tests_passed++;                                                \
            printf("  PASS  %s\n", msg);                                     \
        } else {                                                             \
            g_tests_failed++;                                                \
            printf("  FAIL  %s  (line %d)\n", msg, __LINE__);               \
        }                                                                    \
    } while (0)

/* ---- Helpers ---- */
static uint32_t g_fake_time_ms = 1000u;

/* =============================================================================
   TEST 1 — ks_iec62443_init: context fields and CR bitmask
   ============================================================================= */
static void test_init(void)
{
    printf("\nTEST 1: Context initialisation\n");

    ks_iec62443_ctx_t ctx;
    memset(&ctx, 0xFF, sizeof(ctx));  /* Poison memory first */

    ks_iec62443_init(&ctx, g_fake_time_ms, NULL); /* NULL = RAM-only mode */

    ASSERT(ctx.audit.head         == 0,  "audit.head zeroed");
    ASSERT(ctx.audit.total_logged == 0,  "total_logged zeroed");
    ASSERT(ctx.audit.overflow     == false, "overflow false initially");
    ASSERT(ctx.total_rx           == 0,  "total_rx zeroed");
    ASSERT((ctx.cr_status & KS_CR28_AUDIT)    != 0, "CR28 AUDIT set");
    ASSERT((ctx.cr_status & KS_CR29_CAPACITY) != 0, "CR29 CAPACITY set");
    ASSERT((ctx.cr_status & KS_CR39_INTEGRITY)!= 0, "CR39 INTEGRITY set");
    ASSERT((ctx.cr_status & KS_CR71_DOS)      != 0, "CR71 DOS set");
    ASSERT((ctx.cr_status & KS_CR62_MONITOR)  != 0, "CR62 MONITOR set");
    /* CR61 (file) should NOT be set in RAM-only mode */
    ASSERT((ctx.cr_status & KS_CR61_ACCESSIBILITY) == 0,
           "CR61 ACCESSIBILITY not set (NULL log_dir)");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 2 — ks_iec62443_key_id: deterministic, all-bytes
   ============================================================================= */
static void test_key_id(void)
{
    printf("\nTEST 2: Key ID derivation (XOR-fold)\n");

    uint8_t key_a[32];
    memset(key_a, 0xAB, 32);
    uint8_t id_a1 = ks_iec62443_key_id(key_a);
    uint8_t id_a2 = ks_iec62443_key_id(key_a);

    ASSERT(id_a1 == id_a2, "Same key → same ID (deterministic)");

    /* Different key → different ID: vary one byte so XOR folds differ */
    uint8_t key_b[32];
    memset(key_b, 0xAB, 32);
    key_b[0] = 0xAC; /* one byte flipped: fold changes by 0xAB^0xAC = 0x07 */
    uint8_t id_b = ks_iec62443_key_id(key_b);

    ASSERT(id_a1 != id_b, "Different keys → different IDs");

    /* Zero key → ID must be 0 */
    uint8_t key_zero[32];
    memset(key_zero, 0, 32);
    ASSERT(ks_iec62443_key_id(key_zero) == 0, "Zero key → ID 0");
}

/* =============================================================================
   TEST 3-9 — Key Lifecycle Functions (CR 1.5 / CR 1.9)
   ============================================================================= */
static void test_lifecycle(void)
{
    printf("\nTEST 3: ks_lc_init field population\n");

    uint8_t dummy_key[32];
    memset(dummy_key, 0x42, 32);

    ks_key_lifecycle_t lc;
    memset(&lc, 0xFF, sizeof(lc)); /* Poison */

    ks_lc_init(&lc, dummy_key, (uint8_t)KS_KEY_ORIGIN_GENERATED,
                KS_KEY_LIFETIME_1H_MS, 5000u);

    ASSERT(lc.created_at_ms   == 5000u,              "created_at_ms = 5000");
    ASSERT(lc.max_lifetime_ms == KS_KEY_LIFETIME_1H_MS, "max_lifetime set");
    ASSERT(lc.packets_encrypted == 0,                "encrypt counter zeroed");
    ASSERT(lc.packets_decrypted == 0,                "decrypt counter zeroed");
    ASSERT(lc.revoked         == false,              "not revoked on init");
    ASSERT(lc.sl_assert       == 2u,                 "sl_assert = SL2");
    ASSERT(lc.origin == (uint8_t)KS_KEY_ORIGIN_GENERATED, "origin recorded");
    /* key_id must equal XOR-fold of dummy_key (0x42 × 32 = 0) */
    ASSERT(lc.key_id == ks_iec62443_key_id(dummy_key), "key_id matches fold");

    /* TEST 4: Valid key accepted */
    printf("\nTEST 4: Valid key accepted\n");
    ASSERT(ks_lc_is_valid(&lc, 5001u), "Fresh key is valid at t+1ms");

    /* TEST 5: Expired key rejected */
    printf("\nTEST 5: Expired key rejected\n");
    uint32_t expired_at = 5000u + KS_KEY_LIFETIME_1H_MS + 1u;
    ASSERT(!ks_lc_is_valid(&lc, expired_at), "Key past max_lifetime rejected");

    /* Key with no expiry must not be rejected by time */
    ks_key_lifecycle_t lc_nexp;
    ks_lc_init(&lc_nexp, dummy_key, (uint8_t)KS_KEY_ORIGIN_FILE,
               KS_KEY_LIFETIME_NONE, 0u);
    ASSERT(ks_lc_is_valid(&lc_nexp, 0xFFFFFFFFu), "No-expiry key valid at max time");

    /* TEST 6: Revoked key rejected */
    printf("\nTEST 6: Revoked key rejected\n");
    ks_key_lifecycle_t lc_rev;
    ks_lc_init(&lc_rev, dummy_key, (uint8_t)KS_KEY_ORIGIN_GENERATED, 0u, 0u);
    lc_rev.revoked = true;
    ASSERT(!ks_lc_is_valid(&lc_rev, 100u), "Revoked key rejected");

    /* TEST 7: Wear-limit key rejected */
    printf("\nTEST 7: Crypto-wear limit key rejected\n");
    ks_key_lifecycle_t lc_wear;
    ks_lc_init(&lc_wear, dummy_key, (uint8_t)KS_KEY_ORIGIN_GENERATED, 0u, 0u);
    lc_wear.packets_encrypted = (uint64_t)KS_KEY_LIFECYCLE_MAX_PACKETS;
    ASSERT(!ks_lc_is_valid(&lc_wear, 100u), "Worn-out key rejected");

    /* TEST 8: SL assertion */
    printf("\nTEST 8: SL assertion\n");
    ks_key_lifecycle_t lc_sl;
    ks_lc_init(&lc_sl, dummy_key, (uint8_t)KS_KEY_ORIGIN_GENERATED, 0u, 0u);
    ASSERT(ks_lc_assert_sl(&lc_sl, 1u), "SL2 asserts against SL1 req");
    ASSERT(ks_lc_assert_sl(&lc_sl, 2u), "SL2 asserts against SL2 req");
    ASSERT(!ks_lc_assert_sl(&lc_sl, 3u),"SL2 fails against SL3 req");

    /* TEST 9: Touch functions */
    printf("\nTEST 9: ks_lc_touch_* counters\n");
    ks_key_lifecycle_t lc_t;
    ks_lc_init(&lc_t, dummy_key, (uint8_t)KS_KEY_ORIGIN_GENERATED, 0u, 0u);
    ks_lc_touch_encrypt(&lc_t, 100u);
    ks_lc_touch_encrypt(&lc_t, 200u);
    ks_lc_touch_decrypt(&lc_t, 300u);

    ASSERT(lc_t.packets_encrypted == 2, "2 encrypt touches");
    ASSERT(lc_t.packets_decrypted == 1, "1 decrypt touch");
    ASSERT(lc_t.last_used_ms      == 300u, "last_used updated");
}

/* =============================================================================
   TEST 10 — ks_generate_key_with_lifecycle
   ============================================================================= */
static void test_generate_key_with_lifecycle(void)
{
    printf("\nTEST 10: ks_generate_key_with_lifecycle\n");

    uint8_t key[32];
    ks_key_lifecycle_t lc;

    int r = ks_generate_key_with_lifecycle(key, &lc,
                                           KS_KEY_LIFETIME_1H_MS, 9999u);
    ASSERT(r == 0, "Generate returns 0 on success");
    ASSERT(ks_lc_is_valid(&lc, 10000u), "Generated key lifecycle is valid");
    ASSERT(lc.origin == (uint8_t)KS_KEY_ORIGIN_GENERATED, "origin = GENERATED");
    ASSERT(lc.key_id  == ks_iec62443_key_id(key), "key_id derived correctly");

    /* Key must not be all-zero (probability ~2^-256 of false failure) */
    uint8_t zero[32];
    memset(zero, 0, 32);
    ASSERT(memcmp(key, zero, 32) != 0, "Generated key is not all-zero");
}

/* =============================================================================
   TEST 11 — ks_iec62443_audit: ring writes, total_logged, counter
   ============================================================================= */
static void test_audit_ring(void)
{
    printf("\nTEST 11: Audit ring writes and total_logged\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    ks_iec62443_audit(&ctx, KS_AUDIT_AUTH_OK,     0x01u, 1u, 0u, 100u);
    ks_iec62443_audit(&ctx, KS_AUDIT_MAC_FAIL,    0x01u, 1u, 3u, 200u);
    ks_iec62443_audit(&ctx, KS_AUDIT_KEY_ROTATED, 0x02u, 1u, 0u, 300u);

    ASSERT(ctx.audit.total_logged == 3, "3 events total_logged");
    ASSERT(ctx.audit.ring[0].event == (uint8_t)KS_AUDIT_AUTH_OK,
           "ring[0].event = AUTH_OK");
    ASSERT(ctx.audit.ring[1].event == (uint8_t)KS_AUDIT_MAC_FAIL,
           "ring[1].event = MAC_FAIL");
    ASSERT(ctx.audit.ring[2].timestamp_ms == 300u,
           "ring[2].timestamp_ms = 300");
    ASSERT(ctx.audit.overflow == false, "No overflow at 3 records");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 12 — ks_iec62443_audit_integrity_ok: clean chain
   ============================================================================= */
static void test_integrity_clean(void)
{
    printf("\nTEST 12: Audit integrity — clean chain passes\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    ks_iec62443_audit(&ctx, KS_AUDIT_KEY_GENERATED, 0xAAu, 1u, 0u, 100u);
    ks_iec62443_audit(&ctx, KS_AUDIT_AUTH_OK,       0xAAu, 1u, 0u, 200u);
    ks_iec62443_audit(&ctx, KS_AUDIT_REPLAY_REJECT, 0xAAu, 255u, 7u, 300u);

    ASSERT(ks_iec62443_audit_integrity_ok(&ctx),
           "Clean 3-record chain passes integrity check");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 13 — ks_iec62443_audit_integrity_ok: tampered record fails
   ============================================================================= */
static void test_integrity_tampered(void)
{
    printf("\nTEST 13: Audit integrity — tampered record fails\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    ks_iec62443_audit(&ctx, KS_AUDIT_AUTH_OK,   0x01u, 1u, 0u, 100u);
    ks_iec62443_audit(&ctx, KS_AUDIT_KEY_ROTATED, 0x02u, 1u, 0u, 200u);

    /* Simulate in-memory tampering */
    ctx.audit.ring[0].result = 0xFF;

    ASSERT(!ks_iec62443_audit_integrity_ok(&ctx),
           "Tampered ring[0] causes chain MAC mismatch");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 14 — ks_iec62443_dos_check: rate limiting  (CR 7.1)
   ============================================================================= */
static void test_dos_guard(void)
{
    printf("\nTEST 14: DoS rate guard\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    uint32_t t = 2000u;
    uint32_t i;
    /* Send KS_FLOOD_MAX_PKTS packets — all should be accepted */
    for (i = 0u; i < KS_FLOOD_MAX_PKTS; i++) {
        bool ok = ks_iec62443_dos_check(&ctx, t);
        if (!ok) break;
    }
    ASSERT(i == KS_FLOOD_MAX_PKTS,
           "First FLOOD_MAX_PKTS packets all accepted");

    /* One more — must be rejected (over threshold) */
    bool over = ks_iec62443_dos_check(&ctx, t);
    ASSERT(!over, "Packet beyond FLOOD_MAX_PKTS is rejected");
    ASSERT(ctx.dos.flood_active, "flood_active set after threshold");

    /* After window expiry, packets are accepted again */
    bool after_window = ks_iec62443_dos_check(&ctx, t + KS_FLOOD_WINDOW_MS + 1u);
    ASSERT(after_window, "First packet in new window is accepted");
    ASSERT(!ctx.dos.flood_active, "flood_active cleared in new window");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 15 — ks_iec62443_monitor_update: anomaly detection  (CR 6.2)
   ============================================================================= */
static void test_monitor(void)
{
    printf("\nTEST 15: Link anomaly monitor\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    uint32_t t = 3000u;
    uint32_t i;

    /* Feed a mostly-clean window (5% errors) — no anomaly */
    for (i = 0u; i < KS_ANOMALY_WINDOW_PKTS; i++) {
        int res = (i % 20u == 0u) ? KS_ERR_MAC_VERIFICATION : 1;
        ks_iec62443_monitor_update(&ctx, res, t);
    }
    ASSERT(!ctx.monitor.anomaly_active,
           "5% error rate — no anomaly (< 20% threshold)");

    /* Feed a high-error window (50% errors) — anomaly triggered */
    ctx.monitor.window_rx  = 0u;
    ctx.monitor.window_err = 0u;
    ctx.monitor.anomaly_active = false;

    for (i = 0u; i < KS_ANOMALY_WINDOW_PKTS; i++) {
        int res = (i % 2u == 0u) ? KS_ERR_MAC_VERIFICATION : 1;
        ks_iec62443_monitor_update(&ctx, res, t);
    }
    ASSERT(ctx.monitor.anomaly_active,
           "50% error rate → anomaly_active");

    /* Incomplete bytes (parse_result == 0) are NOT counted */
    uint32_t before = ctx.monitor.window_rx;
    ks_iec62443_monitor_update(&ctx, 0, t);
    ASSERT(ctx.monitor.window_rx == before,
           "parse_result==0 not counted in window");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 16 — ks_iec62443_audit_overflow: overflow flag + CR29  (CR 2.9/2.10)
   ============================================================================= */
static void test_audit_overflow(void)
{
    printf("\nTEST 16: Audit ring overflow (CR 2.9)\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    /* CR29 must be set initially */
    ASSERT((ctx.cr_status & KS_CR29_CAPACITY) != 0,
           "CR29 set before overflow");

    uint32_t i;
    for (i = 0u; i <= KS_AUDIT_RING_SIZE; i++) {
        ks_iec62443_audit(&ctx, KS_AUDIT_REPLAY_REJECT,
                          0xFFu, 1u, 0u, 1000u + i);
    }

    ASSERT(ctx.audit.overflow, "overflow flag set after ring+1 events");
    ASSERT(ks_iec62443_audit_overflow(&ctx), "ks_iec62443_audit_overflow() true");
    ASSERT((ctx.cr_status & KS_CR29_CAPACITY) == 0,
           "CR29 cleared after overflow (CR 2.10 alert)");
    ASSERT(ctx.audit.total_logged > KS_AUDIT_RING_SIZE,
           "total_logged > RING_SIZE");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 17 — ks_iec62443_status_str
   ============================================================================= */
static void test_status_str(void)
{
    printf("\nTEST 17: Status string content\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    /* No events yet — should report OK */
    char buf[256];
    const char *s = ks_iec62443_status_str(&ctx, buf, (int)sizeof(buf));
    ASSERT(s == buf,                  "Returns buf pointer");
    ASSERT(strstr(s, "IEC62443") != NULL, "Contains IEC62443");
    ASSERT(strstr(s, "SL2")      != NULL, "Contains SL2");
    ASSERT(strstr(s, "OK")       != NULL, "Status OK on clean context");
    printf("  Status: %s\n", s);

    /* After flooding, should report WARN */
    uint32_t i;
    for (i = 0u; i < KS_FLOOD_MAX_PKTS + 2u; i++) {
        ks_iec62443_dos_check(&ctx, 8000u);
    }
    s = ks_iec62443_status_str(&ctx, buf, (int)sizeof(buf));
    ASSERT(strstr(s, "WARN") != NULL,  "Status WARN after flood");
    printf("  Status (flood): %s\n", s);

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 18 — ks_iec62443_audit_dump: smoke test (no crash)
   ============================================================================= */
static void test_audit_dump(void)
{
    printf("\nTEST 18: Audit dump smoke test\n");

    ks_iec62443_ctx_t ctx;
    ks_iec62443_init(&ctx, 0, NULL);

    ks_iec62443_audit(&ctx, KS_AUDIT_AUTH_OK,       0x01u, 1u, 0u, 100u);
    ks_iec62443_audit(&ctx, KS_AUDIT_KEY_ROTATED,   0x01u, 1u, 0u, 200u);
    ks_iec62443_audit(&ctx, KS_AUDIT_REPLAY_REJECT, 0x02u, 255u, 7u, 300u);

    /* dump last 2 — must not crash */
    ks_iec62443_audit_dump(&ctx, 2u);
    g_tests_run++;
    g_tests_passed++;
    printf("  PASS  audit_dump(2) did not crash\n");

    /* dump all (pass 0) — must not crash */
    ks_iec62443_audit_dump(&ctx, 0u);
    g_tests_run++;
    g_tests_passed++;
    printf("  PASS  audit_dump(0) did not crash\n");

    ks_iec62443_destroy(&ctx);
}

/* =============================================================================
   TEST 19 — ks_rotate_with_lifecycle: session rotated, lifecycle reset
   ============================================================================= */
static void test_rotate_with_lifecycle(void)
{
    printf("\nTEST 19: ks_rotate_with_lifecycle\n");

    /* Initialise a session */
    uint8_t orig_key[32];
    memset(orig_key, 0x11, 32);
    ks_session_t session;
    int init_r = ks_session_init(&session, orig_key);
    ASSERT(init_r == 0, "Session initialised");

    ks_key_lifecycle_t lc;
    ks_lc_init(&lc, orig_key, (uint8_t)KS_KEY_ORIGIN_GENERATED,
               KS_KEY_LIFETIME_1H_MS, 1000u);
    lc.packets_encrypted = 1000u; /* Simulate some usage */

    /* Rotate */
    uint8_t new_key[32];
    memset(new_key, 0x22, 32);

    int r = ks_rotate_with_lifecycle(&session, new_key, &lc,
                                      KS_KEY_LIFETIME_8H_MS, 5000u);
    ASSERT(r == 0, "Rotate returns 0");
    ASSERT(lc.packets_encrypted == 0,    "Wear counter reset to 0");
    ASSERT(lc.created_at_ms     == 5000u,"created_at_ms updated to now");
    ASSERT(lc.max_lifetime_ms == KS_KEY_LIFETIME_8H_MS,
           "max_lifetime updated to 8h");
    ASSERT(lc.key_id == ks_iec62443_key_id(new_key),
           "key_id updated for new key");
    ASSERT(lc.origin == (uint8_t)KS_KEY_ORIGIN_GENERATED,
           "origin preserved across rotation");
    ASSERT(ks_lc_is_valid(&lc, 5001u), "Rotated key lifecycle is valid");

    ks_session_destroy(&session);
}

/* =============================================================================
   MAIN
   ============================================================================= */
int main(void)
{
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  IEC 62443-4-2 — kestrel_iec62443 Unit Test Suite        ║\n");
    printf("║  Target: SL 2  |  CR Coverage: 1.5, 1.9, 2.8-2.10,      ║\n");
    printf("║                          3.9, 6.1-6.2, 7.1               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    test_init();
    test_key_id();
    test_lifecycle();
    test_generate_key_with_lifecycle();
    test_audit_ring();
    test_integrity_clean();
    test_integrity_tampered();
    test_dos_guard();
    test_monitor();
    test_audit_overflow();
    test_status_str();
    test_audit_dump();
    test_rotate_with_lifecycle();

    /* Print a final dump for manual inspection */
    printf("\n--- Final context audit dump (last 5 records) ---\n");
    ks_iec62443_ctx_t ctx_final;
    ks_iec62443_init(&ctx_final, 0u, NULL);
    ks_iec62443_audit(&ctx_final, KS_AUDIT_KEY_GENERATED, 0xABu, 1u, 0u, 100u);
    ks_iec62443_audit(&ctx_final, KS_AUDIT_AUTH_OK,       0xABu, 1u, 0u, 200u);
    ks_iec62443_audit(&ctx_final, KS_AUDIT_KEY_ROTATED,   0xCDu, 1u, 0u, 300u);
    ks_iec62443_audit(&ctx_final, KS_AUDIT_REPLAY_REJECT, 0xCDu, 255u, 7u, 400u);
    ks_iec62443_audit_dump(&ctx_final, 5u);
    ks_iec62443_destroy(&ctx_final);

    /* Summary */
    printf("══════════════════════════════════════════════════════════════\n");
    printf("  Tests run    : %d\n", g_tests_run);
    printf("  Tests passed : %d\n", g_tests_passed);
    printf("  Tests failed : %d\n", g_tests_failed);
    printf("══════════════════════════════════════════════════════════════\n");

    if (g_tests_failed > 0) {
        printf("RESULT: ❌ FAILED (%d test(s) did not pass)\n\n", g_tests_failed);
        return 1;
    }

    printf("RESULT: ✅ ALL TESTS PASSED\n\n");
    return 0;
}
