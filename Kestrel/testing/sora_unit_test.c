/*
 * =============================================================================
 *  sora_unit_test.c — JARUS SORA OSO#06 Compliance Module Unit Test
 *
 *  Self-contained test executable. No network, no files.
 *  Exercises every public function in kestrel_sora.c and validates:
 *
 *    TEST 1  Init produces zeroed counters
 *    TEST 2  Events are logged and counters increment correctly
 *    TEST 3  Ring buffer wraps cleanly at 64 entries
 *    TEST 4  ks_sora_on_parse_result maps KS_ERR_* to correct events
 *    TEST 5  is_compliant() returns false before any auth_ok
 *    TEST 6  is_compliant() returns true after valid auth sequence
 *    TEST 7  is_compliant() returns false when MAC fail threshold exceeded
 *    TEST 8  is_compliant() returns false on replay flood
 *    TEST 9  is_compliant() returns false on unmitigated auth failure
 *    TEST 10 ks_sora_status_str() formats correctly
 *
 *  Build:
 *    gcc -Wall -Werror -O2 -Isrc/core -o testing/sora_test \
 *        src/core/kestrel_sora.c testing/sora_unit_test.c -lm
 * =============================================================================
 */

#include "kestrel_sora.h"
#include "kestrel.h"    /* KS_ERR_* codes */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ---- Test framework ---- */
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
static void log_event(ks_sora_ctx_t *ctx, ks_sora_event_t ev)
{
    ks_sora_log(ctx, ev, 1000u, 1u, 0u, 0u);
}

/* ============================================================
   TEST 1 — Init produces clean zeroed context
   ============================================================ */
static void test_init(void)
{
    printf("\nTEST 1: Init\n");
    ks_sora_ctx_t ctx;
    /* Poison the memory first so we prove init zeroes it */
    memset(&ctx, 0xFF, sizeof(ctx));
    ks_sora_init(&ctx);

    ASSERT(ctx.head           == 0,  "head zeroed after init");
    ASSERT(ctx.total_logged   == 0,  "total_logged zeroed");
    ASSERT(ctx.auth_ok_count  == 0,  "auth_ok_count zeroed");
    ASSERT(ctx.mac_fail_count == 0,  "mac_fail_count zeroed");
    ASSERT(ctx.replay_count   == 0,  "replay_count zeroed");
    ASSERT(ctx.key_rotated_count == 0, "key_rotated_count zeroed");
}

/* ============================================================
   TEST 2 — Log events and verify counters
   ============================================================ */
static void test_logging(void)
{
    printf("\nTEST 2: Event logging and counters\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);

    log_event(&ctx, KS_SORA_MUTUAL_AUTH_OK);
    log_event(&ctx, KS_SORA_KEY_ROTATED);
    log_event(&ctx, KS_SORA_REPLAY_REJECTED);
    log_event(&ctx, KS_SORA_MAC_FAIL);
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_FAIL);

    ASSERT(ctx.total_logged          == 5, "5 events total");
    ASSERT(ctx.auth_ok_count         == 1, "auth_ok_count = 1");
    ASSERT(ctx.key_rotated_count     == 1, "key_rotated = 1");
    ASSERT(ctx.replay_count          == 1, "replay_count = 1");
    ASSERT(ctx.mac_fail_count        == 1, "mac_fail_count = 1");
    ASSERT(ctx.auth_fail_count       == 1, "auth_fail_count = 1");

    /* Verify ring entries */
    ASSERT(ctx.ring[0].event == (uint8_t)KS_SORA_MUTUAL_AUTH_OK,   "ring[0] = AUTH_OK");
    ASSERT(ctx.ring[1].event == (uint8_t)KS_SORA_KEY_ROTATED,      "ring[1] = KEY_ROTATED");
    ASSERT(ctx.ring[4].event == (uint8_t)KS_SORA_MUTUAL_AUTH_FAIL, "ring[4] = AUTH_FAIL");
}

/* ============================================================
   TEST 3 — Ring buffer wraps at KS_SORA_RING_SIZE (64)
   ============================================================ */
static void test_ring_wrap(void)
{
    printf("\nTEST 3: Ring buffer wrap-around\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);

    /* Fill exactly one ring's worth */
    for (uint32_t i = 0; i < KS_SORA_RING_SIZE; i++)
        log_event(&ctx, KS_SORA_REPLAY_REJECTED);

    ASSERT(ctx.total_logged  == KS_SORA_RING_SIZE, "64 events logged");
    ASSERT(ctx.head          == KS_SORA_RING_SIZE, "head == 64");
    ASSERT(ctx.replay_count  == KS_SORA_RING_SIZE, "replay_count == 64");

    /* Log one more — should overwrite slot 0 */
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_OK);
    ASSERT(ctx.total_logged == KS_SORA_RING_SIZE + 1, "65th event logged");
    ASSERT(ctx.ring[0].event == (uint8_t)KS_SORA_MUTUAL_AUTH_OK,
           "ring[0] overwritten with AUTH_OK after wrap");
}

/* ============================================================
   TEST 4 — ks_sora_on_parse_result maps error codes correctly
   ============================================================ */
static void test_parse_result_mapping(void)
{
    printf("\nTEST 4: Parse result → SORA event mapping\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);

    /* KS_ERR_REPLAY should log REPLAY_REJECTED */
    ks_sora_on_parse_result(&ctx, KS_ERR_REPLAY, 1u, 100u, 5000u);
    ASSERT(ctx.replay_count   == 1, "KS_ERR_REPLAY -> replay_count++");
    ASSERT(ctx.mac_fail_count == 0, "KS_ERR_REPLAY -> mac_fail unchanged");

    /* KS_ERR_MAC_VERIFICATION should log MAC_FAIL */
    ks_sora_on_parse_result(&ctx, KS_ERR_MAC_VERIFICATION, 1u, 101u, 5001u);
    ASSERT(ctx.mac_fail_count == 1, "KS_ERR_MAC_VERIFICATION -> mac_fail_count++");
    ASSERT(ctx.replay_count   == 1, "mac_fail -> replay_count unchanged");

    /* KS_ERR_NO_KEY should log NO_KEY (not a security counter) */
    ks_sora_on_parse_result(&ctx, KS_ERR_NO_KEY, 1u, 102u, 5002u);
    ASSERT(ctx.total_logged == 3, "NO_KEY adds to total_logged");

    /* KS_OK (positive) and KS_ERR_CRC should NOT log anything */
    uint32_t before = ctx.total_logged;
    ks_sora_on_parse_result(&ctx, 1,           1u, 103u, 5003u); /* KS_OK */
    ks_sora_on_parse_result(&ctx, KS_ERR_CRC,  1u, 104u, 5004u); /* RF noise */
    ASSERT(ctx.total_logged == before, "KS_OK + CRC not logged as security events");
}

/* ============================================================
   TEST 5 — Not compliant before any successful auth
   ============================================================ */
static void test_not_compliant_before_auth(void)
{
    printf("\nTEST 5: Not compliant before auth_ok\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);

    /* Fresh context — no auth events yet */
    ASSERT(!ks_sora_is_compliant(&ctx), "Fresh context: NOT compliant (no auth)");

    /* Key rotation and replay below threshold — still not compliant without auth */
    log_event(&ctx, KS_SORA_KEY_ROTATED);
    log_event(&ctx, KS_SORA_REPLAY_REJECTED);
    ASSERT(!ks_sora_is_compliant(&ctx), "Key+replay logged, still NOT compliant (no auth_ok)");
}

/* ============================================================
   TEST 6 — Compliant after clean handshake
   ============================================================ */
static void test_compliant_after_auth(void)
{
    printf("\nTEST 6: Compliant after clean auth sequence\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);

    log_event(&ctx, KS_SORA_KEY_ROTATED);
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_OK);

    ASSERT(ks_sora_is_compliant(&ctx), "KEY_ROTATED + AUTH_OK = COMPLIANT");

    /* Adding acceptable replays (< threshold=10) — still compliant */
    for (int i = 0; i < 5; i++)
        log_event(&ctx, KS_SORA_REPLAY_REJECTED);
    ASSERT(ks_sora_is_compliant(&ctx), "5 replays (< threshold 10) = still COMPLIANT");
}

/* ============================================================
   TEST 7 — Not compliant when MAC failures exceed threshold
   ============================================================ */
static void test_mac_fail_threshold(void)
{
    printf("\nTEST 7: MAC failure threshold\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_OK); /* establish auth first */

    ASSERT(ks_sora_is_compliant(&ctx), "AUTH_OK -> COMPLIANT baseline");

    /* Log up to threshold - 1 = still compliant */
    for (uint32_t i = 0; i < KS_SORA_MAC_FAIL_THRESHOLD - 1; i++)
        log_event(&ctx, KS_SORA_MAC_FAIL);
    ASSERT(ks_sora_is_compliant(&ctx),
           "mac_fail < threshold -> still COMPLIANT");

    /* One more pushes it over */
    log_event(&ctx, KS_SORA_MAC_FAIL);
    ASSERT(!ks_sora_is_compliant(&ctx),
           "mac_fail >= threshold -> NON-COMPLIANT");
}

/* ============================================================
   TEST 8 — Not compliant when replay count exceeds threshold
   ============================================================ */
static void test_replay_threshold(void)
{
    printf("\nTEST 8: Replay flood threshold\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_OK);

    for (uint32_t i = 0; i < KS_SORA_REPLAY_THRESHOLD - 1; i++)
        log_event(&ctx, KS_SORA_REPLAY_REJECTED);
    ASSERT(ks_sora_is_compliant(&ctx),  "replay < threshold -> COMPLIANT");

    log_event(&ctx, KS_SORA_REPLAY_REJECTED);
    ASSERT(!ks_sora_is_compliant(&ctx), "replay >= threshold -> NON-COMPLIANT");
}

/* ============================================================
   TEST 9 — Not compliant on unmitigated auth failure
   ============================================================ */
static void test_unmitigated_auth_fail(void)
{
    printf("\nTEST 9: Unmitigated auth failure\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);

    /* Auth fail with NO subsequent auth_ok = MITM, unmitigated */
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_FAIL);
    ASSERT(!ks_sora_is_compliant(&ctx),
           "auth_fail with no auth_ok -> NON-COMPLIANT");

    /* Now recover with a successful auth */
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_OK);
    ASSERT(ks_sora_is_compliant(&ctx),
           "auth_fail then auth_ok -> mitigated, COMPLIANT");
}

/* ============================================================
   TEST 10 — Status string format
   ============================================================ */
static void test_status_string(void)
{
    printf("\nTEST 10: Status string formatting\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);
    log_event(&ctx, KS_SORA_MUTUAL_AUTH_OK);

    char buf[256];
    const char *s = ks_sora_status_str(&ctx, buf, sizeof(buf));
    ASSERT(s == buf,       "returns buf pointer");
    ASSERT(strstr(s, "COMPLIANT")   != NULL, "contains COMPLIANT");
    ASSERT(strstr(s, "auth=1")      != NULL, "contains auth=1");
    ASSERT(strstr(s, "mac_fail=0")  != NULL, "contains mac_fail=0");
    ASSERT(strstr(s, "replay=0")    != NULL, "contains replay=0");

    printf("  Status: %s\n", s);

    /* Non-compliant string */
    ks_sora_ctx_t ctx2;
    ks_sora_init(&ctx2);
    const char *s2 = ks_sora_status_str(&ctx2, buf, sizeof(buf));
    ASSERT(strstr(s2, "NON-COMPLIANT") != NULL, "fresh ctx -> NON-COMPLIANT string");
}

/* ============================================================
   MAIN — run all tests and report
   ============================================================ */
int main(void)
{
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║  JARUS SORA OSO#06 — kestrel_sora Unit Test Suite  ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");

    test_init();
    test_logging();
    test_ring_wrap();
    test_parse_result_mapping();
    test_not_compliant_before_auth();
    test_compliant_after_auth();
    test_mac_fail_threshold();
    test_replay_threshold();
    test_unmitigated_auth_fail();
    test_status_string();

    /* Print dump for manual inspection */
    printf("\n--- Audit dump from final test context ---\n");
    ks_sora_ctx_t ctx;
    ks_sora_init(&ctx);
    ks_sora_log(&ctx, KS_SORA_KEY_ROTATED,     1000u, 1u, 1u, 0u);
    ks_sora_log(&ctx, KS_SORA_MUTUAL_AUTH_OK,  1100u, 1u, 2u, 0u);
    ks_sora_log(&ctx, KS_SORA_REPLAY_REJECTED, 1200u, 255u, 3u, 6u);
    ks_sora_dump(&ctx);

    /* Summary */
    printf("══════════════════════════════════════════════════════\n");
    printf("  Tests run:    %d\n", g_tests_run);
    printf("  Tests passed: %d\n", g_tests_passed);
    printf("  Tests failed: %d\n", g_tests_failed);
    printf("══════════════════════════════════════════════════════\n");

    if (g_tests_failed > 0)
    {
        printf("RESULT: ❌ FAILED (%d test(s) did not pass)\n\n", g_tests_failed);
        return 1;
    }

    printf("RESULT: ✅ ALL TESTS PASSED\n\n");
    return 0;
}
