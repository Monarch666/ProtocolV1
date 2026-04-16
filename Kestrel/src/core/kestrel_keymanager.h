/**
 * Kestrel Key Management Utilities
 *
 * Secure key loading and management functions for Kestrel protocol.
 * Supports loading keys from files, environment variables, and secure storage.
 *
 * SECURITY NOTES:
 * - Always validate key file permissions (owner read-only recommended)
 * - Clear key buffers from memory after use (use ks_secure_zero)
 * - Never log or print keys in production
 * - Store key files outside of version control
 */

#ifndef KESTREL_KEYMANAGER_H
#define KESTREL_KEYMANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "kestrel.h"  /* ks_session_t — needed by ks_atomic_key_rotate() */

// Key file format identifiers
#define KS_KEY_FORMAT_BINARY 0 // Raw 32-byte binary
#define KS_KEY_FORMAT_HEX 1    // 64-character hex string
#define KS_KEY_FORMAT_BASE64 2 // Base64 encoded

// Error codes
#define KS_KEY_OK 0
#define KS_KEY_ERR_FILE -1       // File not found or cannot open
#define KS_KEY_ERR_PERMISSION -2 // File permissions too open
#define KS_KEY_ERR_SIZE -3       // Invalid key size
#define KS_KEY_ERR_FORMAT -4     // Invalid format
#define KS_KEY_ERR_ENV -5        // Environment variable not found

/**
 * Load encryption key from binary file
 *
 * @param filename    Path to key file (32 bytes)
 * @param key_out     Output buffer for key (must be 32 bytes)
 * @param check_perms If true, verify file permissions are restrictive
 * @return KS_KEY_OK on success, negative error code on failure
 *
 * Example:
 *   uint8_t key[32];
 *   int result = ks_load_key_from_file("uav1_key.bin", key, true);
 *   if (result != KS_KEY_OK) {
 *       fprintf(stderr, "Failed to load key: %d\n", result);
 *   }
 */
int ks_load_key_from_file(const char *filename, uint8_t key_out[32], bool check_perms);

/**
 * Load encryption key from hex string file
 *
 * @param filename Path to text file containing 64-character hex string
 * @param key_out  Output buffer for key (must be 32 bytes)
 * @return KS_KEY_OK on success, negative error code on failure
 *
 * Example hex file content:
 *   a1b2c3d4e5f6071829384756a1b2c3d4e5f6071829384756a1b2c3d4e5f60718
 */
int ks_load_key_from_hex_file(const char *filename, uint8_t key_out[32]);

/**
 * Load encryption key from environment variable
 *
 * @param var_name Environment variable name
 * @param key_out  Output buffer for key (must be 32 bytes)
 * @param format   Expected format (KS_KEY_FORMAT_HEX or KS_KEY_FORMAT_BASE64)
 * @return KS_KEY_OK on success, negative error code on failure
 *
 * Example:
 *   export KESTREL_KEY="a1b2c3d4e5f6071829384756a1b2c3d4e5f6071829384756a1b2c3d4e5f60718"
 *   uint8_t key[32];
 *   ks_load_key_from_env("KESTREL_KEY", key, KS_KEY_FORMAT_HEX);
 */
int ks_load_key_from_env(const char *var_name, uint8_t key_out[32], int format);

/**
 * Generate random key using the platform CSPRNG.
 *
 * @param key_out Output buffer for key (must be 32 bytes)
 * @return 0 on success, -1 on failure.
 *
 * BUG-10 FIX: Previously returned void, silently leaving key_out zeroed on
 * failure. Now returns -1 so callers can detect and abort on entropy failure.
 *
 * WARNING: Not suitable for production use. Use keygen.py to generate
 * cryptographically secure keys from proper entropy sources.
 */
int ks_generate_random_key(uint8_t key_out[32]);

/**
 * Securely zero key buffer in memory
 *
 * @param key     Key buffer to clear
 * @param key_len Length of key buffer
 *
 * Uses compiler barriers to prevent optimization from removing the memset.
 * Call this before freeing key buffers or exiting the program.
 *
 * Example:
 *   uint8_t key[32];
 *   // ... use key ...
 *   ks_secure_zero(key, 32);
 */
void ks_secure_zero(void *key, size_t key_len);

/**
 * Verify file has restrictive permissions (owner-only read/write)
 *
 * @param filename Path to file to check
 * @return true if permissions are secure, false otherwise
 *
 * On Unix: checks that only owner has read/write access
 * On Windows: checks that file is not world-readable
 */
bool ks_check_file_permissions(const char *filename);

/**
 * Get error description string
 *
 * @param error_code Error code from key loading function
 * @return Human-readable error description
 */
const char *ks_key_error_string(int error_code);

/**
 * Release the persistent CSPRNG handle (persistent /dev/urandom fd).
 *
 * Call this once during application shutdown — in your SIGTERM/SIGINT handler
 * AND at the end of main(). Safe to call multiple times (idempotent).
 * No-op on Windows.
 */
void ks_keymanager_cleanup(void);

/**
 * Atomically rotate the session key in three guaranteed stages:
 * Prepare → Commit → Wipe.
 *
 * The old key is always zeroed from memory, even if the caller crashes
 * immediately after. The nonce state is re-initialised via ks_nonce_init()
 * which seeds a new unpredictable counter offset from the platform CSPRNG.
 * If the CSPRNG fails, the session is rolled back to its previous valid state.
 *
 * @param session  Active session to rotate (must be initialised)
 * @param new_key  32-byte replacement key
 * @return 0 on success, -1 on bad arguments, uninitialised session, or CSPRNG failure
 *
 * IMPORTANT: If you need the old key for a grace window (double-buffer),
 * memcpy it out of session->key BEFORE calling this function.
 * Do NOT pass new_key == session->key (self-rotation is caught and rejected).
 */
int ks_atomic_key_rotate(ks_session_t *session, const uint8_t new_key[32]);

/* ==========================================================================
 * IEC 62443-4-2 CR 1.5 — Key Lifecycle Management
 *
 * These types are defined in kestrel_keymanager.h because lifecycle tracking
 * is a natural keymanager concern.  kestrel_iec62443.h includes this header
 * so that the audit module can reference ks_key_lifecycle_t directly.
 * ======================================================================== */

/** Maximum packets encrypted per key before crypto-wear limit is reached. */
#define KS_KEY_LIFECYCLE_MAX_PACKETS  (1UL << 24)  /* ~16 million packets       */

/** Recommended key lifetime constants. */
#define KS_KEY_LIFETIME_1H_MS    3600000UL  /* 1 hour  — short-haul flights   */
#define KS_KEY_LIFETIME_8H_MS   28800000UL  /* 8 hours — long-endurance UAVs  */
#define KS_KEY_LIFETIME_NONE           0UL  /* No expiry (manual rotation)    */

/** How a session key was provisioned — recorded in the lifecycle for auditing. */
typedef enum {
    KS_KEY_ORIGIN_GENERATED = 0x01,  /* ks_generate_random_key()             */
    KS_KEY_ORIGIN_FILE      = 0x02,  /* Loaded from file (ks_load_key_from_file) */
    KS_KEY_ORIGIN_ENV       = 0x03,  /* Loaded from env  (ks_load_key_from_env)  */
    KS_KEY_ORIGIN_EXCHANGE  = 0x04,  /* Derived via X25519 ECDH handshake    */
} ks_key_origin_t;

/**
 * Key lifecycle record — tracks expiry, revocation, and cryptographic wear.
 *
 * Attach one of these to every session key.  Pass it to ks_lc_touch_encrypt()
 * / ks_lc_touch_decrypt() on every crypto operation, and call ks_lc_is_valid()
 * before encrypting to enforce CR 1.5 key expiry and revocation.
 */
typedef struct {
    uint32_t created_at_ms;      /* Monotonic ms when key was provisioned     */
    uint32_t max_lifetime_ms;    /* Max age in ms; 0 = no expiry              */
    uint32_t last_used_ms;       /* ms timestamp of last encrypt/decrypt call */
    uint64_t packets_encrypted;  /* Outbound crypto-wear counter              */
    uint64_t packets_decrypted;  /* Inbound  crypto-wear counter              */
    uint8_t  origin;             /* ks_key_origin_t                           */
    bool     revoked;            /* Set true by GCS KS_MSG_KEY_REVOKE         */
    uint8_t  key_id;             /* XOR-folded key ID for audit correlation   */
    uint8_t  sl_assert;          /* Asserted SL level (2 = IEC 62443-4-2 SL2) */
} ks_key_lifecycle_t;

/**
 * Initialise a key lifecycle record for a freshly provisioned key.
 *
 * @param lc          Lifecycle record to initialise
 * @param key         The 32-byte session key (used only to derive key_id)
 * @param origin      How the key was created (ks_key_origin_t)
 * @param lifetime_ms Max permitted key age in ms (0 = no expiry)
 * @param now_ms      Current monotonic timestamp in ms
 */
void ks_lc_init(ks_key_lifecycle_t *lc, const uint8_t key[32],
                uint8_t origin, uint32_t lifetime_ms, uint32_t now_ms);

/**
 * Update last_used_ms and increment packets_encrypted.
 * Call immediately after any successful encryption operation.
 */
void ks_lc_touch_encrypt(ks_key_lifecycle_t *lc, uint32_t now_ms);

/**
 * Update last_used_ms and increment packets_decrypted.
 * Call immediately after any successful decryption operation.
 */
void ks_lc_touch_decrypt(ks_key_lifecycle_t *lc, uint32_t now_ms);

/**
 * CR 1.5: Check whether the key is still within its lifecycle bounds.
 *
 * Returns false if any of the following apply:
 *   - lc->revoked is true
 *   - max_lifetime_ms > 0 and the key has exceeded its maximum age
 *   - packets_encrypted >= KS_KEY_LIFECYCLE_MAX_PACKETS (crypto-wear limit)
 */
bool ks_lc_is_valid(const ks_key_lifecycle_t *lc, uint32_t now_ms);

/**
 * CR 1.9: Assert that the key's declared SL meets or exceeds required_sl.
 * Returns true if lc->sl_assert >= required_sl.
 */
bool ks_lc_assert_sl(const ks_key_lifecycle_t *lc, uint8_t required_sl);

/**
 * IEC 62443-4-2 CR 1.5: Generate a fresh key AND initialise its lifecycle.
 *
 * Combines ks_generate_random_key() + ks_lc_init() in one call.
 * After success, log KS_AUDIT_KEY_GENERATED via ks_iec62443_audit().
 *
 * @param key_out      Output: 32-byte session key
 * @param lc_out       Output: populated lifecycle record
 * @param lifetime_ms  Max key age in ms (0 = no expiry)
 * @param now_ms       Current monotonic timestamp in ms
 * @return 0 on success, -1 on CSPRNG failure
 */
int ks_generate_key_with_lifecycle(uint8_t key_out[32],
                                   ks_key_lifecycle_t *lc_out,
                                   uint32_t lifetime_ms,
                                   uint32_t now_ms);

/**
 * IEC 62443-4-2 CR 1.5: Atomically rotate a session key and reset its lifecycle.
 *
 * Wraps ks_atomic_key_rotate() and then re-initialises the lifecycle record
 * for the new key (resets wear counters, updates created_at_ms).
 * After success, log KS_AUDIT_KEY_ROTATED via ks_iec62443_audit().
 *
 * @param session      Active session to rotate (must be initialised)
 * @param new_key      32-byte replacement key
 * @param lc           Lifecycle record to reset for the new key
 * @param lifetime_ms  Max age for the new key (0 = no expiry)
 * @param now_ms       Current monotonic timestamp in ms
 * @return 0 on success, -1 on bad arguments, uninitialised session, or CSPRNG
 */
int ks_rotate_with_lifecycle(ks_session_t *session,
                              const uint8_t new_key[32],
                              ks_key_lifecycle_t *lc,
                              uint32_t lifetime_ms,
                              uint32_t now_ms);

#endif // KESTREL_KEYMANAGER_H
