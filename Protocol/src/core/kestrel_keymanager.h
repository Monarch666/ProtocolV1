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

#endif // KESTREL_KEYMANAGER_H
