/* Feature-test macro: required for O_CLOEXEC on glibc (must precede all includes) */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/**
 * Kestrel Key Management Utilities - Implementation
 */

#include "kestrel_keymanager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <aclapi.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>   /* open(), O_RDONLY, O_CLOEXEC */
#endif

/* -----------------------------------------------------------------------
 * PERSISTENT CSPRNG HANDLE
 * Opens /dev/urandom once and keeps the fd alive for the process lifetime.
 * Eliminates open()/close() syscall overhead on every key generation call.
 * Thread safety: safe for single-threaded embedded use. If your platform
 * uses pthreads, wrap get_urandom_fd() with pthread_once().
 * ----------------------------------------------------------------------- */
#ifndef _WIN32
static int s_urandom_fd = -1;

static int get_urandom_fd(void)
{
    if (s_urandom_fd == -1) {
        /* O_CLOEXEC: child processes spawned via fork/exec do NOT inherit
         * this fd — critical if the UAV software ever launches subprocesses. */
        s_urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (s_urandom_fd == -1) {
            fprintf(stderr, "ERROR: Cannot open /dev/urandom\n");
        }
    }
    return s_urandom_fd;
}
#endif

// Securely zero memory (prevents compiler optimization)
void ks_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL)
        return;

    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--)
    {
        *p++ = 0;
    }
}

// Check file permissions
bool ks_check_file_permissions(const char *filename)
{
#ifdef _WIN32
    // Windows: Check that file is not world-readable
    DWORD result = GetFileAttributesA(filename);
    if (result == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }

    // Basic ACL checking - Ensure "Everyone" doesn't have read access
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;
    bool secure = false;

    /* GetNamedSecurityInfoA expects non-const LPSTR — cast explicitly to satisfy MinGW */
    char *filename_nc = (char *)(uintptr_t)filename;
    if (GetNamedSecurityInfoA(filename_nc, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSD) == ERROR_SUCCESS)
    {
        // Try to find if "Everyone" (World) has any access
        ACL_SIZE_INFORMATION aclSize;
        if (GetAclInformation(pDacl, &aclSize, sizeof(aclSize), AclSizeInformation))
        {
            secure = true; // Assume secure unless we find a wide-open ACE
            PSID everyoneSid = NULL;
            SID_IDENTIFIER_AUTHORITY worldAuth = { SECURITY_WORLD_SID_AUTHORITY }; /* braces fix -Wmissing-braces */
            if (AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyoneSid))
            {
                for (DWORD i = 0; i < aclSize.AceCount; i++)
                {
                    PVOID pAce = NULL;
                    if (GetAce(pDacl, i, &pAce))
                    {
                        PACE_HEADER pHeader = (PACE_HEADER)pAce;
                        if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
                        {
                            ACCESS_ALLOWED_ACE *pAllowed = (ACCESS_ALLOWED_ACE *)pAce;
                            if (EqualSid(everyoneSid, (PSID)&pAllowed->SidStart))
                            {
                                // Everyone has some access - this is insecure for a key file
                                secure = false;
                                fprintf(stderr, " Warning: Key file %s is accessible by 'Everyone'\n", filename);
                                break;
                            }
                        }
                    }
                }
                FreeSid(everyoneSid);
            }
        }
        LocalFree(pSD);
    }

    return secure;
#else
    // Unix/Linux: Check that only owner has read/write
    struct stat st;
    if (stat(filename, &st) != 0)
    {
        return false;
    }

    // Check that group and others have no permissions
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        fprintf(stderr, " Warning: Key file %s has insecure permissions\n", filename);
        fprintf(stderr, "    Run: chmod 600 %s\n", filename);
        return false;
    }

    return true;
#endif
}

// Load binary key from file
int ks_load_key_from_file(const char *filename, uint8_t key_out[32], bool check_perms)
{
    if (filename == NULL || key_out == NULL)
    {
        return KS_KEY_ERR_FILE;
    }

    // Check permissions if requested
    if (check_perms && !ks_check_file_permissions(filename))
    {
        return KS_KEY_ERR_PERMISSION;
    }

    // Open file
    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        return KS_KEY_ERR_FILE;
    }

    // Read exactly 32 bytes
    size_t bytes_read = fread(key_out, 1, 32, f);
    fclose(f);

    if (bytes_read != 32)
    {
        ks_secure_zero(key_out, 32);
        return KS_KEY_ERR_SIZE;
    }

    return KS_KEY_OK;
}

// Convert hex character to value
static int hex_to_int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// Load key from hex string file
int ks_load_key_from_hex_file(const char *filename, uint8_t key_out[32])
{
    if (filename == NULL || key_out == NULL)
    {
        return KS_KEY_ERR_FILE;
    }

    // Open file
    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        return KS_KEY_ERR_FILE;
    }

    // Read hex string (need 64 characters)
    char hex_string[128];
    if (fgets(hex_string, sizeof(hex_string), f) == NULL)
    {
        fclose(f);
        return KS_KEY_ERR_FORMAT;
    }
    fclose(f);

    // Remove whitespace and newlines
    int hex_len = 0;
    for (int i = 0; hex_string[i] != '\0' && hex_len < 128; i++)
    {
        if (!isspace(hex_string[i]))
        {
            hex_string[hex_len++] = hex_string[i];
        }
    }

    // Must be exactly 64 hex characters
    if (hex_len != 64)
    {
        return KS_KEY_ERR_SIZE;
    }

    // Convert hex to binary
    for (int i = 0; i < 32; i++)
    {
        int hi = hex_to_int(hex_string[i * 2]);
        int lo = hex_to_int(hex_string[i * 2 + 1]);

        if (hi < 0 || lo < 0)
        {
            ks_secure_zero(key_out, 32);
            return KS_KEY_ERR_FORMAT;
        }

        key_out[i] = (hi << 4) | lo;
    }

    return KS_KEY_OK;
}

// Load key from environment variable
int ks_load_key_from_env(const char *var_name, uint8_t key_out[32], int format)
{
    if (var_name == NULL || key_out == NULL)
    {
        return KS_KEY_ERR_ENV;
    }

    const char *env_value = getenv(var_name);
    if (env_value == NULL)
    {
        return KS_KEY_ERR_ENV;
    }

    if (format == KS_KEY_FORMAT_HEX)
    {
        // Parse hex string
        size_t len = strlen(env_value);
        if (len != 64)
        {
            return KS_KEY_ERR_SIZE;
        }

        for (int i = 0; i < 32; i++)
        {
            int hi = hex_to_int(env_value[i * 2]);
            int lo = hex_to_int(env_value[i * 2 + 1]);

            if (hi < 0 || lo < 0)
            {
                ks_secure_zero(key_out, 32);
                return KS_KEY_ERR_FORMAT;
            }

            key_out[i] = (hi << 4) | lo;
        }

        return KS_KEY_OK;
    }

    // Other formats not implemented
    return KS_KEY_ERR_FORMAT;
}

/* BUG-10 FIX: Return int (0 = success, -1 = failure) so callers never
 * unknowingly use a zeroed key when Cryptographically Secure Pseudorandom Number Generator (CSPRNG) initialisation fails. */
int ks_generate_random_key(uint8_t key_out[32])
{
    if (key_out == NULL)
        return -1;

#ifdef _WIN32
    HCRYPTPROV hProvider;
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        fprintf(stderr, "ERROR: Failed to acquire Windows Crypto Context!\n");
        ks_secure_zero(key_out, 32);
        return -1;
    }
    if (!CryptGenRandom(hProvider, 32, key_out))
    {
        fprintf(stderr, "ERROR: CryptGenRandom failed!\n");
        CryptReleaseContext(hProvider, 0);
        ks_secure_zero(key_out, 32);
        return -1;
    }
    CryptReleaseContext(hProvider, 0);
    return 0;
#else
    /* Use the persistent fd — no open()/close() overhead. */
    int fd = get_urandom_fd();
    if (fd == -1) {
        ks_secure_zero(key_out, 32);
        return -1;
    }

    ssize_t bytes = read(fd, key_out, 32);
    if (bytes != 32) {
        fprintf(stderr, "ERROR: Short read from /dev/urandom (%zd/32 bytes)\n",
                bytes);
        ks_secure_zero(key_out, 32);
        return -1;
    }
    return 0;
    /* fd intentionally left open — closed by ks_keymanager_cleanup() */
#endif
}

// Get error description
const char *ks_key_error_string(int error_code)
{
    switch (error_code)
    {
    case KS_KEY_OK:
        return "Success";
    case KS_KEY_ERR_FILE:
        return "File not found or cannot open";
    case KS_KEY_ERR_PERMISSION:
        return "File has insecure permissions";
    case KS_KEY_ERR_SIZE:
        return "Invalid key size";
    case KS_KEY_ERR_FORMAT:
        return "Invalid key format";
    case KS_KEY_ERR_ENV:
        return "Environment variable not found";
    default:
        return "Unknown error";
    }
}

/* -----------------------------------------------------------------------
 * PERSISTENT CSPRNG CLEANUP
 * Closes the cached /dev/urandom fd. Call once at application shutdown
 * (SIGTERM handler + end of main). Idempotent — safe to call multiple times.
 * No-op on Windows.
 * ----------------------------------------------------------------------- */
void ks_keymanager_cleanup(void)
{
#ifndef _WIN32
    if (s_urandom_fd != -1) {
        close(s_urandom_fd);
        s_urandom_fd = -1;
    }
#endif
}

/* -----------------------------------------------------------------------
 * ATOMIC KEY ROTATION
 *
 * Sequences the swap as three strict stages to ensure the old key is
 * always wiped, even if something goes wrong after the commit.
 *
 * CORRECT CALLER PATTERN when you need the old key for a grace window:
 *
 *   uint8_t grace_key[32];
 *   memcpy(grace_key, session->key, 32);          // save old BEFORE rotate
 *   int r = ks_atomic_key_rotate(session, new_key);
 *   if (r == 0) {
 *       // use grace_key for the window period...
 *       ks_secure_zero(grace_key, 32);             // caller must wipe it
 *   }
 *
 * Why not pass grace_key into this function?
 * Because forcing the caller to copy first makes the intent explicit and
 * prevents accidental use of a stale pointer after the wipe.
 * ----------------------------------------------------------------------- */
int ks_atomic_key_rotate(ks_session_t *session, const uint8_t new_key[32])
{
    /* --- Guard rails --------------------------------------------------- */
    if (session == NULL || new_key == NULL)
        return -1;

    if (!session->initialized) {
        fprintf(stderr, "ERROR: ks_atomic_key_rotate called on uninitialised session\n");
        return -1;
    }

    /* Detect the self-rotation bug at the call site:
     * if new_key points into session->key we'd wipe data we just wrote. */
    if (new_key == session->key) {
        fprintf(stderr, "ERROR: ks_atomic_key_rotate: new_key aliases session->key\n");
        return -1;
    }

    int result = 0;

    /* --- STAGE 1: PREPARE ---
     * Copy old key and nonce state to stack so we can roll back on failure
     * and unconditionally wipe the old key material in Stage 3. */
    uint8_t old_key[32];
    memcpy(old_key, session->key, 32);
    ks_nonce_state_t old_nonce_state = session->nonce_state;

    /* --- STAGE 2: COMMIT ---
     * Write the new key into the session. After this line the session is live
     * on the new key. Any packet encrypted from here uses new_key.
     *
     * Reset the nonce counter to 0 for the new key. This ensures both sides
     * stay in sync on the new starting nonce without explicit negotiation.
     * Nonce uniqueness is per-key, so resetting to 0 for a fresh key is safe. */
    // memcpy(session->key, new_key, 32);
    // session->nonce_state.counter = 0;
    // session->nonce_state.initialized = 1;
    memcpy(session->key, new_key, 32);
    if (ks_nonce_init(&session->nonce_state) != 0) {
        /* CSPRNG failed — roll back to old key and nonce state */
        memcpy(session->key, old_key, 32);
        session->nonce_state = old_nonce_state;
        result = -1;
    }

    /* --- STAGE 3: WIPE ---
     * Zero the old key and nonce copies unconditionally.
     * ks_secure_zero uses a volatile loop — the compiler cannot elide it.
     * This executes on BOTH success and rollback paths. */
    ks_secure_zero(old_key, 32);
    ks_secure_zero(&old_nonce_state, sizeof(old_nonce_state));

    return result;
}

/* ==========================================================================
 * IEC 62443-4-2 CR 1.5 — Key Lifecycle Functions
 *
 * Key ID derivation: XOR-fold all 32 key bytes into one byte.
 * Deterministic, stateless, correlatable across reboots — aligns with the
 * Kestrel protocol philosophy of "zero implicit state where possible".
 * ======================================================================== */

static uint8_t derive_key_id(const uint8_t key[32])
{
    uint8_t id = 0;
    int i;
    for (i = 0; i < 32; i++) {
        id ^= key[i];
    }
    return id;
}

void ks_lc_init(ks_key_lifecycle_t *lc, const uint8_t key[32],
                uint8_t origin, uint32_t lifetime_ms, uint32_t now_ms)
{
    if (lc == NULL || key == NULL) return;

    memset(lc, 0, sizeof(ks_key_lifecycle_t));
    lc->created_at_ms   = now_ms;
    lc->max_lifetime_ms = lifetime_ms;
    lc->last_used_ms    = now_ms;
    lc->origin          = origin;
    lc->sl_assert       = 2u; /* IEC 62443-4-2 Security Level 2 target */
    lc->key_id          = derive_key_id(key);
    lc->revoked         = false;
}

void ks_lc_touch_encrypt(ks_key_lifecycle_t *lc, uint32_t now_ms)
{
    if (lc == NULL) return;
    lc->last_used_ms = now_ms;
    lc->packets_encrypted++;
}

void ks_lc_touch_decrypt(ks_key_lifecycle_t *lc, uint32_t now_ms)
{
    if (lc == NULL) return;
    lc->last_used_ms = now_ms;
    lc->packets_decrypted++;
}

bool ks_lc_is_valid(const ks_key_lifecycle_t *lc, uint32_t now_ms)
{
    if (lc == NULL)             return false;
    if (lc->revoked)            return false;

    /* Expiry check (only when a finite lifetime is configured) */
    if (lc->max_lifetime_ms > 0u &&
        (now_ms - lc->created_at_ms) > lc->max_lifetime_ms) {
        return false;
    }

    /* Crypto-wear limit: retire the key after ~16 million encryptions */
    if (lc->packets_encrypted >= (uint64_t)KS_KEY_LIFECYCLE_MAX_PACKETS) {
        return false;
    }

    return true;
}

bool ks_lc_assert_sl(const ks_key_lifecycle_t *lc, uint8_t required_sl)
{
    if (lc == NULL) return false;
    return (lc->sl_assert >= required_sl);
}

int ks_generate_key_with_lifecycle(uint8_t key_out[32],
                                   ks_key_lifecycle_t *lc_out,
                                   uint32_t lifetime_ms,
                                   uint32_t now_ms)
{
    if (key_out == NULL || lc_out == NULL) return -1;

    if (ks_generate_random_key(key_out) != 0) return -1;

    ks_lc_init(lc_out, key_out,
               (uint8_t)KS_KEY_ORIGIN_GENERATED, lifetime_ms, now_ms);
    return 0;
}

int ks_rotate_with_lifecycle(ks_session_t *session,
                              const uint8_t new_key[32],
                              ks_key_lifecycle_t *lc,
                              uint32_t lifetime_ms,
                              uint32_t now_ms)
{
    if (session == NULL || new_key == NULL || lc == NULL) return -1;

    if (ks_atomic_key_rotate(session, new_key) != 0) return -1;

    /* Preserve the origin across rotations (key was still derived the same way) */
    uint8_t origin = lc->origin;
    ks_lc_init(lc, new_key, origin, lifetime_ms, now_ms);

    return 0;
}
