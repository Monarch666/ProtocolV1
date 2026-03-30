#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kestrel.h"
#include "kestrel_keymanager.h"

int main() {
    printf("--- Testing Persistent CSPRNG & Atomic Key Rotation ---\n");
    fflush(stdout);

    ks_session_t session;
    uint8_t initial_key[32];
    
    // Seed initial key
    if (ks_generate_random_key(initial_key) != 0) {
        printf("FAILED: ks_generate_random_key for initial key\n");
        fflush(stdout);
        return 1;
    }

    if (ks_session_init(&session, initial_key) != 0) {
        printf("FAILED: ks_session_init\n");
        fflush(stdout);
        return 1;
    }

    printf("Session initialized. Initial nonce counter: %u\n", session.nonce_state.counter);
    fflush(stdout);

    // Get a new key
    uint8_t new_key[32];
    if (ks_generate_random_key(new_key) != 0) {
        printf("FAILED: ks_generate_random_key for new key\n");
        fflush(stdout);
        return 1;
    }

    // Save old key for comparison (in a real app, caller saves for grace window)
    uint8_t grace_key[32];
    memcpy(grace_key, session.key, 32);

    // Rotate
    printf("Rotating key...\n");
    fflush(stdout);
    if (ks_atomic_key_rotate(&session, new_key) != 0) {
        printf("FAILED: ks_atomic_key_rotate\n");
        fflush(stdout);
        return 1;
    }

    // Verify
    printf("Rotation successful.\n");
    fflush(stdout);
    printf("New nonce counter: %u\n", session.nonce_state.counter);
    fflush(stdout);
    
    if (memcmp(session.key, new_key, 32) == 0) {
        printf("SUCCESS: Session key matches new key.\n");
        fflush(stdout);
    } else {
        printf("FAILED: Session key doesn't match new key.\n");
        fflush(stdout);
    }

    if (memcmp(session.key, grace_key, 32) != 0) {
        printf("SUCCESS: Session key changed from grace key.\n");
        fflush(stdout);
    } else {
        printf("FAILED: Session key did not change.\n");
        fflush(stdout);
    }

    // Cleanup
    ks_secure_zero(new_key, 32);
    ks_secure_zero(grace_key, 32);
    ks_session_destroy(&session);
    ks_keymanager_cleanup();
    
    printf("Cleanup successful.\n");
    fflush(stdout);
    return 0;
}
