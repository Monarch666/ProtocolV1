/*
 * Kestrel Bidirectional GCS (Ground Control Station)
 *
 * Receives telemetry on UDP port 14552 (UAV -> GCS)
 * Sends commands on UDP port 14553 (GCS -> UAV)
 * Receives ACKs on UDP port 14552 (UAV -> GCS)
 *
 * Interactive command menu via stdin (non-blocking)
 */

#include "kestrel.h"
#include "kestrel_fast.h"
#include "monocypher.h"
#include "kestrel_sora.h"   /* JARUS SORA OSO#06 compliance shim */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <conio.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/select.h>
#endif

// Cross-platform millisecond timer
static uint32_t get_time_ms(void)
{
#ifdef _WIN32
    return (uint32_t)GetTickCount();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
}

// Cryptographically secure random number generator
static void secure_random(uint8_t *buf, size_t len)
{
#ifdef _WIN32
    // Dynamically load RtlGenRandom from advapi32.dll (works on all MinGW versions)
    typedef BOOLEAN(WINAPI * RtlGenRandomFunc)(PVOID, ULONG);
    static RtlGenRandomFunc pRtlGenRandom = NULL;
    if (!pRtlGenRandom)
    {
        HMODULE hAdv = LoadLibraryA("advapi32.dll");
        if (hAdv)
            pRtlGenRandom = (RtlGenRandomFunc)GetProcAddress(hAdv, "SystemFunction036");
    }
    if (pRtlGenRandom)
    {
        pRtlGenRandom(buf, (ULONG)len);
    }
    else
    {
        fprintf(stderr, "FATAL: Cannot load RtlGenRandom\n");
        exit(1);
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f)
    {
        if (fread(buf, 1, len, f) != len)
        {
            fprintf(stderr, "FATAL: /dev/urandom short read\n");
            fclose(f);
            exit(1);
        }
        fclose(f);
    }
    else
    {
        fprintf(stderr, "FATAL: Cannot open /dev/urandom\n");
        exit(1);
    }
#endif
}

// ECDH Session Key State
static ks_session_t g_session;           /* Session bundling key + nonce state */
static bool g_session_ready = false;     /* true once ks_session_init() has run */

/* JARUS SORA OSO#06: Security event log — global to GCS process lifetime */
static ks_sora_ctx_t g_sora_ctx;
static uint8_t private_key[32] = {0};
static uint8_t public_key[32]  = {0};

// Identity Key State
static uint8_t gcs_id_seed[32] = {0};
static uint8_t gcs_id_secret[64] = {0};
static uint8_t gcs_id_public[32] = {0};
static uint8_t uav_id_public[32] = {0};

static ks_ecdh_state_t ecdh_state = KS_ECDH_IDLE;
static uint8_t ecdh_seq_num = 1;         // Our handshake sequence number
static uint8_t ecdh_peer_seq = 0;        // Peer's sequence number
static uint32_t ecdh_retry_count = 0;    // Number of retries
static uint32_t ecdh_last_send_time = 0; // For exponential backoff
static uint32_t ecdh_timeout_ms = 5000;  // 5 second timeout

/* DO-362A §2.2.4: Failsafe parameters the GCS commands into the UAV via heartbeat.
 * Configurable at runtime via --failsafe-action / --failsafe-timeout CLI args.
 * Defaults match UAV compile-time defaults so the link is self-consistent out-of-box. */
static uint8_t  g_failsafe_action  = 2;   /* 0=none 1=Land 2=RTL(default) 3=Hover */
static uint16_t g_failsafe_timeout = 3;   /* seconds of silence before failsafe fires */

// Flight mode name lookup
static const char *mode_names[] = {
    "MANUAL", "STABILIZE", "ALT_HOLD", "LOITER",
    "AUTO", "RTL", "LAND"};

static const char *get_mode_name(uint8_t mode)
{
    if (mode <= KS_MODE_LAND)
        return mode_names[mode];
    return "UNKNOWN";
}

// ACK result name lookup
static const char *get_ack_result(uint8_t result)
{
    switch (result)
    {
    case KS_ACK_OK:
        return "OK";
    case KS_ACK_REJECTED:
        return "REJECTED";
    case KS_ACK_UNSUPPORTED:
        return "UNSUPPORTED";
    case KS_ACK_FAILED:
        return "FAILED";
    case KS_ACK_IN_PROGRESS:
        return "IN_PROGRESS";
    default:
        return "UNKNOWN";
    }
}

// --- Nonce Persistence (NVM) Helpers ---
static void save_nonce_state(const ks_session_t *s, const char *filename)
{
    if (!s || !s->initialized)
        return;
    FILE *f = fopen(filename, "wb");
    if (f)
    {
        uint32_t current_counter = ks_nonce_get_counter(&s->nonce_state);
        fwrite(&current_counter, sizeof(uint32_t), 1, f);
        fclose(f);
    }
}

static void load_nonce_counter(ks_session_t *s, const char *filename)
{
    /* Must be called AFTER ks_session_init() has been called on s */
    if (!s || !s->initialized)
        return;
    FILE *f = fopen(filename, "rb");
    if (f)
    {
        uint32_t saved_counter = 0;
        if (fread(&saved_counter, sizeof(uint32_t), 1, f) == 1)
        {
            // Jump by 10000 to prevent reuse if power was lost before a save
            saved_counter += 10000;
            ks_nonce_set_counter(&s->nonce_state, saved_counter);
            printf("NVM: Loaded nonce counter %u from %s (with safety jump)\n", saved_counter, filename);
        }
        fclose(f);
    }
    else
    {
        printf("NVM: No saved nonce found (%s), starting fresh.\n", filename);
    }

    // Save immediately so the jumped value is committed to disk
    save_nonce_state(s, filename);
}

static void print_menu(void)
{
    printf("\n--------- Command Menu ---------\n");
    printf("  1: ARM         2: DISARM\n");
    printf("  3: TAKEOFF     4: LAND\n");
    printf("  5: RTL         6: EMERGENCY STOP\n");
    printf("  7: Mode Change 8: Send Waypoint\n");
    printf("  9: Upload Mission (fragmented)\n");
    printf("  N: Send NPNT Permission Artifact (keys/test_pa.bin)\n");
    printf("  0: Show Menu  Ctrl+C: Quit\n");
    printf(">>> ");
    fflush(stdout);
}

/* --- DO-377A Sliding Window Command Pipeline --- */
#define DO_377A_MAX_WINDOW_SIZE 4
#define DO_377A_MAX_RETRIES 3
#define CMD_QUEUE_SIZE 256

typedef struct
{
    ks_header_t header;
    uint8_t payload[256]; /* KS_FRAG_MAX_PAYLOAD */
    uint16_t cmd_id;      /* For logging */
} queued_cmd_t;

typedef struct
{
    bool active;
    uint32_t send_time_ms;
    uint16_t sequence;
    uint16_t msg_id;
    uint16_t cmd_id;
    uint8_t retries;
    ks_header_t header;
    uint8_t payload[256];
} in_flight_cmd_t;

static queued_cmd_t cmd_queue[CMD_QUEUE_SIZE];
static int cmd_queue_head = 0;
static int cmd_queue_tail = 0;

static in_flight_cmd_t g_cmd_window[DO_377A_MAX_WINDOW_SIZE] = {0};
static uint8_t in_flight_count = 0;

/* Send immediately without queuing (used by ECDH and the window dispatcher) */
static int send_packet_direct(int sock, struct sockaddr_in *dest,
                              const ks_header_t *header, const uint8_t *payload,
                              ks_mempool_t *pool, ks_session_t *session,
                              ks_crypto_ctx_t *crypto_ctx)
{
    uint8_t *packet_buf = NULL;
    int packet_len = ks_pack_fast(pool, header, payload, session,
                                  crypto_ctx, &packet_buf);

    if (packet_len > 0 && packet_buf)
    {
        sendto(sock, (char *)packet_buf, packet_len, 0,
               (struct sockaddr *)dest, sizeof(*dest));
        ks_mempool_free(pool, packet_buf);
        return packet_len;
    }
    return -1;
}

// Send a command packet to the UAV
static int send_command_packet(int sock, struct sockaddr_in *dest,
                               const ks_header_t *header, const uint8_t *payload,
                               ks_mempool_t *pool, ks_session_t *session,
                               ks_crypto_ctx_t *crypto_ctx)
{
    /* Bypass window for handshake */
    if (header->msg_id == KS_MSG_KEY_EXCHANGE || header->msg_id == KS_MSG_KEY_EXCHANGE_ACK)
    {
        return send_packet_direct(sock, dest, header, payload, pool, session, crypto_ctx);
    }

    /* Enqueue to sliding window */
    if (((cmd_queue_tail + 1) % CMD_QUEUE_SIZE) == cmd_queue_head)
    {
        printf(">>> ERR: Command queue full!\n");
        return -1;
    }

    queued_cmd_t *q = &cmd_queue[cmd_queue_tail];
    q->header = *header;
    memcpy(q->payload, payload, header->payload_len);
    
    /* Attempt to extract command ID for logging if it's a KS_MSG_CMD */
    if (header->msg_id == KS_MSG_CMD && header->payload_len >= 2) {
        q->cmd_id = payload[0] | (payload[1] << 8);
    } else {
        q->cmd_id = 0;
    }

    cmd_queue_tail = (cmd_queue_tail + 1) % CMD_QUEUE_SIZE;
    return header->payload_len; /* Pretend we sent it successfully */
}

/* Dispatch queued commands into empty window slots and handle timeouts */
static void process_sliding_window(int sock, struct sockaddr_in *dest,
                                   ks_mempool_t *pool, ks_session_t *session,
                                   ks_crypto_ctx_t *crypto_ctx)
{
    if (!g_session_ready) return;

    uint32_t now = get_time_ms();
    uint8_t window_limit = session->window_size > 0 ? session->window_size : 1;
    if (window_limit > DO_377A_MAX_WINDOW_SIZE) window_limit = DO_377A_MAX_WINDOW_SIZE;
    
    uint16_t ack_timeout = session->ack_timeout_ms > 0 ? session->ack_timeout_ms : 500;

    /* 1. Handle Timeouts & Retransmissions */
    for (int i = 0; i < DO_377A_MAX_WINDOW_SIZE; i++)
    {
        if (g_cmd_window[i].active)
        {
            if ((now - g_cmd_window[i].send_time_ms) > ack_timeout)
            {
                if (g_cmd_window[i].retries >= DO_377A_MAX_RETRIES)
                {
                    printf("\n>>> DO-377A: Slot %d OUT OF RETRIES for Seq=%u. Dropping.\n>>> ", i, g_cmd_window[i].sequence);
                    g_cmd_window[i].active = false;
                    in_flight_count--;
                    fflush(stdout);
                }
                else
                {
                    g_cmd_window[i].retries++;
                    g_cmd_window[i].send_time_ms = now;
                    printf("\n>>> DO-377A: Timeout Seq=%u in Slot %d, Retransmitting (%d/%d)...\n>>> ", 
                           g_cmd_window[i].sequence, i, g_cmd_window[i].retries, DO_377A_MAX_RETRIES);
                    fflush(stdout);
                    send_packet_direct(sock, dest, &g_cmd_window[i].header, g_cmd_window[i].payload, pool, session, crypto_ctx);
                }
            }
        }
    }

    /* 2. Dispatch New Commands into Empty Slots */
    while (in_flight_count < window_limit && cmd_queue_head != cmd_queue_tail)
    {
        /* Find empty slot */
        int slot = -1;
        for (int i = 0; i < window_limit; i++) {
            if (!g_cmd_window[i].active) { slot = i; break; }
        }
        if (slot == -1) break; /* Should not happen if in_flight_count is correct but safeguard */

        /* Pop from queue */
        queued_cmd_t *q = &cmd_queue[cmd_queue_head];
        cmd_queue_head = (cmd_queue_head + 1) % CMD_QUEUE_SIZE;

        /* Store in window */
        g_cmd_window[slot].active = true;
        g_cmd_window[slot].send_time_ms = now;
        g_cmd_window[slot].sequence = q->header.sequence;
        g_cmd_window[slot].msg_id = q->header.msg_id;
        g_cmd_window[slot].cmd_id = q->cmd_id;
        g_cmd_window[slot].retries = 0;
        g_cmd_window[slot].header = q->header;
        memcpy(g_cmd_window[slot].payload, q->payload, q->header.payload_len);
        in_flight_count++;

        int sent = send_packet_direct(sock, dest, &q->header, q->payload, pool, session, crypto_ctx);
        if (sent > 0)
        {
            printf("\n--- DO-377A: Dispatched Seq=%u to Slot %d limit=%u/%u ---\n>>> ", 
                   q->header.sequence, slot, in_flight_count, window_limit);
            fflush(stdout);
        }
    }
}

/* Remove acknowledged command from window */
static void acknowledge_command(uint16_t seq)
{
    for (int i = 0; i < DO_377A_MAX_WINDOW_SIZE; i++)
    {
        if (g_cmd_window[i].active && g_cmd_window[i].sequence == seq)
        {
            g_cmd_window[i].active = false;
            in_flight_count--;
            break;
        }
    }
}

// Send a generic command (arm, disarm, takeoff, land, etc.)
static void send_cmd(int sock, struct sockaddr_in *dest,
                     uint16_t cmd_id, uint16_t param1,
                     ks_mempool_t *pool, ks_session_t *session,
                     ks_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    ks_command_t cmd = {0};
    cmd.command_id = cmd_id;
    cmd.param1 = param1;

    uint8_t payload[32];
    int payload_len = ks_serialize_command(&cmd, payload);

    ks_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = KS_PRIO_HIGH;
    header.stream_type = KS_STREAM_CMD;
    header.encrypted = true;
    header.sequence = (*seq)++;
    header.sys_id = 255; // GCS
    header.comp_id = 0;
    header.target_sys_id = 1; // UAV
    header.msg_id = KS_MSG_CMD;

    int sent = send_command_packet(sock, dest, &header, payload, pool, session, crypto_ctx);
    if (sent > 0)
        printf("Sent command 0x%04X (%d bytes)\n", cmd_id, sent);
}

typedef enum
{
    AUTO_STEP_CMD = 0,
    AUTO_STEP_MODE = 1
} auto_step_type_t;

typedef struct
{
    auto_step_type_t type;
    uint16_t cmd_id;
    uint16_t param1;
    uint8_t mode;
    uint32_t wait_ms;
    const char *name;
} auto_step_t;

static void send_mode_change(int sock, struct sockaddr_in *dest,
                             uint8_t mode,
                             ks_mempool_t *pool, ks_session_t *session,
                             ks_crypto_ctx_t *crypto_ctx, uint16_t *seq);

static const auto_step_t soak_steps[] = {
    {AUTO_STEP_CMD, KS_CMD_ARM, 0, 0, 15000, "ARM"},
    {AUTO_STEP_CMD, KS_CMD_TAKEOFF, 1000, 0, 25000, "TAKEOFF (10m)"},
    {AUTO_STEP_MODE, 0, 0, KS_MODE_AUTO, 8000, "SET_MODE AUTO"},
    {AUTO_STEP_CMD, KS_CMD_RTL, 0, 0, 25000, "RTL"},
    {AUTO_STEP_CMD, KS_CMD_LAND, 0, 0, 20000, "LAND"},
    {AUTO_STEP_CMD, KS_CMD_DISARM, 0, 0, 12000, "DISARM"},
    {AUTO_STEP_CMD, KS_CMD_ARM, 0, 0, 12000, "ARM"},
    {AUTO_STEP_MODE, 0, 0, KS_MODE_LOITER, 8000, "SET_MODE LOITER"},
    {AUTO_STEP_CMD, KS_CMD_LAND, 0, 0, 20000, "LAND"},
    {AUTO_STEP_CMD, KS_CMD_DISARM, 0, 0, 12000, "DISARM"},
};

static void run_auto_step(int sock, struct sockaddr_in *dest,
                          const auto_step_t *step,
                          ks_mempool_t *pool, ks_session_t *session,
                          ks_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    if (!step)
        return;

    if (step->type == AUTO_STEP_MODE)
    {
        send_mode_change(sock, dest, step->mode, pool, session, crypto_ctx, seq);
    }
    else
    {
        send_cmd(sock, dest, step->cmd_id, step->param1, pool, session, crypto_ctx, seq);
    }
}

// Send a mode change
static void send_mode_change(int sock, struct sockaddr_in *dest,
                             uint8_t mode,
                             ks_mempool_t *pool, ks_session_t *session,
                             ks_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    ks_mode_change_t mc = {0};
    mc.mode = mode;

    uint8_t payload[32];
    int payload_len = ks_serialize_mode_change(&mc, payload);

    ks_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = KS_PRIO_HIGH;
    header.stream_type = KS_STREAM_CMD;
    header.encrypted = true;
    header.sequence = (*seq)++;
    header.sys_id = 255;
    header.comp_id = 0;
    header.target_sys_id = 1;
    header.msg_id = KS_MSG_MODE_CHANGE;

    int sent = send_command_packet(sock, dest, &header, payload, pool, session, crypto_ctx);
    if (sent > 0)
        printf("Sent mode change -> %s (%d bytes)\n", get_mode_name(mode), sent);
}

// Send a mission waypoint
static void send_waypoint(int sock, struct sockaddr_in *dest,
                          uint16_t wp_seq,
                          ks_mempool_t *pool, ks_session_t *session,
                          ks_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    ks_mission_item_t item = {0};
    item.seq = wp_seq;
    item.frame = 0;   // Global
    item.command = 0; // Navigate
    item.lat = 47670000 + (wp_seq * 1000);
    item.lon = -122320000 + (wp_seq * 1000);
    item.alt = 50000 + (wp_seq * 10000); // 50m + 10m per waypoint
    item.speed = 500;                    // 5 m/s

    uint8_t payload[32];
    int payload_len = ks_serialize_mission_item(&item, payload);

    ks_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = KS_PRIO_HIGH;
    header.stream_type = KS_STREAM_CMD;
    header.encrypted = true;
    header.sequence = (*seq)++;
    header.sys_id = 255;
    header.comp_id = 0;
    header.target_sys_id = 1;
    header.msg_id = KS_MSG_MISSION_ITEM;

    int sent = send_command_packet(sock, dest, &header, payload, pool, session, crypto_ctx);
    if (sent > 0)
        printf("Sent waypoint #%u: lat=%d lon=%d alt=%dmm (%d bytes)\n",
               wp_seq, item.lat, item.lon, item.alt, sent);
}

// Check for keyboard input (non-blocking)
static int key_available(void)
{
#ifdef _WIN32
    return _kbhit();
#else
    struct timeval tv = {0, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    return select(1, &fds, NULL, NULL, &tv) > 0;
#endif
}

static int get_key(void)
{
#ifdef _WIN32
    return _getch();
#else
    return getchar();
#endif
}

// Send a fragmented mission plan (5 waypoints packed into one large payload)
static void send_mission_fragmented(int sock, struct sockaddr_in *dest,
                                    ks_mempool_t *pool, ks_session_t *session,
                                    ks_crypto_ctx_t *crypto_ctx, uint16_t *seq)
{
    // Pack 5 waypoints into a single large payload
    uint8_t big_payload[1024];
    int offset = 0;

    // First byte = number of waypoints
    big_payload[offset++] = 5;

    for (int i = 0; i < 5; i++)
    {
        ks_mission_item_t wp = {0};
        wp.seq = i;
        wp.frame = 0;                   // Global
        wp.command = 0;                 // Navigate
        wp.lat = 47670000 + (i * 5000); // Spread waypoints 0.0005 deg apart
        wp.lon = -122320000 + (i * 5000);
        wp.alt = 50000 + (i * 10000);       // 50m, 60m, 70m, 80m, 90m
        wp.speed = 500;                     // 5 m/s
        wp.loiter_time = (i == 2) ? 30 : 0; // Loiter 30s at WP#2

        int len = ks_serialize_mission_item(&wp, big_payload + offset);
        offset += len; // 20 bytes each
    }

    printf("Mission payload: %d bytes (%d waypoints x 20 bytes + 1 header)\n", offset, 5);

    // Fragment the mission payload manually
    // Use 64 bytes per fragment for demonstration
    const int FRAGMENT_SIZE = 64;
    int num_frags = (offset + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE; // Ceiling division

    if (num_frags > 255)
    {
        printf("ERROR: Payload too large (%d fragments needed, max 255)\n", num_frags);
        return;
    }

    printf("Split into %d fragments:\n", num_frags);

    // Send each fragment
    int total_sent = 0;
    for (int i = 0; i < num_frags; i++)
    {
        // Calculate payload slice for this fragment
        int frag_offset = i * FRAGMENT_SIZE;
        int frag_len = (i == num_frags - 1) ? (offset - frag_offset) : FRAGMENT_SIZE;

        // Create header for this fragment
        ks_header_t frag_header = {0};
        frag_header.payload_len = frag_len;
        frag_header.priority = KS_PRIO_HIGH;
        frag_header.stream_type = KS_STREAM_MISSION;
        frag_header.encrypted = true;
        frag_header.fragmented = (num_frags > 1); // Set fragmented flag if multiple fragments
        frag_header.frag_index = i;
        frag_header.frag_total = num_frags;
        frag_header.sequence = (*seq)++;
        frag_header.sys_id = 255; // GCS
        frag_header.comp_id = 0;
        frag_header.target_sys_id = 1; // UAV
        frag_header.msg_id = KS_MSG_MISSION_ITEM;

        int sent = send_command_packet(sock, dest, &frag_header,
                                       big_payload + frag_offset, pool, session, crypto_ctx);
        if (sent > 0)
        {
            printf("  Fragment %d/%d: %d payload bytes, %d wire bytes\n",
                   i + 1, num_frags, frag_len, sent);
            total_sent += sent;
        }

        // Small delay between fragments to avoid overwhelming receiver
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    printf("Mission upload complete: %d fragments, %d total wire bytes\n", num_frags, total_sent);
}

int main(int argc, char *argv[])
{
    printf("=== Kestrel Bidirectional GCS ===\n\n");

    // Determine UAV IP and startup mode
    const char *uav_ip = "127.0.0.1";
    bool auto_soak = false;
    uint16_t send_port = 14553;
    uint16_t listen_port = 14552;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--auto-soak") == 0)
        {
            auto_soak = true;
            continue;
        }

        if (strcmp(argv[i], "--send-port") == 0 && i + 1 < argc)
        {
            send_port = (uint16_t)atoi(argv[++i]);
            continue;
        }

        if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc)
        {
            listen_port = (uint16_t)atoi(argv[++i]);
            continue;
        }

        /* DO-362A: GCS-commanded failsafe configuration */
        if (strcmp(argv[i], "--failsafe-action") == 0 && i + 1 < argc)
        {
            int v = atoi(argv[++i]);
            if (v >= 0 && v <= 3) g_failsafe_action = (uint8_t)v;
            else { printf("ERROR: --failsafe-action must be 0..3 (0=none 1=Land 2=RTL 3=Hover)\n"); return 1; }
            continue;
        }

        if (strcmp(argv[i], "--failsafe-timeout") == 0 && i + 1 < argc)
        {
            int v = atoi(argv[++i]);
            if (v > 0 && v <= 300) g_failsafe_timeout = (uint16_t)v;
            else { printf("ERROR: --failsafe-timeout must be 1..300 seconds\n"); return 1; }
            continue;
        }

        if (argv[i][0] != '-')
        {
            uav_ip = argv[i];
        }
    }

    if (argc < 2)
    {
        printf("Usage: %s <uav_ip> [--auto-soak]\n", argv[0]);
        printf("               [--failsafe-action <0-3>]   0=none 1=Land 2=RTL 3=Hover\n");
        printf("               [--failsafe-timeout <secs>] seconds before failsafe fires\n");
        printf("               [--send-port <port>] [--listen-port <port>]\n");
        printf("No IP provided, defaulting to 127.0.0.1\n\n");
    }

    if (auto_soak)
    {
        printf("[AUTO] Soak command mode enabled in GCS\n");
    }

    // Load Identity Keys
    FILE *f_gcs_seed = fopen("keys/gcs_id_seed.bin", "rb");
    if (!f_gcs_seed || fread(gcs_id_seed, 1, 32, f_gcs_seed) != 32)
    {
        printf("ERROR: Could not load gcs_id_seed.bin (generate with keygen.py)\n");
        return 1;
    }
    if (f_gcs_seed)
        fclose(f_gcs_seed);

    FILE *f_uav_pub = fopen("keys/uav_pub.bin", "rb");
    if (!f_uav_pub || fread(uav_id_public, 1, 32, f_uav_pub) != 32)
    {
        printf("ERROR: Could not load uav_pub.bin (generate with id_gen.exe)\n");
        return 1;
    }
    if (f_uav_pub)
        fclose(f_uav_pub);

    crypto_eddsa_key_pair(gcs_id_secret, gcs_id_public, gcs_id_seed);
    printf("Identity loaded: EdDSA Keys loaded successfully\n");

    // Initialize systems
    ks_mempool_t pool;
    ks_mempool_init(&pool);

    /* Session will be initialised after ECDH completes.
       The NVM nonce counter will be applied to it at that point. */
    memset(&g_session, 0, sizeof(g_session));

    /* JARUS SORA OSO#06: Initialise security event log at process start */
    ks_sora_init(&g_sora_ctx);

    ks_crypto_ctx_t crypto_ctx;
    ks_crypto_ctx_init(&crypto_ctx);

    printf("Crypto Backend: Software\n");
    printf("Memory Pool: %d buffers x %d bytes = %d KB\n\n",
           KS_MEMPOOL_NUM_BUFFERS, KS_MEMPOOL_BUFFER_SIZE,
           (KS_MEMPOOL_NUM_BUFFERS * KS_MEMPOOL_BUFFER_SIZE) / 1024);
    printf("JARUS SORA OSO#06: Security event logging active.\n");

// Setup Winsock
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    // Socket for receiving telemetry + ACKs (port 14550)
    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recv_sock < 0)
    {
        printf("ERROR: Failed to create receive socket\n");
        return 1;
    }

    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(listen_port);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0)
    {
        printf("ERROR: Failed to bind to port %u\n", listen_port);
        return 1;
    }

    // Set receive socket non-blocking
#ifdef _WIN32
    u_long iMode = 1;
    ioctlsocket(recv_sock, FIONBIO, &iMode);
#else
    int flags = fcntl(recv_sock, F_GETFL, 0);
    fcntl(recv_sock, F_SETFL, flags | O_NONBLOCK);
#endif

    // Socket for sending commands (port 14553 for direct UAV connection)
    int cmd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (cmd_sock < 0)
    {
        printf("ERROR: Failed to create command socket\n");
        return 1;
    }

    struct sockaddr_in uav_cmd_addr;
    memset(&uav_cmd_addr, 0, sizeof(uav_cmd_addr));
    uav_cmd_addr.sin_family = AF_INET;
    uav_cmd_addr.sin_port = htons(send_port);
    uav_cmd_addr.sin_addr.s_addr = inet_addr(uav_ip);

    printf("Listening on UDP port %u (telemetry + ACKs)\n", listen_port);
    printf("Sending commands to %s:%u (direct UAV connection)\n", uav_ip, send_port);
    print_menu();

    // Generate ECDH Keys (using OS CSRNG)
    secure_random(private_key, 32);
    crypto_x25519_public_key(public_key, private_key);
    printf("ECDH: GCS Public Key generated. Waiting for UAV connection...\n");

    // Parser
    ks_parser_zerocopy_t parser;
    memset(&parser, 0, sizeof(parser));
    ks_parser_zerocopy_init(&parser);
    parser.key_32b = g_session_ready ? g_session.key : NULL; // Will be updated when session is established

    uint32_t packets_received = 0;
    uint32_t parse_errors = 0;
    uint32_t acks_received = 0;
    uint16_t cmd_sequence = 0;
    uint16_t next_wp_seq = 0;
    uint32_t auto_next_send_ms = 0;
    size_t auto_step_index = 0;
    uint32_t auto_iteration = 0;
    bool auto_started = false;

    uint8_t recv_buf[2048];
    uint8_t parse_output[512];
    uint32_t last_telem_print = 0;
    uint32_t loop_counter = 0;
    uint32_t last_gcs_hb_send_ms = 0; /* DO-362A: GCS->UAV heartbeat tracker */

    // Main loop
    while (1)
    {
        // ECDH Handshake with Exponential Backoff and Timeout
        if (ecdh_state != KS_ECDH_ESTABLISHED)
        {
            uint32_t current_time = get_time_ms();

            // Check for timeout - restart handshake if we've been stuck
            if (ecdh_state != KS_ECDH_IDLE &&
                (current_time - ecdh_last_send_time) > ecdh_timeout_ms)
            {
                printf("\n>>> ECDH: Timeout! Restarting handshake (was in state %u) <<<\n>>> ", ecdh_state);
                fflush(stdout);
                ecdh_state = KS_ECDH_IDLE;
                ecdh_retry_count = 0;
                ecdh_seq_num++; // Increment sequence for new attempt
            }

            // Exponential backoff calculation: 100ms * 2^retry, max 2000ms
            uint32_t backoff_ms = 100 * (1 << (ecdh_retry_count < 5 ? ecdh_retry_count : 4));
            if (backoff_ms > 2000)
                backoff_ms = 2000;

            // Send KEY_EXCHANGE if not established and backoff elapsed
            if (ecdh_state != KS_ECDH_ESTABLISHED &&
                (current_time - ecdh_last_send_time) >= backoff_ms)
            {
                ks_key_exchange_t kx = {0};
                memcpy(kx.public_key, public_key, 32);
                kx.seq_num = ecdh_seq_num;

                // Create signature over BLAKE2b(x25519_pub || ed25519_pub || "Kestrel-v1.2")
                uint8_t sig_input[76];
                memcpy(sig_input, public_key, 32);
                memcpy(sig_input + 32, gcs_id_public, 32);
                memcpy(sig_input + 64, "Kestrel-v1.2", 12);
                uint8_t sig_hash[64];
                crypto_blake2b(sig_hash, 64, sig_input, 76);
                crypto_eddsa_sign(kx.signature, gcs_id_secret, sig_hash, 64);

                uint8_t payload[97];
                int payload_len = ks_serialize_key_exchange(&kx, payload);

                ks_header_t header = {0};
                header.payload_len = payload_len;
                header.priority = KS_PRIO_HIGH;
                header.stream_type = KS_STREAM_CMD;
                header.encrypted = false;
                header.sequence = cmd_sequence++;
                header.sys_id = 255;
                header.comp_id = 0;
                header.target_sys_id = 1; // UAV
                header.msg_id = KS_MSG_KEY_EXCHANGE;

                send_command_packet(cmd_sock, &uav_cmd_addr, &header, payload, &pool,
                                    g_session_ready ? &g_session : NULL, &crypto_ctx);

                // If we already have a session (from receiving UAV KEY_EXCHANGE), mark ESTABLISHED
                if (g_session_ready && ecdh_state == KS_ECDH_RECEIVED_KEY)
                {
                    // We received their key earlier, now we sent ours - ESTABLISHED
                    ecdh_state = KS_ECDH_ESTABLISHED;
                    ecdh_retry_count = 0;
                    printf("\n  >>> ECDH: Session ESTABLISHED! (sent GCS key after receiving UAV key)\n>>> ");
                    printf("[Kestrel] Sic Parvis Magna.\n>>> ");
                    fflush(stdout);
                }
                else
                {
                    ecdh_state = KS_ECDH_SENT_KEY;
                    ecdh_retry_count++;
                }
                ecdh_last_send_time = current_time;

                if (ecdh_retry_count == 1)
                {
                    printf("\n>>> ECDH: Sending KEY_EXCHANGE seq=%u <<<\n>>> ", ecdh_seq_num);
                }
                else
                {
                    printf("\n>>> ECDH: Retry #%u (backoff=%ums) seq=%u <<<\n>>> ",
                           ecdh_retry_count - 1, backoff_ms, ecdh_seq_num);
                }
                fflush(stdout);
            }
        }
        loop_counter++;

        // --- Internal soak automation (commands generated directly by GCS) ---
        if (auto_soak && ecdh_state == KS_ECDH_ESTABLISHED)
        {
            uint32_t now_ms = get_time_ms();

            if (!auto_started)
            {
                auto_next_send_ms = now_ms + 5000; // give link time after handshake
                auto_started = true;
                printf("\n[AUTO] Starting soak command cycle in 5s...\n>>> ");
                fflush(stdout);
            }

            if (now_ms >= auto_next_send_ms)
            {
                const auto_step_t *step = &soak_steps[auto_step_index];
                auto_iteration++;
                printf("\n[AUTO] Step %u: %s\n", (unsigned int)auto_iteration, step->name);
                run_auto_step(cmd_sock, &uav_cmd_addr, step, &pool, &g_session, &crypto_ctx, &cmd_sequence);
                printf(">>> ");
                fflush(stdout);

                auto_next_send_ms = now_ms + step->wait_ms;
                auto_step_index = (auto_step_index + 1) % (sizeof(soak_steps) / sizeof(soak_steps[0]));
            }
        }

        // --- Check for keyboard input (non-blocking) ---
        if (key_available())
        {
            int key = get_key();
            if (ecdh_state != KS_ECDH_ESTABLISHED && key != '0')
            {
                printf("\n[ERROR] ECDH Session not established yet! Command ignored.\n>>> ");
                fflush(stdout);
                goto skip_input;
            }
            switch (key)
            {
            case '1':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, KS_CMD_ARM, 0,
                         &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            case '2':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, KS_CMD_DISARM, 0,
                         &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            case '3':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, KS_CMD_TAKEOFF, 1000, // 10m
                         &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            case '4':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, KS_CMD_LAND, 0,
                         &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            case '5':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, KS_CMD_RTL, 0,
                         &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            case '6':
                printf("\n");
                send_cmd(cmd_sock, &uav_cmd_addr, KS_CMD_EMERGENCY, 0,
                         &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            case '7':
            {
                printf("\nModes: 0=MANUAL 1=STABILIZE 2=ALT_HOLD 3=LOITER 4=AUTO 5=RTL 6=LAND\n");
                printf("Enter mode number: ");
                fflush(stdout);
                int mode_key = get_key();
                if (mode_key >= '0' && mode_key <= '6')
                {
                    printf("%c\n", mode_key);
                    send_mode_change(cmd_sock, &uav_cmd_addr, mode_key - '0',
                                     &pool, &g_session, &crypto_ctx, &cmd_sequence);
                }
                else
                {
                    printf("\nInvalid mode\n");
                }
                break;
            }
            case '8':
            {
                printf("\n");
                send_waypoint(cmd_sock, &uav_cmd_addr, next_wp_seq++,
                              &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            }
            case '9':
            {
                printf("\n--- Uploading Fragmented Mission (5 waypoints) ---\n");
                send_mission_fragmented(cmd_sock, &uav_cmd_addr,
                                        &pool, &g_session, &crypto_ctx, &cmd_sequence);
                break;
            }
            case '0':
                print_menu();
                break;
            case 'N':
            case 'n':
            {
                /* DGCA NPNT: Send pre-generated Permission Artifact to UAV.
                 * Generate keys/test_pa.bin first with:  python scripts/npnt_test_pa.py */
                printf("\n--- Sending NPNT Permission Artifact ---\n");
                FILE *f_pa = fopen("keys/test_pa.bin", "rb");
                if (!f_pa)
                {
                    printf("[NPNT] ERROR: keys/test_pa.bin not found.\n");
                    printf("[NPNT] Run: python scripts/npnt_test_pa.py  to generate it.\n");
                    break;
                }
                uint8_t pa_raw[82];
                if (fread(pa_raw, 1, 82, f_pa) != 82)
                {
                    printf("[NPNT] ERROR: test_pa.bin is malformed (expected 82 bytes).\n");
                    fclose(f_pa);
                    break;
                }
                fclose(f_pa);

                ks_header_t pa_hdr = {0};
                pa_hdr.payload_len   = 82;
                pa_hdr.priority      = KS_PRIO_HIGH;
                pa_hdr.stream_type   = KS_STREAM_NPNT;
                pa_hdr.encrypted     = true;
                pa_hdr.sequence      = cmd_sequence++;
                pa_hdr.sys_id        = 255;
                pa_hdr.comp_id       = 0;
                pa_hdr.target_sys_id = 1;
                pa_hdr.msg_id        = KS_MSG_NPNT_PA;

                int sent = send_command_packet(cmd_sock, &uav_cmd_addr, &pa_hdr, pa_raw,
                                               &pool, &g_session, &crypto_ctx);
                if (sent > 0)
                    printf("[NPNT] Permission Artifact sent (%d bytes). UAV will verify.\n", sent);
                else
                    printf("[NPNT] ERROR: Could not send PA (session not ready?).\n");
                break;
            }
            default:
                break;
            }
        skip_input:;
        }

        /* Process DO-377A Command Pipeline (if session established) */
        if (ecdh_state == KS_ECDH_ESTABLISHED)
        {
            process_sliding_window(cmd_sock, &uav_cmd_addr, &pool, &g_session, &crypto_ctx);
        }

        /* DO-362A §2.2.4 (Bug #3 fix): GCS sends its own heartbeat to the UAV
         * carrying g_failsafe_action / g_failsafe_timeout so the UAV can update
         * g_failsafe_action and g_failsafe_timeout_s at runtime. Transmitted at
         * 0.5 Hz (every 2 s) — fast enough to reach UAV well within any >3 s timeout. */
        if (ecdh_state == KS_ECDH_ESTABLISHED)
        {
            uint32_t now_hb = get_time_ms();
            if (now_hb - last_gcs_hb_send_ms >= 2000)
            {
                ks_heartbeat_t gcs_hb = {0};
                gcs_hb.system_status       = 0x04;             /* GCS Active */
                gcs_hb.system_type         = 0xFF;             /* GCS system type */
                gcs_hb.base_mode           = 0x01;
                gcs_hb.lost_link_action    = g_failsafe_action;
                gcs_hb.lost_link_timeout_s = g_failsafe_timeout;

                uint8_t hb_payload[16];
                int hb_len = ks_serialize_heartbeat(&gcs_hb, hb_payload);

                ks_header_t hb_hdr = {0};
                hb_hdr.payload_len   = hb_len;
                hb_hdr.priority      = KS_PRIO_NORMAL;
                hb_hdr.stream_type   = KS_STREAM_HEARTBEAT;
                hb_hdr.encrypted     = false; /* KS_ENCRYPT_NEVER for HEARTBEAT */
                hb_hdr.sequence      = cmd_sequence++;
                hb_hdr.sys_id        = 255;   /* GCS system ID */
                hb_hdr.comp_id       = 0;
                hb_hdr.target_sys_id = 1;     /* UAV */
                hb_hdr.msg_id        = KS_MSG_HEARTBEAT;

                send_packet_direct(cmd_sock, &uav_cmd_addr, &hb_hdr, hb_payload,
                                   &pool, NULL, &crypto_ctx);
                last_gcs_hb_send_ms = now_hb;
            }
        }

        // --- Receive telemetry + ACKs (non-blocking) ---
        struct sockaddr_in sender_addr;
        int sender_len = sizeof(sender_addr);
#ifdef _WIN32
        int recv_len = recvfrom(recv_sock, (char *)recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&sender_addr, &sender_len);
#else
        int recv_len = recvfrom(recv_sock, (char *)recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&sender_addr, (socklen_t *)&sender_len);
#endif

        if (recv_len > 0)
        {
            // Parse received packet byte by byte
            ks_parser_zerocopy_init(&parser);

            int result = 0;
            for (int i = 0; i < recv_len && result <= 0; i++)
            {
                result = ks_parse_char_zerocopy(&parser, recv_buf[i], parse_output, sizeof(parse_output));
            }
            /* SORA OSO#06 HOOK: Log security-relevant parse errors (replay, MAC fail) */
            ks_sora_on_parse_result(&g_sora_ctx, result,
                                    1 /*UAV sys_id*/, parser.out_sequence,
                                    get_time_ms());

            if (result == 1)
            {
                packets_received++;

                // Get header info
                uint16_t msg_id = parser.msg_id;
                uint16_t payload_len = parser.payload_len;
                (void)payload_len; /* referenced below in logging paths only */

                // Process message
                switch (msg_id)
                {
                case KS_MSG_KEY_EXCHANGE:
                {
                    ks_key_exchange_t rx_kx;
                    ks_deserialize_key_exchange(&rx_kx, parse_output);

                    // Ignore duplicate KEY_EXCHANGE (same seq_num we already processed)
                    if (ecdh_state == KS_ECDH_ESTABLISHED && rx_kx.seq_num == ecdh_peer_seq)
                    {
                        printf("\n  (Duplicate KEY_EXCHANGE seq=%u, already established)\n>>> ", rx_kx.seq_num);
                        fflush(stdout);
                        break;
                    }

                    // Authenticate incoming Key Exchange Request
                    // Verify BLAKE2b(x25519_pub || ed25519_pub || "Kestrel-v1.2")
                    uint8_t verify_input[76];
                    memcpy(verify_input, rx_kx.public_key, 32);
                    memcpy(verify_input + 32, uav_id_public, 32);
                    memcpy(verify_input + 64, "Kestrel-v1.2", 12);
                    uint8_t verify_hash[64];
                    crypto_blake2b(verify_hash, 64, verify_input, 76);
                    if (crypto_eddsa_check(rx_kx.signature, uav_id_public, verify_hash, 64) != 0)
                    {
                        printf("\n  >>> ECDH FATAL: EdDSA signature verification failed. MITM detected!\n>>> ");
                        printf("[Kestrel] You shall not pass... without authentication.\n");
                        /* SORA OSO#06 HOOK: Log mutual authentication failure (potential MITM) */
                        ks_sora_log(&g_sora_ctx, KS_SORA_MUTUAL_AUTH_FAIL,
                                    get_time_ms(), 255 /*GCS sys_id*/,
                                    cmd_sequence, 1 /*failure*/);
                        fflush(stdout);
                        break;
                    }

                    // Always send our KEY_EXCHANGE when we receive peer's KEY_EXCHANGE
                    // This handles crossed-in-flight KEY_EXCHANGE packets and ensures both sides get the key
                    uint8_t raw_shared[32];
                    crypto_x25519(raw_shared, private_key, rx_kx.public_key);
                    uint8_t derived_key[32];
                    crypto_blake2b(derived_key, 32, raw_shared, 32);
                    crypto_wipe(raw_shared, 32);

                    if (ks_session_init(&g_session, derived_key) != 0)
                    {
                        printf("  >>> ECDH FATAL: session init failed (CSPRNG error)\n");
                        crypto_wipe(derived_key, 32);
                        break;
                    }
                    crypto_wipe(derived_key, 32); /* Remove key from stack */
                    /* SORA OSO#06 HOOK: Log session key established (key rotation event) */
                    ks_sora_log(&g_sora_ctx, KS_SORA_KEY_ROTATED,
                                get_time_ms(), 255 /*GCS sys_id*/,
                                cmd_sequence, 0 /*success*/);

                    /* Apply saved NVM counter (prevents reuse on reboot) */
                    load_nonce_counter(&g_session, "keys/gcs_nonce.dat");
                    g_session_ready = true;

                    /* Update the parser's key pointer */
                    parser.key_32b = g_session.key;

                    printf("[DEBUG] GCS session initialized securely\n");
                    printf("[TM] HANDSHAKE:RECEIVED_KEY\n");
                    fflush(stdout);

                    ecdh_peer_seq = rx_kx.seq_num;

                    printf("\n  >>> ECDH: Received UAV key (seq=%u), sending GCS key\n>>> ", rx_kx.seq_num);

                    // Send our KEY_EXCHANGE immediately
                    ks_key_exchange_t kx_reply = {0};
                    memcpy(kx_reply.public_key, public_key, 32);
                    kx_reply.seq_num = ecdh_seq_num;

                    // Sign BLAKE2b(x25519_pub || ed25519_pub || "Kestrel-v1.2")
                    uint8_t reply_sig_input[76];
                    memcpy(reply_sig_input, public_key, 32);
                    memcpy(reply_sig_input + 32, gcs_id_public, 32);
                    memcpy(reply_sig_input + 64, "Kestrel-v1.2", 12);
                    uint8_t reply_sig_hash[64];
                    crypto_blake2b(reply_sig_hash, 64, reply_sig_input, 76);
                    crypto_eddsa_sign(kx_reply.signature, gcs_id_secret, reply_sig_hash, 64);

                    uint8_t kx_payload[97];
                    int kx_payload_len = ks_serialize_key_exchange(&kx_reply, kx_payload);

                    ks_header_t kx_hdr = {0};
                    kx_hdr.payload_len = kx_payload_len;
                    kx_hdr.priority = KS_PRIO_HIGH;
                    kx_hdr.stream_type = KS_STREAM_CMD;
                    kx_hdr.encrypted = false;
                    kx_hdr.sequence = cmd_sequence++;
                    kx_hdr.sys_id = 255;
                    kx_hdr.comp_id = 0;
                    kx_hdr.target_sys_id = 1;
                    kx_hdr.msg_id = KS_MSG_KEY_EXCHANGE;

                    uint8_t *kx_buf = NULL;
                    int kx_pkt_len = ks_pack_fast(&pool, &kx_hdr, kx_payload,
                                                  g_session_ready ? &g_session : NULL, &crypto_ctx, &kx_buf);
                    if (kx_pkt_len > 0 && kx_buf)
                    {
                        sendto(cmd_sock, (char *)kx_buf, kx_pkt_len, 0,
                               (struct sockaddr *)&uav_cmd_addr, sizeof(uav_cmd_addr));
                        ks_mempool_free(&pool, kx_buf);
                    }

                    // Mark ESTABLISHED immediately - we have both keys now
                    ecdh_state = KS_ECDH_ESTABLISHED;
                    ecdh_retry_count = 0;
                    /* SORA OSO#06 HOOK: Log mutual authentication success */
                    ks_sora_log(&g_sora_ctx, KS_SORA_MUTUAL_AUTH_OK,
                                get_time_ms(), 255 /*GCS sys_id*/,
                                cmd_sequence, 0 /*success*/);

                    printf("  >>> ECDH: Session ESTABLISHED! (received UAV key, sent GCS key)\n>>> ");
                    printf("[TM] HANDSHAKE:ESTABLISHED\n");
                    printf("[TM] SESSION_KEY:%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
                           g_session.key[0],  g_session.key[1],  g_session.key[2],  g_session.key[3],
                           g_session.key[4],  g_session.key[5],  g_session.key[6],  g_session.key[7],
                           g_session.key[8],  g_session.key[9],  g_session.key[10], g_session.key[11],
                           g_session.key[12], g_session.key[13], g_session.key[14], g_session.key[15],
                           g_session.key[16], g_session.key[17], g_session.key[18], g_session.key[19],
                           g_session.key[20], g_session.key[21], g_session.key[22], g_session.key[23],
                           g_session.key[24], g_session.key[25], g_session.key[26], g_session.key[27],
                           g_session.key[28], g_session.key[29], g_session.key[30], g_session.key[31]);
                    printf("[Kestrel] Sic Parvis Magna.\n>>> ");
                    fflush(stdout);

                    // Always send ACK when we receive KEY_EXCHANGE
                    ks_key_exchange_ack_t kx_ack = {0};
                    kx_ack.seq_num = rx_kx.seq_num;
                    kx_ack.status = 0; // OK

                    uint8_t ack_payload[2];
                    int ack_len = ks_serialize_key_exchange_ack(&kx_ack, ack_payload);

                    ks_header_t ack_hdr = {0};
                    ack_hdr.payload_len = ack_len;
                    ack_hdr.priority = KS_PRIO_HIGH;
                    ack_hdr.stream_type = KS_STREAM_CMD_ACK;
                    ack_hdr.encrypted = false;
                    ack_hdr.sequence = cmd_sequence++;
                    ack_hdr.sys_id = 255;
                    ack_hdr.comp_id = 0;
                    ack_hdr.target_sys_id = 1;
                    ack_hdr.msg_id = KS_MSG_KEY_EXCHANGE_ACK;

                    uint8_t *ack_buf = NULL;
                    int ack_pkt_len = ks_pack_fast(&pool, &ack_hdr, ack_payload,
                                                   g_session_ready ? &g_session : NULL, &crypto_ctx, &ack_buf);
                    if (ack_pkt_len > 0 && ack_buf)
                    {
                        sendto(cmd_sock, (char *)ack_buf, ack_pkt_len, 0,
                               (struct sockaddr *)&uav_cmd_addr, sizeof(uav_cmd_addr));
                        ks_mempool_free(&pool, ack_buf);
                    }
                    break;
                }
                case KS_MSG_KEY_EXCHANGE_ACK:
                {
                    ks_key_exchange_ack_t rx_ack;
                    ks_deserialize_key_exchange_ack(&rx_ack, parse_output);

                    // Check if this ACK is for our current handshake
                    // Mark as ESTABLISHED if we have session_key computed
                    if (rx_ack.seq_num == ecdh_seq_num && ecdh_state >= KS_ECDH_SENT_KEY && ecdh_state != KS_ECDH_ESTABLISHED)
                    {
                        if (g_session_ready)
                        {
                            // Session already established
                            ecdh_state = KS_ECDH_ESTABLISHED;
                            ecdh_retry_count = 0;
                            printf("\n  >>> ECDH: Received ACK for seq=%u, session ESTABLISHED!\n>>> ", ecdh_seq_num);
                            printf("[Kestrel] Sic Parvis Magna.\n>>> ");
                            fflush(stdout);
                        }
                        else
                        {
                            printf("\n  >>> ECDH: Received ACK for seq=%u (waiting for UAV KEY_EXCHANGE)\n>>> ", ecdh_seq_num);
                            fflush(stdout);
                        }
                    }
                    else if (rx_ack.seq_num == ecdh_seq_num && ecdh_state == KS_ECDH_ESTABLISHED)
                    {
                        printf("\n  (ACK for seq=%u received, session already established)\n>>> ", ecdh_seq_num);
                        fflush(stdout);
                    }
                    break;
                }
                case KS_MSG_HEARTBEAT:
                {
                    ks_heartbeat_t hb;
                    ks_deserialize_heartbeat(&hb, parse_output);
                    bool armed = (hb.base_mode & 0x80) != 0;
                    uint8_t mode = (hb.base_mode >> 2) & 0x07;

                    // Print heartbeat only every 5 seconds (not every 1s)
                    // MODIFIED FOR TESTING: Print more frequently to see errors
                    if (packets_received - last_telem_print >= 10 || packets_received <= 50)
                    {
                        printf("[HB] %s | %s | Status:0x%X | Pkts:%u ACKs:%u Errors:%u\n",
                               armed ? "ARMED" : "DISARMED",
                               get_mode_name(mode),
                               hb.system_status,
                               packets_received, acks_received, parse_errors);
                        printf("[TM] HEARTBEAT: ARMED=%d MODE=%d STAT=0x%X PKTS=%u ERR=%u\n",
                               armed, mode, hb.system_status, packets_received, parse_errors);
                        last_telem_print = packets_received;
                        fflush(stdout);

                        // Periodically save the nonce to NVM to keep the jump safe
                        save_nonce_state(&g_session, "gcs_nonce.dat");
                    }
                    break;
                }
                case KS_MSG_RC_INPUT:
                {
                    ks_rc_input_t rc;
                    ks_deserialize_rc_input(&rc, parse_output);

                    // Periodically print the Link Quality back to the operator
                    if (packets_received % 50 == 0)
                    {
                        printf("[RC] Link Quality: %u%% | RSSI: %u\n", rc.quality, rc.rssi);
                    }
                    break;
                }
                case KS_MSG_GPS_RAW:
                {
                    // Silently receive
                    break;
                }
                case KS_MSG_BATTERY:
                {
                    ks_battery_t bat;
                    ks_deserialize_battery(&bat, parse_output);
                    printf("[BAT] %.1fV  %.1fA  %d%%\n",
                           bat.voltage / 1000.0, bat.current / -100.0, bat.remaining);
                    printf("[TM] BATTERY: VOLT=%d CURR=%d REM=%d\n",
                           bat.voltage, bat.current, bat.remaining);
                    break;
                }
                case KS_MSG_CMD_ACK:
                {
                    acks_received++;
                    ks_command_ack_t ack;
                    ks_deserialize_command_ack(&ack, parse_output);
                    
                    /* The UAV currently doesn't echo the sequence number in the raw ACK payload,
                     * but Kestrel uses the header sequence for ACKs in advanced extensions. 
                     * For now, we clear the first matching command_id from the window 
                     * since the protocol's basic ACK lacks sequence reflection. */
                    for (int i = 0; i < DO_377A_MAX_WINDOW_SIZE; i++)
                    {
                        if (g_cmd_window[i].active && g_cmd_window[i].msg_id == KS_MSG_CMD && g_cmd_window[i].cmd_id == ack.command_id)
                        {
                            acknowledge_command(g_cmd_window[i].sequence);
                            break;
                        }
                    }

                    printf("[ACK] Cmd=0x%04X Result=%s",
                           ack.command_id, get_ack_result(ack.result));
                    if (ack.result == KS_ACK_IN_PROGRESS)
                        printf(" Progress=%u%%", ack.progress);
                    printf("\n>>> ");
                    fflush(stdout);
                    break;
                }
                case KS_MSG_VIDEO_TS:
                {
                    // STANAG 4609 MPEG-TS packet
                    FILE *v_out = fopen("video_out.ts", "ab");
                    if (v_out) {
                        fwrite(parse_output, 1, payload_len, v_out);
                        fclose(v_out);
                    }
                    printf("[STANAG 4609] MPEG-TS Video block received (%u bytes)\n", payload_len);
                    break;
                }
                default:
                    // Other telemetry silently received
                    break;
                }
            }
            else if (result < 0)
            {
                parse_errors++;
            }
        }

// Small sleep to avoid busy-waiting
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

// Cleanup
#ifdef _WIN32
    closesocket(recv_sock);
    closesocket(cmd_sock);
    WSACleanup();
#else
    close(recv_sock);
    close(cmd_sock);
#endif

    // Final save on clean exit
    save_nonce_state(&g_session, "gcs_nonce.dat");

    /* JARUS SORA OSO#06: Print audit log on clean shutdown */
    ks_sora_dump(&g_sora_ctx);

    return 0;
}
