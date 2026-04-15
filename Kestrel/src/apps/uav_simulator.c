/*
 * Kestrel Bidirectional UAV Simulator
 *
 * Sends telemetry on UDP port 14552 (UAV -> GCS)
 * Receives commands on UDP port 14553 (GCS -> UAV)
 * Sends command ACKs on UDP port 14552 (UAV -> GCS)
 */

#include "kestrel_video.h"
#include "kestrel.h"
#include "kestrel_fast.h"
#include "kestrel_rid.h"
#include "kestrel_sora.h"   /* JARUS SORA OSO#06 compliance shim */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#define sleep(x) Sleep((x) * 1000)
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include "monocypher.h"

#define BLUE "\033[0;34m"
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define RESET "\033[0m"

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

/* JARUS SORA OSO#06: Security event log — global to UAV process lifetime */
static ks_sora_ctx_t g_sora_ctx;
static uint8_t private_key[32] = {0};
static uint8_t public_key[32]  = {0};

// Identity Key State
static uint8_t uav_id_seed[32] = {0};
static uint8_t uav_id_secret[64] = {0};
static uint8_t uav_id_public[32] = {0};
static uint8_t gcs_id_public[32] = {0};

static ks_ecdh_state_t ecdh_state = KS_ECDH_IDLE;
static uint8_t ecdh_seq_num = 1;         // Our handshake sequence number
static uint8_t ecdh_peer_seq = 0;        // Peer's sequence number
static uint32_t ecdh_retry_count = 0;    // Number of retries
static uint32_t ecdh_last_send_time = 0; // For exponential backoff
static uint32_t ecdh_timeout_ms = 5000;  /* One hour on this planet = 7 years of waiting — Interstellar */

/* DO-362A: Configurable lost-link failsafe (set by GCS via heartbeat).
 * Defaults: RTL after 3 seconds — identical to prior hard-coded behaviour. */
static uint8_t  g_failsafe_action      = 2;   /* 0=none 1=Land 2=RTL 3=Hover */
static uint16_t g_failsafe_timeout_s   = 3;   /* seconds of silence */

/* DGCA NPNT arming gate state.
 * If g_npnt_enabled is false (DGCA key file absent) NPNT is gracefully disabled
 * and arming proceeds without a PA check — non-India deployments are unaffected. */
static bool     g_npnt_enabled       = false; /* true once DGCA pub key loaded  */
static bool     g_npnt_validated     = false; /* true once a valid PA verified  */
static uint32_t g_npnt_valid_until   = 0;     /* PA expiry (Unix UTC)           */
static uint8_t  g_dgca_pub[32]       = {0};   /* Pre-shared DGCA Ed25519 pubkey */
static ks_npnt_pa_t g_npnt_pa        = {0};   /* Last received PA (for logging) */

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

// --- Nonce Persistence (NVM) Helpers ---
// These helpers persist the nonce counter so that if the UAV loses power before
// saving, the counter restarts 10000 ahead — preventing reuse on reboot.
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

// UAV State
typedef struct
{
    // Attitude
    float roll, pitch, yaw;
    float roll_rate, pitch_rate, yaw_rate;

    // Position
    int32_t lat, lon, alt;

    // Battery
    uint16_t voltage;
    int16_t current;

    // Status
    bool armed;
    uint8_t flight_mode;
    uint16_t sequence;

    // Mission
    ks_mission_item_t mission[16];
    uint8_t mission_count;
} uav_state_t;

// Process a received command and return ACK
static ks_command_ack_t process_command(uav_state_t *state, const ks_command_t *cmd)
{
    ks_command_ack_t ack = {0};
    ack.command_id = cmd->command_id;

    switch (cmd->command_id)
    {
    case KS_CMD_ARM:
        /* DGCA NPNT gate: if NPNT is enabled, PA must be validated first */
        if (g_npnt_enabled && !g_npnt_validated)
        {
            ack.result = KS_ACK_REJECTED;
            printf("  >>> NPNT GATE: ARM rejected — no valid Permission Artifact!\n");
            printf("  >>> Push KS_MSG_NPNT_PA from GCS before arming.\n");
            return ack;
        }
        if (!state->armed)
        {
            state->armed = true;
            ack.result = KS_ACK_OK;
            printf("  >>> ARMED! Motors enabled.\n");
        }
        else
        {
            ack.result = KS_ACK_REJECTED;
            printf("  >>> ARM rejected: already armed\n");
        }
        break;

    case KS_CMD_DISARM:
        if (state->armed)
        {
            state->armed = false;
            ack.result = KS_ACK_OK;
            printf("  >>> DISARMED. Motors disabled.\n");
        }
        else
        {
            ack.result = KS_ACK_REJECTED;
            printf("  >>> DISARM rejected: already disarmed\n");
        }
        break;

    case KS_CMD_TAKEOFF:
        if (state->armed)
        {
            uint16_t target_alt_cm = cmd->param1;
            printf("  >>> TAKEOFF to %u cm\n", target_alt_cm);
            state->alt = target_alt_cm * 10; // Convert cm to mm
            ack.result = KS_ACK_OK;
        }
        else
        {
            ack.result = KS_ACK_REJECTED;
            printf("  >>> TAKEOFF rejected: not armed\n");
        }
        break;

    case KS_CMD_LAND:
        if (state->armed)
        {
            printf("  >>> LANDING initiated\n");
            state->flight_mode = KS_MODE_LAND;
            ack.result = KS_ACK_OK;
        }
        else
        {
            ack.result = KS_ACK_REJECTED;
            printf("  >>> LAND rejected: not armed\n");
        }
        break;

    case KS_CMD_RTL:
        if (state->armed)
        {
            printf("  >>> RTL initiated\n");
            state->flight_mode = KS_MODE_RTL;
            ack.result = KS_ACK_OK;
        }
        else
        {
            ack.result = KS_ACK_REJECTED;
            printf("  >>> RTL rejected: not armed\n");
        }
        break;

    case KS_CMD_EMERGENCY:
        printf("  >>> !!! EMERGENCY STOP !!!\n");
        state->armed = false;
        state->flight_mode = KS_MODE_MANUAL;
        ack.result = KS_ACK_OK;
        break;

    default:
        ack.result = KS_ACK_UNSUPPORTED;
        printf("  >>> Unknown command 0x%04X\n", cmd->command_id);
        break;
    }

    return ack;
}

// Send an ACK packet back to GCS
static void send_ack(int sock, struct sockaddr_in *dest,
                     const ks_command_ack_t *ack, uav_state_t *state,
                     ks_mempool_t *pool, ks_session_t *session,
                     ks_crypto_ctx_t *crypto_ctx)
{
    uint8_t payload[32];
    int payload_len = ks_serialize_command_ack(ack, payload);

    ks_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = KS_PRIO_HIGH;
    header.stream_type = KS_STREAM_CMD_ACK;
    header.encrypted = true;
    header.sequence = state->sequence++;
    header.sys_id = 1;
    header.comp_id = 1;
    header.target_sys_id = 255; // GCS
    header.msg_id = KS_MSG_CMD_ACK;

    uint8_t *packet_buf = NULL;
    int packet_len = ks_pack_fast(pool, &header, payload, session,
                                  crypto_ctx, &packet_buf);

    if (packet_len > 0 && packet_buf)
    {
        sendto(sock, (char *)packet_buf, packet_len, 0,
               (struct sockaddr *)dest, sizeof(*dest));
        ks_mempool_free(pool, packet_buf);
    }
}

int main(int argc, char *argv[])
{
    printf("=== Kestrel Bidirectional UAV Simulator ===\n\n");
    printf(BLUE "[Kestrel] Hello, friend." RESET "\n\n");

    // Determine GCS IP and Ports
    const char *gcs_ip = "127.0.0.1";
    uint16_t send_port = 14552;
    uint16_t listen_port = 14553;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--send-port") == 0 && i + 1 < argc)
        {
            send_port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc)
        {
            listen_port = (uint16_t)atoi(argv[++i]);
        }
        else if (argv[i][0] != '-')
        {
            gcs_ip = argv[i];
        }
    }

    if (argc < 2)
    {
        printf("Usage: %s <gcs_ip> [--send-port <port>] [--listen-port <port>]\n", argv[0]);
        printf("No IP provided, defaulting to 127.0.0.1\n\n");
    }

    // Load Identity Keys
    FILE *f_uav_seed = fopen("keys/uav_id_seed.bin", "rb");
    if (!f_uav_seed || fread(uav_id_seed, 1, 32, f_uav_seed) != 32)
    {
        printf(RED "ERROR: Could not load uav_id_seed.bin (generate with keygen.py)\n" RESET);
        return 1;
    }
    if (f_uav_seed)
        fclose(f_uav_seed);

    FILE *f_gcs_pub = fopen("keys/gcs_pub.bin", "rb");
    if (!f_gcs_pub || fread(gcs_id_public, 1, 32, f_gcs_pub) != 32)
    {
        printf(RED "ERROR: Could not load gcs_pub.bin (generate with id_gen.exe)\n" RESET);
        return 1;
    }
    if (f_gcs_pub)
        fclose(f_gcs_pub);

    crypto_eddsa_key_pair(uav_id_secret, uav_id_public, uav_id_seed);
    printf("Identity loaded: EdDSA Keys loaded successfully\n");

    /* Initialize ASTM F3411 Remote ID Module */
    ks_rid_init("KESTREL-UAV-001");
    printf("ASTM F3411: Remote ID Module Initialized.\n");

    /* DGCA NPNT (Bug #1 fix): Load DGCA authority public key at startup.
     * On success: g_npnt_enabled = true  -> ARM gate is active (India deployment).
     * On failure: g_npnt_enabled = false -> ARM gate bypassed (non-India deployment). */
    {
        FILE *f_dgca = fopen("keys/dgca_pub.bin", "rb");
        if (f_dgca)
        {
            if (fread(g_dgca_pub, 1, 32, f_dgca) == 32)
            {
                g_npnt_enabled = true;
                printf(GREEN "DGCA NPNT: Authority key loaded (32 bytes). NPNT gate ENABLED." RESET "\n");
                printf("DGCA NPNT: Push KS_MSG_NPNT_PA from GCS before sending KS_CMD_ARM.\n");
            }
            else
            {
                printf(RED "DGCA NPNT: keys/dgca_pub.bin too short — NPNT disabled." RESET "\n");
            }
            fclose(f_dgca);
        }
        else
        {
            printf("DGCA NPNT: keys/dgca_pub.bin not found — NPNT disabled (non-India deployment).\n");
        }
    }

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

    ks_ts_mux_t ts_mux;
    ks_ts_mux_init(&ts_mux);

    printf("Crypto: Software | Memory Pool: %d x %d bytes\n\n",
           KS_MEMPOOL_NUM_BUFFERS, KS_MEMPOOL_BUFFER_SIZE);
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

    // Socket for sending telemetry (UAV -> GCS on port 14550)
    int telem_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (telem_sock < 0)
    {
        printf("ERROR: Failed to create telemetry socket\n");
        return 1;
    }

    struct sockaddr_in gcs_telem_addr;
    memset(&gcs_telem_addr, 0, sizeof(gcs_telem_addr));
    gcs_telem_addr.sin_family = AF_INET;
    gcs_telem_addr.sin_port = htons(send_port);
    gcs_telem_addr.sin_addr.s_addr = inet_addr(gcs_ip);

    // Socket for receiving commands (GCS -> UAV on port 14551)
    int cmd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (cmd_sock < 0)
    {
        printf("ERROR: Failed to create command socket\n");
        return 1;
    }

    struct sockaddr_in cmd_bind_addr;
    memset(&cmd_bind_addr, 0, sizeof(cmd_bind_addr));
    cmd_bind_addr.sin_family = AF_INET;
    cmd_bind_addr.sin_port = htons(listen_port);
    cmd_bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(cmd_sock, (struct sockaddr *)&cmd_bind_addr, sizeof(cmd_bind_addr)) < 0)
    {
        printf(RED "ERROR: Failed to bind command socket to port %u\n" RESET, listen_port);
        return 1;
    }

    // Set command socket to non-blocking
#ifdef _WIN32
    u_long iMode = 1;
    ioctlsocket(cmd_sock, FIONBIO, &iMode);
#else
    int flags = fcntl(cmd_sock, F_GETFL, 0);
    fcntl(cmd_sock, F_SETFL, flags | O_NONBLOCK);
#endif

    printf("Telemetry -> %s:%u (direct GCS connection)\n", gcs_ip, send_port);
    printf("Commands  <- 0.0.0.0:%u (direct GCS connection)\n", listen_port);
    printf("Status: DISARMED | Mode: MANUAL\n");
    printf("Waiting for commands...\n\n");

    // Generate ECDH Keys (using OS CSRNG)
    secure_random(private_key, 32);
    crypto_x25519_public_key(public_key, private_key);
    printf("ECDH: UAV Public Key generated. Waiting for GCS connection...\n");

    // Initialize UAV state
    uav_state_t state = {0};
    state.lat = 47670000;
    state.lon = -122320000;
    state.alt = 0;
    state.voltage = 12600;
    state.current = -500;
    state.armed = false;
    state.flight_mode = KS_MODE_MANUAL;
    state.sequence = 0;

    // Zero-copy parser for incoming commands
    ks_parser_zerocopy_t cmd_parser;
    memset(&cmd_parser, 0, sizeof(cmd_parser));
    ks_parser_zerocopy_init(&cmd_parser);
    cmd_parser.key_32b = g_session_ready ? g_session.key : NULL; // Will be updated when session is established

    uint32_t packets_sent = 0;
    uint32_t commands_received = 0;
    uint8_t cmd_recv_buf[2048];

    // Fragment reassembly context
    ks_reassembly_ctx_t reasm_ctx;
    ks_reassembly_init(&reasm_ctx);
    uint8_t reasm_output[KS_FRAG_MAX_TOTAL];
    uint16_t reasm_output_len = 0;

    // Main loop — send telemetry + check for commands
    uint32_t last_gcs_msg_time = 0;

    for (int loop = 0;; loop++)
    {
        // --- Check for incoming commands (non-blocking) ---
        struct sockaddr_in sender_addr;
        int sender_len = sizeof(sender_addr);
#ifdef _WIN32
        int recv_len = recvfrom(cmd_sock, (char *)cmd_recv_buf, sizeof(cmd_recv_buf), 0,
                                (struct sockaddr *)&sender_addr, &sender_len);
#else
        int recv_len = recvfrom(cmd_sock, (char *)cmd_recv_buf, sizeof(cmd_recv_buf), 0,
                                (struct sockaddr *)&sender_addr, (socklen_t *)&sender_len);
#endif

        if (recv_len > 10 && cmd_recv_buf[0] == 0xA5)
        {
            // Parse the command packet
            uint8_t *parse_buf = (uint8_t *)ks_mempool_alloc(&pool);
            if (parse_buf)
            {
                ks_parser_zerocopy_init(&cmd_parser); // Reset parser

                int result = 0;
                for (int i = 0; i < recv_len && result <= 0; i++)
                {
                    result = ks_parse_char_zerocopy(&cmd_parser, cmd_recv_buf[i], parse_buf, 256);
                }
                /* SORA OSO#06 HOOK: Log security-relevant parse errors (replay, MAC fail) */
                ks_sora_on_parse_result(&g_sora_ctx, result,
                                        255 /*GCS sys_id*/, cmd_parser.out_sequence,
                                        get_time_ms());

                if (result == 1)
                {
                    commands_received++;
                    last_gcs_msg_time = loop; // Reset failsafe timer

                    // Decode header
                    ks_header_t hdr = {0};
                    hdr.msg_id = cmd_parser.msg_id;
                    hdr.payload_len = cmd_parser.payload_len;
                    hdr.encrypted = (cmd_parser.header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
                    hdr.fragmented = (cmd_parser.header_buf[3] & KS_FLAG_FRAGMENTED) != 0;

                    // Parse frag fields from extended header if fragmented
                    if (hdr.fragmented)
                    {
                        // frag_index and frag_total are after sys/comp/msg routing
                        uint8_t stream_type = ((cmd_parser.header_buf[1] & 0x3) << 2) |
                                              ((cmd_parser.header_buf[2] >> 6) & 0x3);
                        bool is_cmd_stream = (stream_type == KS_STREAM_CMD || stream_type == KS_STREAM_CMD_ACK);
                        int frag_offset = 4 + 4 + (is_cmd_stream ? 1 : 0); // base + ext routing + target
                        hdr.frag_index = cmd_parser.header_buf[frag_offset];
                        hdr.frag_total = cmd_parser.header_buf[frag_offset + 1];
                        hdr.sys_id = cmd_parser.header_buf[5] & 0x3F;
                    }

                    printf("[CMD #%u] ", commands_received);

                    switch (hdr.msg_id)
                    {
                    case KS_MSG_KEY_EXCHANGE:
                    {
                        ks_key_exchange_t rx_kx;
                        ks_deserialize_key_exchange(&rx_kx, parse_buf);

                        // Ignore duplicate KEY_EXCHANGE (same seq_num we already processed)
                        if (ecdh_state == KS_ECDH_ESTABLISHED && rx_kx.seq_num == ecdh_peer_seq)
                        {
                            printf("  (Duplicate KEY_EXCHANGE seq=%u, already established)\n", rx_kx.seq_num);
                            break;
                        }

                        // Authenticate incoming Key Exchange Request
                        // Verify BLAKE2b(x25519_pub || ed25519_pub || "Kestrel-v1.2")
                        uint8_t verify_input[76];
                        memcpy(verify_input, rx_kx.public_key, 32);
                        memcpy(verify_input + 32, gcs_id_public, 32);
                        memcpy(verify_input + 64, "Kestrel-v1.2", 12);
                        uint8_t verify_hash[64];
                        crypto_blake2b(verify_hash, 64, verify_input, 76);
                        if (crypto_eddsa_check(rx_kx.signature, gcs_id_public, verify_hash, 64) != 0)
                        {
                            printf(RED "  >>> ECDH FATAL: EdDSA signature verification failed. MITM detected!\n" RESET);
                            /* SORA OSO#06 HOOK: Log mutual authentication failure (potential MITM) */
                            ks_sora_log(&g_sora_ctx, KS_SORA_MUTUAL_AUTH_FAIL,
                                        get_time_ms(), 1 /*UAV sys_id*/,
                                        state.sequence, 1 /*failure*/);
                            break;
                        }

                        // Always send our KEY_EXCHANGE when we receive peer's KEY_EXCHANGE
                        // This handles crossed-in-flight KEY_EXCHANGE packets and ensures both sides get the key
                        uint8_t raw_shared[32];
                        crypto_x25519(raw_shared, private_key, rx_kx.public_key);

                        /* Derive the session key then immediately initialise the
                           session object — key and nonce are now inseparable. */
                        uint8_t derived_key[32];
                        crypto_blake2b(derived_key, 32, raw_shared, 32);
                        crypto_wipe(raw_shared, 32);

                        if (ks_session_init(&g_session, derived_key) != 0)
                        {
                            printf(RED "  >>> ECDH FATAL: session init failed (CSPRNG error)\n" RESET);
                            crypto_wipe(derived_key, 32);
                            break;
                        }
                        crypto_wipe(derived_key, 32); /* Remove key from stack */
                        /* SORA OSO#06 HOOK: Log session key established (key rotation event) */
                        ks_sora_log(&g_sora_ctx, KS_SORA_KEY_ROTATED,
                                    get_time_ms(), 1 /*UAV sys_id*/,
                                    state.sequence, 0 /*success*/);

                        /* Apply saved NVM counter (prevents reuse on reboot) */
                        load_nonce_counter(&g_session, "keys/uav_nonce.dat");
                        g_session_ready = true;

                        /* Update the parser's key pointer */
                        cmd_parser.key_32b = g_session.key;

                        ecdh_peer_seq = rx_kx.seq_num;

                        printf("  >>> ECDH: Received GCS key (seq=%u), sending UAV key\n", rx_kx.seq_num);

                        // Send our KEY_EXCHANGE immediately
                        ks_key_exchange_t kx_reply = {0};
                        memcpy(kx_reply.public_key, public_key, 32);
                        kx_reply.seq_num = ecdh_seq_num;

                        // Sign BLAKE2b(x25519_pub || ed25519_pub || "Kestrel-v1.2")
                        uint8_t reply_sig_input[76];
                        memcpy(reply_sig_input, public_key, 32);
                        memcpy(reply_sig_input + 32, uav_id_public, 32);
                        memcpy(reply_sig_input + 64, "Kestrel-v1.2", 12);
                        uint8_t reply_sig_hash[64];
                        crypto_blake2b(reply_sig_hash, 64, reply_sig_input, 76);
                        crypto_eddsa_sign(kx_reply.signature, uav_id_secret, reply_sig_hash, 64);

                        uint8_t kx_payload[97];
                        int kx_payload_len = ks_serialize_key_exchange(&kx_reply, kx_payload);

                        ks_header_t kx_hdr = {0};
                        kx_hdr.payload_len = kx_payload_len;
                        kx_hdr.priority = KS_PRIO_HIGH;
                        kx_hdr.stream_type = KS_STREAM_CMD;
                        kx_hdr.encrypted = false;
                        kx_hdr.sequence = state.sequence++;
                        kx_hdr.sys_id = 1;
                        kx_hdr.comp_id = 1;
                        kx_hdr.target_sys_id = 255;
                        kx_hdr.msg_id = KS_MSG_KEY_EXCHANGE;

                        uint8_t *kx_buf = NULL;
                        int kx_pkt_len = ks_pack_fast(&pool, &kx_hdr, kx_payload,
                                                      g_session_ready ? &g_session : NULL,
                                                      &crypto_ctx, &kx_buf);
                        if (kx_pkt_len > 0 && kx_buf)
                        {
                            sendto(telem_sock, (char *)kx_buf, kx_pkt_len, 0,
                                   (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                            ks_mempool_free(&pool, kx_buf);
                        }

                        // Mark ESTABLISHED immediately - we have both keys now
                        ecdh_state = KS_ECDH_ESTABLISHED;
                        ecdh_retry_count = 0;
                        ecdh_last_send_time = get_time_ms();
                        /* SORA OSO#06 HOOK: Log mutual authentication success */
                        ks_sora_log(&g_sora_ctx, KS_SORA_MUTUAL_AUTH_OK,
                                    get_time_ms(), 1 /*UAV sys_id*/,
                                    state.sequence, 0 /*success*/);

                        printf(GREEN "  >>> ECDH: Session ESTABLISHED! (received GCS key, sent UAV key)\n" RESET);
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
                        printf(BLUE "[Kestrel] Uniform, Alpha, Victor. Link is hot !!" RESET "\n");
                        fflush(stdout);

                        // Send ACK when we receive KEY_EXCHANGE
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
                        ack_hdr.sequence = state.sequence++;
                        ack_hdr.sys_id = 1;
                        ack_hdr.comp_id = 1;
                        ack_hdr.target_sys_id = 255;
                        ack_hdr.msg_id = KS_MSG_KEY_EXCHANGE_ACK;

                        uint8_t *ack_buf = NULL;
                        int ack_pkt_len = ks_pack_fast(&pool, &ack_hdr, ack_payload,
                                                       g_session_ready ? &g_session : NULL,
                                                       &crypto_ctx, &ack_buf);
                        if (ack_pkt_len > 0 && ack_buf)
                        {
                            sendto(telem_sock, (char *)ack_buf, ack_pkt_len, 0,
                                   (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                            ks_mempool_free(&pool, ack_buf);
                        }
                        break;
                    }
                    case KS_MSG_KEY_EXCHANGE_ACK:
                    {
                        ks_key_exchange_ack_t rx_ack;
                        ks_deserialize_key_exchange_ack(&rx_ack, parse_buf);

                        // Check if this ACK is for our current handshake
                        // Mark as ESTABLISHED if we have session_key computed
                        if (rx_ack.seq_num == ecdh_seq_num && ecdh_state >= KS_ECDH_SENT_KEY && ecdh_state != KS_ECDH_ESTABLISHED)
                        {
                            if (g_session_ready)
                            {
                                // Session already established
                                ecdh_state = KS_ECDH_ESTABLISHED;
                                ecdh_retry_count = 0;
                                printf("  >>> ECDH: Received ACK for seq=%u, session ESTABLISHED!\n", ecdh_seq_num);
                                printf(BLUE "[Kestrel] Uniform, Alpha, Victor. Link is hot.\n" RESET);
                                fflush(stdout);
                            }
                            else
                            {
                                printf("  >>> ECDH: Received ACK for seq=%u (waiting for GCS KEY_EXCHANGE)\n", ecdh_seq_num);
                            }
                        }
                        else if (rx_ack.seq_num == ecdh_seq_num && ecdh_state == KS_ECDH_ESTABLISHED)
                        {
                            printf("  (ACK for seq=%u received, session already established)\n", ecdh_seq_num);
                        }
                        else
                        {
                            printf("  (Ignoring ACK seq=%u, expected=%u, state=%u)\n",
                                   rx_ack.seq_num, ecdh_seq_num, ecdh_state);
                        }
                        break;
                    }
                    case KS_MSG_CMD:
                    {
                        if (ecdh_state != KS_ECDH_ESTABLISHED)
                            break;

                        ks_command_t cmd;
                        ks_deserialize_command(&cmd, parse_buf);
                        printf("Command received: 0x%04X param1=%u\n", cmd.command_id, cmd.param1);

                        ks_command_ack_t ack = process_command(&state, &cmd);
                        send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                 &pool, &g_session, &crypto_ctx);
                        break;
                    }
                    case KS_MSG_MODE_CHANGE:
                    {
                        if (ecdh_state != KS_ECDH_ESTABLISHED)
                            break;

                        ks_mode_change_t mode;
                        ks_deserialize_mode_change(&mode, parse_buf);
                        printf("Mode change -> %s (0x%02X)\n",
                               get_mode_name(mode.mode), mode.mode);

                        state.flight_mode = mode.mode;

                        ks_command_ack_t ack = {0};
                        ack.command_id = KS_MSG_MODE_CHANGE;
                        ack.result = KS_ACK_OK;
                        send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                 &pool, &g_session, &crypto_ctx);
                        printf("  >>> Mode set to %s\n", get_mode_name(state.flight_mode));
                        break;
                    }
                    case KS_MSG_MISSION_ITEM:
                    {
                        // Check if fragmented
                        if (hdr.fragmented)
                        {
                            printf("Fragment %d/%d received (%d bytes)\n",
                                   hdr.frag_index + 1, hdr.frag_total, hdr.payload_len);

                            int reasm_result = ks_reassembly_add(&reasm_ctx, &hdr,
                                                                 parse_buf, hdr.payload_len,
                                                                 reasm_output, &reasm_output_len);

                            if (reasm_result == 1)
                            {
                                // Reassembly complete! Parse the full mission
                                printf("  >>> MISSION REASSEMBLED! Total %u bytes\n", reasm_output_len);

                                uint8_t num_wps = reasm_output[0];
                                int roff = 1;
                                printf("  >>> %u waypoints received:\n", num_wps);

                                state.mission_count = 0;
                                for (uint8_t w = 0; w < num_wps && roff + 20 <= reasm_output_len; w++)
                                {
                                    ks_mission_item_t wp;
                                    ks_deserialize_mission_item(&wp, reasm_output + roff);
                                    roff += 20;

                                    if (wp.seq < 16)
                                    {
                                        state.mission[wp.seq] = wp;
                                        if (wp.seq >= state.mission_count)
                                            state.mission_count = wp.seq + 1;
                                    }

                                    printf("      WP#%u: lat=%d lon=%d alt=%dmm spd=%ucm/s",
                                           wp.seq, wp.lat, wp.lon, wp.alt, wp.speed);
                                    if (wp.loiter_time > 0)
                                        printf(" loiter=%us", wp.loiter_time);
                                    printf("\n");
                                }

                                // Send ACK for completed mission
                                ks_command_ack_t ack = {0};
                                ack.command_id = KS_MSG_MISSION_ITEM;
                                ack.result = KS_ACK_OK;
                                 send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                          &pool, &g_session, &crypto_ctx);
                                printf("  >>> Mission stored! %u waypoints total\n",
                                       state.mission_count);
                            }
                            else if (reasm_result == 0)
                            {
                                printf("  (waiting for more fragments...)\n");
                            }
                            else
                            {
                                printf(RED "  >>> Reassembly error: %d\n" RESET, reasm_result);
                            }
                        }
                        else
                        {
                            // Single (non-fragmented) waypoint
                            ks_mission_item_t item;
                            ks_deserialize_mission_item(&item, parse_buf);
                            printf("Mission WP#%u: lat=%d lon=%d alt=%dmm\n",
                                   item.seq, item.lat, item.lon, item.alt);

                            if (item.seq < 16)
                            {
                                state.mission[item.seq] = item;
                                if (item.seq >= state.mission_count)
                                    state.mission_count = item.seq + 1;
                            }

                            ks_command_ack_t ack = {0};
                            ack.command_id = KS_MSG_MISSION_ITEM;
                            ack.result = KS_ACK_OK;
                                 send_ack(telem_sock, &gcs_telem_addr, &ack, &state,
                                          &pool, &g_session, &crypto_ctx);
                            printf("  >>> Waypoint %u stored (%u total)\n",
                                   item.seq, state.mission_count);
                        }
                        break;
                    }
                    case KS_MSG_HEARTBEAT:
                    {
                        /* DO-362A §2.2.4 (Bug #2 fix): GCS heartbeat carries failsafe
                         * parameters. Update g_failsafe_action and g_failsafe_timeout_s
                         * so the UAV honours the GCS-commanded lost-link behaviour.
                         * Note: last_gcs_msg_time is already reset for ALL packets above. */
                        ks_heartbeat_t hb;
                        ks_deserialize_heartbeat(&hb, parse_buf);
                        if (hb.lost_link_timeout_s > 0)
                        {
                            g_failsafe_action    = hb.lost_link_action;
                            g_failsafe_timeout_s = hb.lost_link_timeout_s;
                            printf("[DO-362A] GCS failsafe config: action=%u timeout=%us\n",
                                   g_failsafe_action, g_failsafe_timeout_s);
                        }
                        break;
                    }
                    default:
                        printf("Unknown msg_id=0x%03X\n", hdr.msg_id);
                        break;
                    case KS_MSG_NPNT_PA:
                    {
                        /* DGCA NPNT Permission Artifact handler */
                        if (!g_npnt_enabled)
                        {
                            printf("  [NPNT] DGCA key not loaded — NPNT disabled, PA ignored.\n");
                            break;
                        }

                        ks_npnt_pa_t pa;
                        if (ks_deserialize_npnt_pa(&pa, parse_buf) != 82)
                        {
                            printf("  [NPNT] Malformed PA payload length.\n");
                            break;
                        }

                        /* Build the signed body: [valid_from|valid_until|lat|lon|radius] */
                        uint8_t body[18];
                        body[0]  = (uint8_t)(pa.valid_from);
                        body[1]  = (uint8_t)(pa.valid_from >> 8);
                        body[2]  = (uint8_t)(pa.valid_from >> 16);
                        body[3]  = (uint8_t)(pa.valid_from >> 24);
                        body[4]  = (uint8_t)(pa.valid_until);
                        body[5]  = (uint8_t)(pa.valid_until >> 8);
                        body[6]  = (uint8_t)(pa.valid_until >> 16);
                        body[7]  = (uint8_t)(pa.valid_until >> 24);
                        body[8]  = (uint8_t)(pa.center_lat);
                        body[9]  = (uint8_t)(pa.center_lat >> 8);
                        body[10] = (uint8_t)(pa.center_lat >> 16);
                        body[11] = (uint8_t)(pa.center_lat >> 24);
                        body[12] = (uint8_t)(pa.center_lon);
                        body[13] = (uint8_t)(pa.center_lon >> 8);
                        body[14] = (uint8_t)(pa.center_lon >> 16);
                        body[15] = (uint8_t)(pa.center_lon >> 24);
                        body[16] = (uint8_t)(pa.radius_m);
                        body[17] = (uint8_t)(pa.radius_m >> 8);

                        /* Hash and verify signature */
                        uint8_t h[64];
                        crypto_blake2b(h, 64, body, 18);
                        if (crypto_eddsa_check(pa.signature, g_dgca_pub, h, 64) != 0)
                        {
                            printf(RED "  [NPNT] INVALID SIGNATURE — PA rejected!\n" RESET);
                            g_npnt_validated = false;
                            break;
                        }

                        /* Check time validity */
                        uint32_t now_utc = (uint32_t)time(NULL);
                        if (now_utc < pa.valid_from || now_utc > pa.valid_until)
                        {
                            printf(RED "  [NPNT] PA EXPIRED or not yet valid.\n" RESET);
                            g_npnt_validated = false;
                            break;
                        }

                        /* Geofence check: rough distance using lat/lon deltas.
                         * 1 degree lat = ~111 km; good enough for gate checking. */
                        float dlat = (float)(state.lat - pa.center_lat) / 1e7f * 111000.0f;
                        float dlon = (float)(state.lon - pa.center_lon) / 1e7f * 111000.0f;
                        float dist_m = sqrtf(dlat * dlat + dlon * dlon);
                        if (dist_m > (float)pa.radius_m)
                        {
                            printf(RED "  [NPNT] OUTSIDE GEOFENCE (%.0fm from centre, limit %um)\n" RESET,
                                   dist_m, pa.radius_m);
                            g_npnt_validated = false;
                            break;
                        }

                        /* All checks passed */
                        g_npnt_pa        = pa;
                        g_npnt_valid_until = pa.valid_until;
                        g_npnt_validated = true;
                        printf(GREEN "  [NPNT] Permission Artifact VALIDATED. Arming gate OPEN.\n" RESET);
                        printf("  [NPNT] Valid until %u | Fence radius %um | Dist %.0fm\n",
                               pa.valid_until, pa.radius_m, dist_m);

                        /* Send NPNT_STATUS reply */
                        ks_npnt_status_t st = {0};
                        st.status      = 0; /* OK */
                        st.valid_until = pa.valid_until;
                        uint8_t st_payload[5];
                        int st_len = ks_serialize_npnt_status(&st, st_payload);
                        ks_header_t st_hdr = {0};
                        st_hdr.payload_len  = st_len;
                        st_hdr.priority     = KS_PRIO_HIGH;
                        st_hdr.stream_type  = KS_STREAM_NPNT;
                        st_hdr.encrypted    = true;
                        st_hdr.sequence     = state.sequence++;
                        st_hdr.sys_id = 1; st_hdr.comp_id = 1;
                        st_hdr.target_sys_id = 255;
                        st_hdr.msg_id = KS_MSG_NPNT_STATUS;
                        uint8_t *st_buf = NULL;
                        int st_pkt = ks_pack_fast(&pool, &st_hdr, st_payload,
                                                  &g_session, &crypto_ctx, &st_buf);
                        if (st_pkt > 0 && st_buf) {
                            sendto(telem_sock, (char *)st_buf, st_pkt, 0,
                                   (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                            ks_mempool_free(&pool, st_buf);
                        }
                        break;
                    }
                    }
                }

                ks_mempool_free(&pool, parse_buf);
            }
        }
        /* next_iter label removed — no goto references it */

        // --- Update simulation ---
        float t = loop * 0.1f;
        if (state.armed)
        {
            state.roll = sinf(t * 0.5f) * 5.0f;
            state.pitch = sinf(t * 0.3f) * 3.0f;
            state.yaw += 0.5f;
            if (state.yaw > 180.0f)
                state.yaw -= 360.0f;
            state.voltage -= 1;

            /* DO-362A configurable failsafe: honour timeout/action from GCS heartbeat */
            uint32_t silence_ticks = (uint32_t)(loop - last_gcs_msg_time);
            uint32_t timeout_ticks = (uint32_t)g_failsafe_timeout_s * 10; /* 10 ticks/s */
            if (silence_ticks > timeout_ticks &&
                state.flight_mode != KS_MODE_RTL &&
                state.flight_mode != KS_MODE_LAND)
            {
                printf("\n>>> DO-362A FAILSAFE: Link lost for %us! Action=%u <<<\n\n",
                       g_failsafe_timeout_s, g_failsafe_action);
                switch (g_failsafe_action) {
                    case 1: state.flight_mode = KS_MODE_LAND;  break;
                    case 3: /* Hover — stay in current mode but stop cmds */ break;
                    default: /* 0=none keeps flying; 2=RTL (default) */
                        state.flight_mode = KS_MODE_RTL;
                        break;
                }
            }
        }

        // --- Send telemetry ---

        // ECDH Handshake with Exponential Backoff and Timeout
        if (ecdh_state != KS_ECDH_ESTABLISHED)
        {
            uint32_t current_time = get_time_ms();

            // Check for timeout - restart handshake if we've been stuck
            if (ecdh_state != KS_ECDH_IDLE &&
                (current_time - ecdh_last_send_time) > ecdh_timeout_ms)
            {
                printf("\n>>> ECDH: Timeout! Restarting handshake (was in state %u) <<<\n", ecdh_state);
                printf("[Kestrel] A half-blood's patience has limits. Connection timed out.\n");
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
                memcpy(sig_input + 32, uav_id_public, 32);
                memcpy(sig_input + 64, "Kestrel-v1.2", 12);
                uint8_t sig_hash[64];
                crypto_blake2b(sig_hash, 64, sig_input, 76);
                crypto_eddsa_sign(kx.signature, uav_id_secret, sig_hash, 64);

                uint8_t payload[97];
                int payload_len = ks_serialize_key_exchange(&kx, payload);

                ks_header_t header = {0};
                header.payload_len = payload_len;
                header.priority = KS_PRIO_HIGH;
                header.stream_type = KS_STREAM_CMD;
                header.encrypted = false;
                header.sequence = state.sequence++;
                header.sys_id = 1;
                header.comp_id = 1;
                header.target_sys_id = 255; // GCS
                header.msg_id = KS_MSG_KEY_EXCHANGE;

                uint8_t *packet_buf = NULL;
                int packet_len = ks_pack_fast(&pool, &header, payload,
                                              g_session_ready ? &g_session : NULL,
                                              &crypto_ctx, &packet_buf);
                if (packet_len > 0 && packet_buf)
                {
                    sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                           (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                    ks_mempool_free(&pool, packet_buf);

                    ecdh_state = KS_ECDH_SENT_KEY;
                    printf("[TM] HANDSHAKE:SENT_KEY\n");
                    ecdh_last_send_time = current_time;
                    ecdh_retry_count++;

                    if (ecdh_retry_count == 1)
                        printf("\n>>> ECDH: Sending KEY_EXCHANGE seq=%u <<<\n", ecdh_seq_num);
                    else
                        printf(">>> ECDH: Retry #%u (backoff=%ums) seq=%u <<<\n",
                               ecdh_retry_count - 1, backoff_ms, ecdh_seq_num);
                }
            }
        }

        if (ecdh_state != KS_ECDH_ESTABLISHED)
            goto end_loop;

        // Heartbeat (1 Hz)
        if (loop % 10 == 0)
        {
            ks_heartbeat_t hb = {0};
            hb.system_status = state.armed ? 0x04 : 0x03; // Active vs Standby
            hb.system_type = 0x02;                        // Quadcopter
            hb.base_mode = state.armed ? 0x81 : 0x01;     // Armed flag in bit 7
            hb.base_mode |= (state.flight_mode << 2);

            uint8_t payload[32];
            int payload_len = ks_serialize_heartbeat(&hb, payload);

            ks_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = KS_PRIO_NORMAL;
            header.stream_type = KS_STREAM_HEARTBEAT;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = KS_MSG_HEARTBEAT;

            uint8_t *packet_buf = NULL;
            int packet_len = ks_pack_fast(&pool, &header, payload,
                                          g_session_ready ? &g_session : NULL,
                                          &crypto_ctx, &packet_buf);

            if (packet_len > 0 && packet_buf)
            {
                sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                       (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                ks_mempool_free(&pool, packet_buf);
                packets_sent++;
            }
        }

        // Attitude (10 Hz)
        {
            ks_attitude_t att = {0};
            att.roll = state.roll;
            att.pitch = state.pitch;
            att.yaw = state.yaw;

            uint8_t payload[32];
            int payload_len = ks_serialize_attitude(&att, payload);

            ks_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = KS_PRIO_HIGH;
            header.stream_type = KS_STREAM_TELEM_FAST;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = KS_MSG_ATTITUDE;

            uint8_t *packet_buf = NULL;
            int packet_len = ks_pack_fast(&pool, &header, payload,
                                          g_session_ready ? &g_session : NULL,
                                          &crypto_ctx, &packet_buf);

            if (packet_len > 0 && packet_buf)
            {
                sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                       (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                ks_mempool_free(&pool, packet_buf);
                packets_sent++;
            }
        }

        // GPS (2 Hz)
        if (loop % 5 == 0)
        {
            ks_gps_raw_t gps = {0};
            gps.lat = state.lat;
            gps.lon = state.lon;
            gps.alt = state.alt;
            gps.fix_type = 3;
            gps.satellites = 12;

            uint8_t payload[32];
            int payload_len = ks_serialize_gps_raw(&gps, payload);

            ks_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = KS_PRIO_NORMAL;
            header.stream_type = KS_STREAM_TELEM_SLOW;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = KS_MSG_GPS_RAW;

            uint8_t *packet_buf = NULL;
            int packet_len = ks_pack_fast(&pool, &header, payload,
                                          g_session_ready ? &g_session : NULL,
                                          &crypto_ctx, &packet_buf);

            if (packet_len > 0 && packet_buf)
            {
                sendto(telem_sock, (char *)packet_buf, packet_len, 0,
                       (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                ks_mempool_free(&pool, packet_buf);
                packets_sent++;
            }
        }

        // ASTM F3411 Remote ID (1 Hz)
        if (loop % 10 == 0)
        {
            uint8_t basic_buf[64];
            uint8_t loc_buf[64];
            int basic_len = 0, loc_len = 0;

            uint16_t speed = (uint16_t)sqrt(state.roll_rate * state.roll_rate + state.pitch_rate * state.pitch_rate); // mock speed
            uint8_t rid_status = state.armed ? 0x02 : 0x01; // 1=Ground, 2=Airborne

            if (ks_rid_generate_payloads(basic_buf, &basic_len, loc_buf, &loc_len,
                                         state.lat, state.lon, (int16_t)(state.alt / 1000), // convert mm to m
                                         speed, 0, rid_status) == 0)
            {
                /* Broadcast Basic ID */
                ks_header_t hdr_basic = {0};
                hdr_basic.payload_len = basic_len;
                hdr_basic.priority = KS_PRIO_NORMAL;
                hdr_basic.stream_type = KS_STREAM_TELEM_SLOW; /* Or custom Unencrypted stream */
                hdr_basic.encrypted = false;  /* F3411 RID is explicitly unencrypted broadcast */
                hdr_basic.sequence = state.sequence++;
                hdr_basic.sys_id = 1;
                hdr_basic.comp_id = 1;
                hdr_basic.msg_id = KS_MSG_RID_BASIC_ID;

                uint8_t *p_buf = NULL;
                int p_len = ks_pack_fast(&pool, &hdr_basic, basic_buf, NULL, &crypto_ctx, &p_buf);
                if (p_len > 0 && p_buf) {
                    sendto(telem_sock, (char *)p_buf, p_len, 0, (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                    ks_mempool_free(&pool, p_buf);
                    packets_sent++;
                }

                /* Broadcast Location */
                ks_header_t hdr_loc = {0};
                hdr_loc.payload_len = loc_len;
                hdr_loc.priority = KS_PRIO_NORMAL;
                hdr_loc.stream_type = KS_STREAM_TELEM_SLOW;
                hdr_loc.encrypted = false; /* F3411 RID must be open */
                hdr_loc.sequence = state.sequence++;
                hdr_loc.sys_id = 1;
                hdr_loc.comp_id = 1;
                hdr_loc.msg_id = KS_MSG_RID_LOCATION;

                p_buf = NULL;
                p_len = ks_pack_fast(&pool, &hdr_loc, loc_buf, NULL, &crypto_ctx, &p_buf);
                if (p_len > 0 && p_buf) {
                    sendto(telem_sock, (char *)p_buf, p_len, 0, (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                    ks_mempool_free(&pool, p_buf);
                    packets_sent++;
                }
            }
        }

        // STANAG 4609 MPEG-TS Video (1 Hz)
        if (loop % 10 == 0)
        {
            ks_klv_uav_state_t klv_state = {
                .timestamp_us = (uint64_t)time(NULL) * 1000000ULL,
                .mission_id   = "KESTREL-SORTIE-001",
                .heading_deg  = state.yaw < 0 ? state.yaw + 360.0f : state.yaw,
                .pitch_deg    = state.pitch,
                .roll_deg     = state.roll,
                .lat_e7       = state.lat,
                .lon_e7       = state.lon,
                .alt_msl_m    = state.alt / 1000.0f,
                .speed_mps    = 0.0f,
            };

            uint8_t klv_buf[256];
            int klv_len = ks_klv_build_st0601(klv_buf, sizeof(klv_buf), &klv_state);

            if (klv_len > 0)
            {
                uint8_t ts_buf[KS_TS_PACKET_SIZE * 3 + KS_MAX_PAYLOAD_SIZE]; // big enough
                int ts_len = 0;

                // Provide PAT and PMT (at 1Hz this is good practice for TS compliance)
                ts_len += ks_ts_mux_write_pat_pmt(&ts_mux, ts_buf);

                // Provide KLV metadata PES packet
                ts_len += ks_ts_mux_write_pes(&ts_mux, KS_TS_PID_KLV, 0xBD, klv_state.timestamp_us, klv_buf, klv_len, &ts_buf[ts_len], sizeof(ts_buf) - ts_len);

                // Provide dummy H.264 video frame PES packet (I-frame NAL unit mock)
                uint8_t dummy_h264[] = { 0x00, 0x00, 0x00, 0x01, 0x65, 0x11, 0x22, 0x33, 0x44 };
                ts_len += ks_ts_mux_write_pes(&ts_mux, KS_TS_PID_VIDEO, 0xE0, klv_state.timestamp_us, dummy_h264, sizeof(dummy_h264), &ts_buf[ts_len], sizeof(ts_buf) - ts_len);

                // Fragment the output into multiple kestrel payloads if larger than KS_MAX_PAYLOAD_SIZE minus header size approx
                // KS_MAX_PAYLOAD_SIZE is 512. We can send 2 TS packets (376 bytes) at once.
                int offset = 0;
                while (offset < ts_len) {
                    int chunk = ts_len - offset;
                    if (chunk > 376) chunk = 376;
                    
                    ks_header_t hdr_ts = {0};
                    hdr_ts.payload_len = chunk;
                    hdr_ts.priority = KS_PRIO_NORMAL;
                    hdr_ts.stream_type = KS_STREAM_VIDEO;
                    hdr_ts.encrypted = false; 
                    hdr_ts.sequence = state.sequence++;
                    hdr_ts.sys_id = 1;
                    hdr_ts.comp_id = 1;
                    hdr_ts.msg_id = KS_MSG_VIDEO_TS;

                    uint8_t *p_buf = NULL;
                    int p_len = ks_pack_fast(&pool, &hdr_ts, &ts_buf[offset], g_session_ready ? &g_session : NULL, &crypto_ctx, &p_buf);
                    if (p_len > 0 && p_buf) {
                        sendto(telem_sock, (char *)p_buf, p_len, 0, (struct sockaddr *)&gcs_telem_addr, sizeof(gcs_telem_addr));
                        ks_mempool_free(&pool, p_buf);
                        packets_sent++;
                    }
                    offset += chunk;
                }
            }
        }

        // Status display (every 5 seconds)
        if (loop % 50 == 0 && loop > 0)
        {
            printf("\n--- Status [%s | %s] Telem:%u Cmds:%u Batt:%.1fV ---\n\n",
                   state.armed ? "ARMED" : "DISARMED",
                   get_mode_name(state.flight_mode),
                   packets_sent, commands_received,
                   state.voltage / 1000.0f);

            // Periodically save the nonce counter to NVM
            save_nonce_state(&g_session, "keys/uav_nonce.dat");
        }

        // --- PyQt5 Telemetry Output ---
        printf("[TM] ALT:%d BAT:%d MODE:%d ARMED:%d ROLL:%.2f PITCH:%.2f YAW:%.2f\n",
               state.alt, state.voltage, state.flight_mode, state.armed, state.roll, state.pitch, state.yaw);
        fflush(stdout);

    end_loop:; // End loop label

// 100ms loop (10 Hz)
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }

// Cleanup
#ifdef _WIN32
    closesocket(telem_sock);
    closesocket(cmd_sock);
    WSACleanup();
#else
    close(telem_sock);
    close(cmd_sock);
#endif

    // Final save on clean exit
    save_nonce_state(&g_session, "uav_nonce.dat");

    /* JARUS SORA OSO#06: Print audit log on clean shutdown */
    ks_sora_dump(&g_sora_ctx);

    return 0;
}