/*
 * UAVLink Phase 2 UAV Simulator - Network Test
 * 
 * Uses Phase 2 optimizations:
 * - Memory pool allocation (O(1) deterministic)
 * - Selective encryption (60% bandwidth reduction)
 * - Crypto context caching (30% speedup)
 */

#include "uavlink.h"
#include "uavlink_phase2.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    #define sleep(x) Sleep((x)*1000)
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

// Pre-shared encryption key (32 bytes for ChaCha20)
static const uint8_t SHARED_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

// Simulation state
typedef struct {
    float roll, pitch, yaw;
    float roll_rate, pitch_rate, yaw_rate;
    int32_t lat, lon, alt;
    uint16_t voltage;
    int16_t current;
    uint16_t sequence;
} sim_state_t;

int main(void) {
    printf("=== UAVLink Phase 2 UAV Simulator (Network) ===\n\n");
    
    // Initialize memory pool
    ul_mempool_t pool;
    ul_mempool_init(&pool);
    printf("Memory pool initialized: %d buffers x %d bytes\n",
           UL_MEMPOOL_NUM_BUFFERS, UL_MEMPOOL_BUFFER_SIZE);
    
    // Initialize nonce state and crypto context
    ul_nonce_state_t nonce_state;
    ul_nonce_init(&nonce_state);
    
    ul_crypto_ctx_t crypto_ctx;
    ul_crypto_ctx_init(&crypto_ctx);
    
    printf("Crypto context initialized with key caching\n");
    
    // Detect crypto capabilities
    const ul_crypto_caps_t *caps = ul_crypto_get_caps();
    printf("Crypto backend: ");
    switch(caps->backend) {
        case UL_CRYPTO_SOFTWARE: printf("Software\n"); break;
        case UL_CRYPTO_ARM_NEON: printf("ARM NEON (%ux)\n", caps->speedup_factor); break;
        case UL_CRYPTO_X86_AVX2: printf("x86 AVX2 (%ux)\n", caps->speedup_factor); break;
        default: printf("Unknown\n");
    }
    printf("\n");
    
    // Setup UDP socket
    #ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            printf("ERROR: WSAStartup failed\n");
            return 1;
        }
    #endif
    
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printf("ERROR: Failed to create socket\n");
        return 1;
    }
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(14550);
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  // localhost
    
    printf("Sending to 127.0.0.1:14550\n");
    printf("Starting transmission...\n\n");
    
    // Initialize simulation state
    sim_state_t state = {0};
    state.lat = 47670000;  // Seattle area
    state.lon = -122320000;
    state.alt = 100000;  // 100m
    state.voltage = 12600;  // 12.6V
    state.current = -1500;  // -15A (discharging)
    state.sequence = 0;
    
    uint32_t packets_sent = 0;
    uint32_t bytes_sent = 0;
    uint32_t fast_pack_calls = 0;
    
    // Send loop
    for (int loop = 0; loop < 200; loop++) {
        // Update simulation state
        float t = loop * 0.1f;
        state.roll = sinf(t * 0.5f) * 15.0f;
        state.pitch = sinf(t * 0.3f) * 10.0f;
        state.yaw += 0.5f;
        if (state.yaw > 180.0f) state.yaw -= 360.0f;
        
        state.roll_rate = cosf(t * 0.5f) * 7.5f;
        state.pitch_rate = cosf(t * 0.3f) * 3.0f;
        state.yaw_rate = 0.5f;
        
        state.alt += 50;  // Climbing
        state.voltage -= 1;  // Battery draining
        
        // --- Message 1: Heartbeat (10 Hz) ---
        if (loop % 10 == 0) {
            ul_heartbeat_t hb = {0};
            hb.system_status = 0x01;
            hb.system_type = 0x02;
            hb.base_mode = 0x85;
            
            uint8_t payload[32];
            int payload_len = ul_serialize_heartbeat(&hb, payload);
            
            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_NORMAL;
            header.stream_type = UL_STREAM_HEARTBEAT;
            header.encrypted = true;  // Selective encryption will decide
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_HEARTBEAT;
            
            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, SHARED_KEY,
                                         &nonce_state, &crypto_ctx, &packet_buf);
            
            if (packet_len > 0 && packet_buf) {
                sendto(sock, (char*)packet_buf, packet_len, 0,
                      (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                ul_mempool_free(&pool, packet_buf);
                packets_sent++;
                bytes_sent += packet_len;
                fast_pack_calls++;
            }
        }
        
        // --- Message 2: Attitude (50 Hz) ---
        {
            ul_attitude_t att = {0};
            att.roll = state.roll;
            att.pitch = state.pitch;
            att.yaw = state.yaw;
            att.rollspeed = state.roll_rate;
            att.pitchspeed = state.pitch_rate;
            att.yawspeed = state.yaw_rate;
            
            uint8_t payload[32];
            int payload_len = ul_serialize_attitude(&att, payload);
            
            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_HIGH;
            header.stream_type = UL_STREAM_TELEM_FAST;
            header.encrypted = true;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_ATTITUDE;
            
            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, SHARED_KEY,
                                         &nonce_state, &crypto_ctx, &packet_buf);
            
            if (packet_len > 0 && packet_buf) {
                sendto(sock, (char*)packet_buf, packet_len, 0,
                      (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                ul_mempool_free(&pool, packet_buf);
                packets_sent++;
                bytes_sent += packet_len;
                fast_pack_calls++;
            }
        }
        
        // --- Message 3: GPS (5 Hz) ---
        if (loop % 20 == 0) {
            ul_gps_raw_t gps = {0};
            gps.lat = state.lat;
            gps.lon = state.lon;
            gps.alt = state.alt;
            gps.eph = 150;
            gps.epv = 200;
            gps.vel = 500;
            gps.cog = 4500;
            gps.fix_type = 3;
            gps.satellites = 12;
            
            uint8_t payload[32];
            int payload_len = ul_serialize_gps_raw(&gps, payload);
            
            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_NORMAL;
            header.stream_type = UL_STREAM_TELEM_SLOW;
            header.encrypted = true;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_GPS_RAW;
            
            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, SHARED_KEY,
                                         &nonce_state, &crypto_ctx, &packet_buf);
            
            if (packet_len > 0 && packet_buf) {
                sendto(sock, (char*)packet_buf, packet_len, 0,
                      (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                ul_mempool_free(&pool, packet_buf);
                packets_sent++;
                bytes_sent += packet_len;
                fast_pack_calls++;
            }
        }
        
        // --- Message 4: Battery (2 Hz) ---
        if (loop % 50 == 0) {
            ul_battery_t bat = {0};
            bat.voltage = state.voltage;
            bat.current = state.current;
            bat.remaining = 75;
            bat.cell_count = 3;
            bat.status = 0x01;
            
            uint8_t payload[32];
            int payload_len = ul_serialize_battery(&bat, payload);
            
            ul_header_t header = {0};
            header.payload_len = payload_len;
            header.priority = UL_PRIO_NORMAL;
            header.stream_type = UL_STREAM_TELEM_SLOW;
            header.encrypted = true;
            header.sequence = state.sequence++;
            header.sys_id = 1;
            header.comp_id = 1;
            header.msg_id = UL_MSG_BATTERY;
            
            uint8_t *packet_buf = NULL;
            int packet_len = ul_pack_fast(&pool, &header, payload, SHARED_KEY,
                                         &nonce_state, &crypto_ctx, &packet_buf);
            
            if (packet_len > 0 && packet_buf) {
                sendto(sock, (char*)packet_buf, packet_len, 0,
                      (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                ul_mempool_free(&pool, packet_buf);
                packets_sent++;
                bytes_sent += packet_len;
                fast_pack_calls++;
            }
        }
        
        // Print progress
        if (loop % 50 == 0) {
            printf("Loop %d: %u packets sent, %u bytes, %.2f KB/s\n",
                   loop, packets_sent, bytes_sent,
                   bytes_sent / (loop * 0.1f * 1024.0f));
        }
        
        // Sleep 100ms (10 Hz loop)
        #ifdef _WIN32
            Sleep(100);
        #else
            usleep(100000);
        #endif
    }
    
    printf("\n=== Transmission Complete ===\n");
    printf("Packets sent: %u\n", packets_sent);
    printf("Bytes sent: %u\n", bytes_sent);
    printf("Fast pack calls: %u\n", fast_pack_calls);
    printf("Average packet size: %u bytes\n", packets_sent > 0 ? bytes_sent / packets_sent : 0);
    
    // Memory pool statistics
    uint32_t alloc_count, free_count, peak_usage, current_usage;
    ul_mempool_stats(&pool, &alloc_count, &free_count, &peak_usage, &current_usage);
    printf("\nMemory Pool Statistics:\n");
    printf("  Allocations: %u\n", alloc_count);
    printf("  Frees: %u\n", free_count);
    printf("  Peak usage: %u/%u buffers (%.1f%%)\n",
           peak_usage, UL_MEMPOOL_NUM_BUFFERS,
           100.0f * peak_usage / UL_MEMPOOL_NUM_BUFFERS);
    printf("  Current usage: %u buffers\n", current_usage);
    printf("  Memory leaks: %s\n", (alloc_count == free_count) ? "None" : "WARNING!");
    
    // Cleanup
    #ifdef _WIN32
        closesocket(sock);
        WSACleanup();
    #else
        close(sock);
    #endif
    
    return 0;
}
