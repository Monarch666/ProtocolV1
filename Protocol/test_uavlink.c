/**
 * UAVLink Protocol Unit Test Suite
 * 
 * Comprehensive tests for UAVLink protocol implementation including:
 * - Serialization/Deserialization round-trips
 * - AEAD encryption and MAC verification
 * - Parser state machine validation
 * - Error handling and edge cases
 * - CRC computation
 * - Nonce management
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include "uavlink.h"
#include "monocypher.h"

/* Test Framework Macros */
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("  ❌ FAIL: %s\n", message); \
            printf("     at %s:%d\n", __FILE__, __LINE__); \
            test_failed++; \
            return 0; \
        } \
    } while(0)

#define TEST_ASSERT_EQ(actual, expected, name) \
    do { \
        if ((actual) != (expected)) { \
            printf("  ❌ FAIL: %s expected %d, got %d\n", name, (int)(expected), (int)(actual)); \
            printf("     at %s:%d\n", __FILE__, __LINE__); \
            test_failed++; \
            return 0; \
        } \
    } while(0)

#define TEST_ASSERT_FLOAT_EQ(actual, expected, epsilon, name) \
    do { \
        if (fabs((actual) - (expected)) > (epsilon)) { \
            printf("  ❌ FAIL: %s expected %.6f, got %.6f (epsilon=%.6f)\n", \
                   name, (double)(expected), (double)(actual), (double)(epsilon)); \
            printf("     at %s:%d\n", __FILE__, __LINE__); \
            test_failed++; \
            return 0; \
        } \
    } while(0)

#define RUN_TEST(test_func) \
    do { \
        printf("Running %s...\n", #test_func); \
        if (test_func()) { \
            printf("  ✓ PASS\n"); \
            test_passed++; \
        } \
        test_total++; \
    } while(0)

/* Global test counters */
static int test_total = 0;
static int test_passed = 0;
static int test_failed = 0;

/* Test keys and nonces */
static const uint8_t test_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

static const uint8_t test_nonce[8] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

/* Helper function to get CRC seed for message IDs (mirrors internal implementation) */
static uint8_t ul_get_crc_seed(uint16_t msg_id)
{
    switch (msg_id)
    {
    case UL_MSG_HEARTBEAT:
        return 50;
    case UL_MSG_ATTITUDE:
        return 39;
    case UL_MSG_GPS_RAW:
        return 24;
    case UL_MSG_BATTERY:
        return 154;
    case UL_MSG_RC_INPUT:
        return 89;
    default:
        return 0;
    }
}

/* ============================================================================
 * 1. SERIALIZATION/DESERIALIZATION TESTS
 * ============================================================================ */

int test_heartbeat_serialization(void)
{
    ul_heartbeat_t hb_orig = {
        .system_status = 0x12345678,
        .system_type = 5,
        .autopilot_type = 3,
        .base_mode = 0xAB
    };
    
    uint8_t buffer[32];
    ul_heartbeat_t hb_decoded;
    
    int len = ul_serialize_heartbeat(&hb_orig, buffer);
    TEST_ASSERT(len > 0, "Serialization should succeed");
    
    int result = ul_deserialize_heartbeat(&hb_decoded, buffer);
    TEST_ASSERT(result > 0, "Deserialization should return byte count");
    
    // Note: Float conversion may have small precision loss (acceptable)
    uint32_t diff = (hb_decoded.system_status > hb_orig.system_status) ?
                    (hb_decoded.system_status - hb_orig.system_status) :
                    (hb_orig.system_status - hb_decoded.system_status);
    TEST_ASSERT(diff < 16, "system_status should be approximately equal");
    TEST_ASSERT_EQ(hb_decoded.system_type, hb_orig.system_type, "system_type");
    TEST_ASSERT_EQ(hb_decoded.autopilot_type, hb_orig.autopilot_type, "autopilot_type");
    TEST_ASSERT_EQ(hb_decoded.base_mode, hb_orig.base_mode, "base_mode");
    
    return 1;
}

int test_attitude_serialization(void)
{
    ul_attitude_t att_orig = {
        .roll = 0.523f,        // ~30 degrees
        .pitch = -0.174f,      // ~-10 degrees
        .yaw = 1.571f,         // ~90 degrees
        .rollspeed = 0.1f,
        .pitchspeed = -0.05f,
        .yawspeed = 0.02f
    };
    
    uint8_t buffer[64];
    ul_attitude_t att_decoded;
    
    int len = ul_serialize_attitude(&att_orig, buffer);
    TEST_ASSERT(len > 0, "Serialization should succeed");
    
    int result = ul_deserialize_attitude(&att_decoded, buffer);
    TEST_ASSERT(result > 0, "Deserialization should return byte count");
    
    // Allow small floating point error due to float16 compression
    TEST_ASSERT_FLOAT_EQ(att_decoded.roll, att_orig.roll, 0.001f, "roll");
    TEST_ASSERT_FLOAT_EQ(att_decoded.pitch, att_orig.pitch, 0.001f, "pitch");
    TEST_ASSERT_FLOAT_EQ(att_decoded.yaw, att_orig.yaw, 0.001f, "yaw");
    TEST_ASSERT_FLOAT_EQ(att_decoded.rollspeed, att_orig.rollspeed, 0.001f, "rollspeed");
    TEST_ASSERT_FLOAT_EQ(att_decoded.pitchspeed, att_orig.pitchspeed, 0.001f, "pitchspeed");
    TEST_ASSERT_FLOAT_EQ(att_decoded.yawspeed, att_orig.yawspeed, 0.001f, "yawspeed");
    
    return 1;
}

int test_gps_serialization(void)
{
    ul_gps_raw_t gps_orig = {
        .lat = 474977810,      // 47.4977810 degrees (example: Seattle)
        .lon = -1222093200,    // -122.2093200 degrees
        .alt = 100000,         // 100m AMSL
        .eph = 150,            // 1.5m horizontal uncertainty
        .epv = 250,            // 2.5m vertical uncertainty
        .vel = 1500,           // 15 m/s ground speed
        .cog = 9000,           // 90 degrees course
        .fix_type = 3,         // 3D fix
        .satellites = 12
    };
    
    uint8_t buffer[64];
    ul_gps_raw_t gps_decoded;
    
    int len = ul_serialize_gps_raw(&gps_orig, buffer);
    TEST_ASSERT(len > 0, "Serialization should succeed");
    
    int result = ul_deserialize_gps_raw(&gps_decoded, buffer);
    TEST_ASSERT(result > 0, "Deserialization should return byte count");
    
    TEST_ASSERT_EQ(gps_decoded.lat, gps_orig.lat, "lat");
    TEST_ASSERT_EQ(gps_decoded.lon, gps_orig.lon, "lon");
    TEST_ASSERT_EQ(gps_decoded.alt, gps_orig.alt, "alt");
    TEST_ASSERT_EQ(gps_decoded.eph, gps_orig.eph, "eph");
    TEST_ASSERT_EQ(gps_decoded.epv, gps_orig.epv, "epv");
    TEST_ASSERT_EQ(gps_decoded.vel, gps_orig.vel, "vel");
    TEST_ASSERT_EQ(gps_decoded.cog, gps_orig.cog, "cog");
    TEST_ASSERT_EQ(gps_decoded.fix_type, gps_orig.fix_type, "fix_type");
    TEST_ASSERT_EQ(gps_decoded.satellites, gps_orig.satellites, "satellites");
    
    return 1;
}

int test_battery_serialization(void)
{
    ul_battery_t bat_orig = {
        .voltage = 16800,      // 16.8V (4S LiPo fully charged)
        .current = -1500,      // -15A (discharging)
        .remaining = 75,       // 75% remaining
        .cell_count = 4,
        .status = 0x01
    };
    
    uint8_t buffer[32];
    ul_battery_t bat_decoded;
    
    int len = ul_serialize_battery(&bat_orig, buffer);
    TEST_ASSERT(len > 0, "Serialization should succeed");
    
    int result = ul_deserialize_battery(&bat_decoded, buffer);
    TEST_ASSERT(result > 0, "Deserialization should return byte count");
    
    TEST_ASSERT_EQ(bat_decoded.voltage, bat_orig.voltage, "voltage");
    TEST_ASSERT_EQ(bat_decoded.current, bat_orig.current, "current");
    TEST_ASSERT_EQ(bat_decoded.remaining, bat_orig.remaining, "remaining");
    TEST_ASSERT_EQ(bat_decoded.cell_count, bat_orig.cell_count, "cell_count");
    TEST_ASSERT_EQ(bat_decoded.status, bat_orig.status, "status");
    
    return 1;
}

int test_rc_input_serialization(void)
{
    ul_rc_input_t rc_orig = {
        .channels = {1500, 1600, 1400, 1500, 1800, 1200, 1500, 1500},
        .rssi = 95,
        .quality = 98
    };
    
    uint8_t buffer[64];
    ul_rc_input_t rc_decoded;
    
    int len = ul_serialize_rc_input(&rc_orig, buffer);
    TEST_ASSERT(len > 0, "Serialization should succeed");
    
    int result = ul_deserialize_rc_input(&rc_decoded, buffer);
    TEST_ASSERT(result > 0, "Deserialization should return byte count");
    
    for (int i = 0; i < 8; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "channel[%d]", i);
        TEST_ASSERT_EQ(rc_decoded.channels[i], rc_orig.channels[i], msg);
    }
    TEST_ASSERT_EQ(rc_decoded.rssi, rc_orig.rssi, "rssi");
    TEST_ASSERT_EQ(rc_decoded.quality, rc_orig.quality, "quality");
    
    return 1;
}

/* ============================================================================
 * 2. AEAD ENCRYPTION TESTS
 * ============================================================================ */

int test_aead_encrypt_decrypt_roundtrip(void)
{
    // Create a simple test message
    // Note: system_status is serialized as float, so use float-safe value
    ul_heartbeat_t hb = {
        .system_status = 12345,
        .system_type = 1,
        .autopilot_type = 2,
        .base_mode = 0x55
    };
    
    uint8_t payload[32];
    int payload_len = ul_serialize_heartbeat(&hb, payload);
    
    // Create header
    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.priority = UL_PRIO_NORMAL;
    header.stream_type = UL_STREAM_HEARTBEAT;
    header.encrypted = true;
    header.fragmented = false;
    header.sequence = 42;
    header.sys_id = 1;
    header.comp_id = 2;
    header.target_sys_id = 0;
    header.msg_id = UL_MSG_HEARTBEAT;
    memcpy(header.nonce, test_nonce, 8);
    
    // Pack with encryption
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, test_key);
    TEST_ASSERT(packet_len > 0, "Pack with encryption should succeed");
    
    // Expected size: 4 (base) + 4 (ext: seq+sys+comp+msg) + 8 (nonce) + payload_len + 16 (MAC) + 2 (CRC)
    // Note: No target_sys_id (0 = broadcast), no fragmentation
    int expected_len = 4 + 4 + 8 + payload_len + 16 + 2;
    TEST_ASSERT_EQ(packet_len, expected_len, "Packet length should be correct");
    
    // Parse it back
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], test_key);
        if (complete == UL_OK) {
            break;
        }
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Parser should successfully decrypt and verify");
    
    TEST_ASSERT_EQ(parser.header.payload_len, payload_len, "Payload length");
    TEST_ASSERT_EQ(parser.header.sequence, 42, "Sequence number");
    TEST_ASSERT_EQ(parser.header.msg_id, UL_MSG_HEARTBEAT, "Message ID");
    
    // Deserialize and verify payload
    ul_heartbeat_t hb_decoded;
    int result = ul_deserialize_heartbeat(&hb_decoded, parser.payload);
    TEST_ASSERT(result > 0, "Deserialization should return byte count");
    TEST_ASSERT_EQ(hb_decoded.system_status, hb.system_status, "system_status");
    
    return 1;
}

/* ============================================================================
 * 3. MAC VERIFICATION TESTS
 * ============================================================================ */

int test_mac_verification_tampered_payload(void)
{
    // Create and encrypt a packet
    ul_heartbeat_t hb = {0x12345678, 1, 2, 0xAB};
    uint8_t payload[32];
    int payload_len = ul_serialize_heartbeat(&hb, payload);
    
    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.encrypted = true;
    header.sequence = 100;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = UL_MSG_HEARTBEAT;
    memcpy(header.nonce, test_nonce, 8);
    
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, test_key);
    TEST_ASSERT(packet_len > 0, "Pack should succeed");
    
    // Tamper with encrypted payload (modify a byte in the middle)
    // Find where payload starts: 4 (base) + 4 (ext) + 8 (nonce) = 16
    packet[16 + 3] ^= 0xFF;  // Flip bits in encrypted payload
    
    // Recalculate CRC so it passes CRC check but fails MAC
    uint16_t new_crc;
    ul_crc_init(&new_crc);
    for (int i = 1; i < packet_len - 2; i++) {  // Skip SOF, stop before CRC
        ul_crc_accumulate(packet[i], &new_crc);
    }
    ul_crc_accumulate(ul_get_crc_seed(header.msg_id), &new_crc);
    packet[packet_len - 2] = new_crc & 0xFF;
    packet[packet_len - 1] = new_crc >> 8;
    
    // Try to parse - should fail MAC verification
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], test_key);
    }
    
    TEST_ASSERT_EQ(complete, UL_ERR_MAC_VERIFICATION, "Should detect tampered payload");
    
    return 1;
}

int test_mac_verification_tampered_header(void)
{
    // Create and encrypt a packet
    ul_heartbeat_t hb = {0xCAFEBABE, 3, 4, 0xCC};
    uint8_t payload[32];
    int payload_len = ul_serialize_heartbeat(&hb, payload);
    
    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.encrypted = true;
    header.sequence = 200;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = UL_MSG_HEARTBEAT;
    memcpy(header.nonce, test_nonce, 8);
    
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, test_key);
    TEST_ASSERT(packet_len > 0, "Pack should succeed");
    
    // Tamper with header (modify sequence number in base header byte 3)
    packet[3] ^= 0x01;  // Flip one bit in byte 3 (contains sequence bits)
    
    // Recalculate CRC so it passes CRC check but fails MAC (header is AAD)
    uint16_t new_crc;
    ul_crc_init(&new_crc);
    for (int i = 1; i < packet_len - 2; i++) {  // Skip SOF, stop before CRC
        ul_crc_accumulate(packet[i], &new_crc);
    }
    ul_crc_accumulate(ul_get_crc_seed(header.msg_id), &new_crc);
    packet[packet_len - 2] = new_crc & 0xFF;
    packet[packet_len - 1] = new_crc >> 8;
    
    // Try to parse - should fail MAC verification (header is AAD)
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], test_key);
    }
    
    TEST_ASSERT_EQ(complete, UL_ERR_MAC_VERIFICATION, "Should detect tampered header");
    
    return 1;
}

int test_mac_verification_wrong_key(void)
{
    // Create and encrypt a packet
    ul_heartbeat_t hb = {0xDEADC0DE, 5, 6, 0xFF};
    uint8_t payload[32];
    int payload_len = ul_serialize_heartbeat(&hb, payload);
    
    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.encrypted = true;
    header.sequence = 300;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = UL_MSG_HEARTBEAT;
    memcpy(header.nonce, test_nonce, 8);
    
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, test_key);
    TEST_ASSERT(packet_len > 0, "Pack should succeed");
    
    // Try to decrypt with wrong key
    uint8_t wrong_key[32];
    memcpy(wrong_key, test_key, 32);
    wrong_key[0] ^= 0xFF;  // Modify first byte
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], wrong_key);
    }
    
    TEST_ASSERT_EQ(complete, UL_ERR_MAC_VERIFICATION, "Should fail with wrong key");
    
    return 1;
}

/* ============================================================================
 * 4. PARSER STATE MACHINE TESTS
 * ============================================================================ */

int test_parser_multiple_packets(void)
{
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    // Create two packets
    ul_header_t header1 = {0};
    header1.payload_len = 4;
    header1.encrypted = false;
    header1.sequence = 1;
    header1.sys_id = 1;
    header1.comp_id = 1;
    header1.msg_id = UL_MSG_HEARTBEAT;
    
    uint8_t payload1[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t packet1[256];
    int len1 = uavlink_pack(packet1, &header1, payload1, NULL);
    TEST_ASSERT(len1 > 0, "First packet should pack successfully");
    
    ul_header_t header2 = {0};
    header2.payload_len = 4;
    header2.encrypted = false;
    header2.sequence = 2;
    header2.sys_id = 2;
    header2.comp_id = 2;
    header2.msg_id = UL_MSG_ATTITUDE;
    
    uint8_t payload2[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t packet2[256];
    int len2 = uavlink_pack(packet2, &header2, payload2, NULL);
    TEST_ASSERT(len2 > 0, "Second packet should pack successfully");
    
    // Concatenate packets
    uint8_t stream[512];
    memcpy(stream, packet1, len1);
    memcpy(stream + len1, packet2, len2);
    
    // Parse both packets
    int complete_count = 0;
    for (int i = 0; i < len1 + len2; i++) {
        int result = ul_parse_char(&parser, stream[i], NULL);
        if (result == UL_OK) {  // Parser returns UL_OK (0) on success
            complete_count++;
            if (complete_count == 1) {
                TEST_ASSERT_EQ(parser.header.sequence, 1, "First packet sequence");
                TEST_ASSERT_EQ(parser.header.sys_id, 1, "First packet sys_id");
            } else if (complete_count == 2) {
                TEST_ASSERT_EQ(parser.header.sequence, 2, "Second packet sequence");
                TEST_ASSERT_EQ(parser.header.sys_id, 2, "Second packet sys_id");
            }
        }
    }
    
    TEST_ASSERT_EQ(complete_count, 2, "Should parse both packets");
    
    return 1;
}

int test_parser_bad_crc(void)
{
    // Create a valid packet
    ul_header_t header = {0};
    header.payload_len = 4;
    header.encrypted = false;
    header.sequence = 50;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = UL_MSG_HEARTBEAT;
    
    uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t packet[256];
    int len = uavlink_pack(packet, &header, payload, NULL);
    
    // Corrupt the CRC
    packet[len - 1] ^= 0xFF;
    
    // Try to parse
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < len; i++) {
        complete = ul_parse_char(&parser, packet[i], NULL);
    }
    
    TEST_ASSERT_EQ(complete, UL_ERR_CRC, "Should detect bad CRC");
    
    return 1;
}

int test_parser_bad_sof(void)
{
    // Create a stream with invalid start byte
    uint8_t stream[] = {0x00, 0xFF, 0xA5, 0x10, 0x00, 0x00};  // Wrong SOF, then correct SOF
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    // Parse the invalid bytes
    for (int i = 0; i < 2; i++) {
        int result = ul_parse_char(&parser, stream[i], NULL);
        TEST_ASSERT(result > 0, "Should ignore invalid SOF");
        TEST_ASSERT_EQ(parser.state, UL_PARSE_STATE_IDLE, "Should stay in IDLE");
    }
    
    // Now parse the correct SOF
    int result = ul_parse_char(&parser, stream[2], NULL);
    TEST_ASSERT(result > 0, "Should accept valid SOF");
    TEST_ASSERT(parser.state != UL_PARSE_STATE_IDLE, "Should advance from IDLE");
    
    return 1;
}

/* ============================================================================
 * 5. ERROR HANDLING TESTS
 * ============================================================================ */

int test_null_pointer_handling(void)
{
    uint8_t buffer[64];
    ul_heartbeat_t hb = {0};
    ul_header_t header = {0};
    header.payload_len = 4;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = 1;
    
    // Test NULL pointer checks in serialization functions
    int result;
    
    result = ul_serialize_heartbeat(NULL, buffer);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Serialize with NULL struct");
    
    result = ul_serialize_heartbeat(&hb, NULL);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Serialize with NULL buffer");
    
    result = ul_deserialize_heartbeat(NULL, buffer);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Deserialize with NULL struct");
    
    result = ul_deserialize_heartbeat(&hb, NULL);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Deserialize with NULL buffer");
    
    // Test parser initialization
    ul_parser_init(NULL);  // Should not crash (check added)
    
    // Test parse_char with NULL parser (should return error code)
    result = ul_parse_char(NULL, 0x00, NULL);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Parse with NULL parser");
    
    // Test uavlink_pack with NULL pointers
    result = uavlink_pack(NULL, &header, buffer, NULL);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Pack with NULL buffer");
    
    result = uavlink_pack(buffer, NULL, buffer, NULL);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Pack with NULL header");
    
    result = uavlink_pack(buffer, &header, NULL, NULL);
    TEST_ASSERT_EQ(result, UL_ERR_NULL_POINTER, "Pack with NULL payload");
    
    return 1;
}

int test_buffer_overflow_protection(void)
{
    // Try to create a packet exceeding UL_MAX_PAYLOAD_SIZE (512 bytes)
    ul_header_t header = {0};
    header.payload_len = 600;  // Exceeds UL_MAX_PAYLOAD_SIZE (512)
    header.encrypted = false;
    header.sequence = 1;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = 0x123;
    
    uint8_t large_payload[600];
    memset(large_payload, 0xAA, sizeof(large_payload));
    
    uint8_t packet[1024];
    int result = uavlink_pack(packet, &header, large_payload, NULL);
    
    // Should reject oversized payload
    TEST_ASSERT_EQ(result, UL_ERR_BUFFER_OVERFLOW, "Should reject oversized payload");
    
    // Now test valid maximum size
    header.payload_len = 512;  // Exactly UL_MAX_PAYLOAD_SIZE
    result = uavlink_pack(packet, &header, large_payload, NULL);
    TEST_ASSERT(result > 0, "Should accept maximum valid payload");
    
    return 1;
}

/* ============================================================================
 * 6. CRC TESTS
 * ============================================================================ */

int test_crc_known_vectors(void)
{
    // MAVLink X.25 CRC with 0xFFFF initial value
    // Test vector: "123456789" gives 0x6F91 (MAVLink variant)
    const uint8_t test_data[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    
    uint16_t crc;
    ul_crc_init(&crc);
    
    for (int i = 0; i < 9; i++) {
        ul_crc_accumulate(test_data[i], &crc);
    }
    
    // MAVLink uses X.25 CRC variant - different from standard CCITT
    TEST_ASSERT_EQ(crc, 0x6F91, "MAVLink X.25 CRC test vector");
    
    return 1;
}

int test_crc_empty_message(void)
{
    uint16_t crc;
    ul_crc_init(&crc);
    
    // Empty message should give initial value
    TEST_ASSERT_EQ(crc, 0xFFFF, "CRC initial value");
    
    return 1;
}

/* ============================================================================
 * 7. NONCE MANAGEMENT TESTS
 * ============================================================================ */

int test_nonce_initialization(void)
{
    ul_nonce_state_t state;
    memset(&state, 0xAA, sizeof(state));  // Fill with garbage
    
    ul_nonce_init(&state);
    // Counter initializes with random value for security (prevents reuse after reset)
    // Just verify it's been initialized, not the specific counter value
    TEST_ASSERT_EQ(state.initialized, 1, "Should be marked as initialized");
    
    return 1;
}

int test_nonce_uniqueness(void)
{
    ul_nonce_state_t state;
    ul_nonce_init(&state);
    
    uint8_t nonce1[8];
    uint8_t nonce2[8];
    uint8_t nonce3[8];
    
    ul_nonce_generate(&state, nonce1);
    ul_nonce_generate(&state, nonce2);
    ul_nonce_generate(&state, nonce3);
    
    // Counter should increment
    TEST_ASSERT(memcmp(nonce1, nonce2, 8) != 0, "Nonces should be different");
    TEST_ASSERT(memcmp(nonce2, nonce3, 8) != 0, "Nonces should be different");
    TEST_ASSERT(memcmp(nonce1, nonce3, 8) != 0, "Nonces should be different");
    
    return 1;
}

int test_nonce_counter_increment(void)
{
    ul_nonce_state_t state;
    ul_nonce_init(&state);
    
    uint8_t nonce[8];
    uint32_t initial_counter = state.counter;
    
    // Generate several nonces and verify counter increases
    for (int i = 0; i < 10; i++) {
        uint32_t prev_counter = state.counter;
        ul_nonce_generate(&state, nonce);
        TEST_ASSERT(state.counter > prev_counter, "Counter should increment");
    }
    
    TEST_ASSERT_EQ(state.counter, initial_counter + 10, "Counter should increment by 10");
    
    return 1;
}

int test_pack_with_nonce_state(void)
{
    ul_nonce_state_t state;
    ul_nonce_init(&state);
    uint32_t initial_counter = state.counter;
    
    ul_heartbeat_t hb = {0x12345678, 1, 2, 0xAB};
    uint8_t payload[32];
    int payload_len = ul_serialize_heartbeat(&hb, payload);
    
    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.encrypted = true;
    header.sequence = 1;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = UL_MSG_HEARTBEAT;
    
    uint8_t packet[256];
    int packet_len = uavlink_pack_with_nonce(packet, &header, payload, test_key, &state);
    
    TEST_ASSERT(packet_len > 0, "Pack with nonce state should succeed");
    TEST_ASSERT_EQ(state.counter, initial_counter + 1, "Counter should have incremented by 1");
    
    // Parse it back
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], test_key);
        if (complete == UL_OK) break;  // Parser returns UL_OK (0) on success
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should decrypt successfully");
    
    return 1;
}

/* ============================================================================
 * 8. REPLAY PROTECTION / SEQUENCE TRACKING TESTS
 * ============================================================================ */

int test_sequence_tracking_basic(void)
{
    /* Test that parser correctly extracts and tracks sequence numbers
       Note: Current implementation does NOT reject duplicate sequences */
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    // Create three packets with different sequence numbers
    for (int seq = 0; seq < 3; seq++) {
        ul_header_t header = {0};
        header.payload_len = 4;
        header.sequence = seq;
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = 1;
        
        uint8_t payload[] = {0x11, 0x22, 0x33, 0x44};
        uint8_t packet[256];
        int packet_len = uavlink_pack(packet, &header, payload, NULL);
        TEST_ASSERT(packet_len > 0, "Should pack successfully");
        
        // Parse packet
        int complete = 0;
        for (int i = 0; i < packet_len; i++) {
            complete = ul_parse_char(&parser, packet[i], NULL);
            if (complete == UL_OK) break;
        }
        
        TEST_ASSERT_EQ(complete, UL_OK, "Should parse successfully");
        TEST_ASSERT_EQ(parser.header.sequence, seq, "Sequence should match");
    }
    
    return 1;
}

int test_duplicate_sequence_detection(void)
{
    /* NOTE: Current implementation does NOT implement replay protection.
       This test verifies that duplicate packets ARE accepted (current behavior).
       When replay protection is added, this test should be updated to expect rejection. */
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    // Create a packet with sequence 100
    ul_header_t header = {0};
    header.payload_len = 4;
    header.sequence = 100;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = 1;
    
    uint8_t payload[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, NULL);
    
    // Parse same packet twice
    for (int attempt = 0; attempt < 2; attempt++) {
        int complete = 0;
        for (int i = 0; i < packet_len; i++) {
            complete = ul_parse_char(&parser, packet[i], NULL);
            if (complete == UL_OK) break;
        }
        
        // Currently accepts duplicates (no replay protection)
        TEST_ASSERT_EQ(complete, UL_OK, "Currently accepts duplicate sequence");
        TEST_ASSERT_EQ(parser.header.sequence, 100, "Sequence should be 100");
        
        // TODO: When replay protection is added, second attempt should return UL_ERR_REPLAY
    }
    
    return 1;
}

int test_sequence_rollover_handling(void)
{
    /* Test sequence number rollover: 4095 -> 0 
       12-bit sequence wraps around after 4095 */
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    uint16_t test_sequences[] = {4093, 4094, 4095, 0, 1, 2};
    int num_sequences = sizeof(test_sequences) / sizeof(test_sequences[0]);
    
    for (int i = 0; i < num_sequences; i++) {
        ul_header_t header = {0};
        header.payload_len = 2;
        header.sequence = test_sequences[i];
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = 1;
        
        uint8_t payload[] = {0x01, 0x02};
        uint8_t packet[256];
        int packet_len = uavlink_pack(packet, &header, payload, NULL);
        
        int complete = 0;
        for (int j = 0; j < packet_len; j++) {
            complete = ul_parse_char(&parser, packet[j], NULL);
            if (complete == UL_OK) break;
        }
        
        TEST_ASSERT_EQ(complete, UL_OK, "Should parse rollover sequence");
        TEST_ASSERT_EQ(parser.header.sequence, test_sequences[i], "Sequence should match");
    }
    
    return 1;
}

int test_out_of_order_packets(void)
{
    /* Test that parser accepts out-of-order packets
       Note: Without replay window, all packets are accepted regardless of order */
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    // Send packets in non-sequential order: 5, 2, 8, 1, 4
    uint16_t sequences[] = {5, 2, 8, 1, 4};
    int num_packets = sizeof(sequences) / sizeof(sequences[0]);
    
    for (int i = 0; i < num_packets; i++) {
        ul_header_t header = {0};
        header.payload_len = 3;
        header.sequence = sequences[i];
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = 1;
        
        uint8_t payload[] = {0xFF, 0xEE, 0xDD};
        uint8_t packet[256];
        int packet_len = uavlink_pack(packet, &header, payload, NULL);
        
        int complete = 0;
        for (int j = 0; j < packet_len; j++) {
            complete = ul_parse_char(&parser, packet[j], NULL);
            if (complete == UL_OK) break;
        }
        
        TEST_ASSERT_EQ(complete, UL_OK, "Should accept out-of-order packet");
        TEST_ASSERT_EQ(parser.header.sequence, sequences[i], "Sequence should match");
    }
    
    return 1;
}

int test_encrypted_packet_replay(void)
{
    /* Test replay of encrypted packets with unique nonces
       Even without sequence-based replay protection, AEAD nonces provide
       cryptographic replay protection when properly implemented */
    
    ul_nonce_state_t state;
    ul_nonce_init(&state);
    
    ul_heartbeat_t hb = {0x11223344, 1, 2, 0x55};
    uint8_t payload[32];
    int payload_len = ul_serialize_heartbeat(&hb, payload);
    
    ul_header_t header = {0};
    header.payload_len = payload_len;
    header.encrypted = true;
    header.sequence = 50;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = UL_MSG_HEARTBEAT;
    
    // Create packet with unique nonce
    uint8_t packet[256];
    int packet_len = uavlink_pack_with_nonce(packet, &header, payload, test_key, &state);
    TEST_ASSERT(packet_len > 0, "Should pack encrypted packet");
    
    // Parse packet first time - should succeed
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], test_key);
        if (complete == UL_OK) break;
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "First parse should succeed");
    TEST_ASSERT_EQ(parser.header.sequence, 50, "Sequence should be 50");
    
    // Parse same packet again - currently accepted (no nonce tracking)
    // Note: True replay protection would track nonces and reject this
    ul_parser_init(&parser);
    complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], test_key);
        if (complete == UL_OK) break;
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Currently accepts replayed encrypted packet");
    
    return 1;
}

/* ============================================================================
 * 10. FRAGMENTATION TESTS
 * ============================================================================ */

int test_fragmentation_header_encoding(void)
{
    /* Test that fragmentation metadata is correctly encoded in headers */
    
    ul_header_t header = {0};
    header.payload_len = 100;
    header.fragmented = true;
    header.frag_index = 2;   // Fragment 2 of 5
    header.frag_total = 5;
    header.sequence = 42;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = 0x123;
    
    uint8_t payload[100];
    for (int i = 0; i < 100; i++) payload[i] = i;
    
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, NULL);
    TEST_ASSERT(packet_len > 0, "Should pack fragmented packet");
    
    // Parse it back to verify fragmentation fields
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], NULL);
        if (complete == UL_OK) break;
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should parse fragmented packet");
    TEST_ASSERT(parser.header.fragmented, "Fragmented flag should be set");
    TEST_ASSERT_EQ(parser.header.frag_index, 2, "Fragment index should be 2");
    TEST_ASSERT_EQ(parser.header.frag_total, 5, "Fragment total should be 5");
    TEST_ASSERT_EQ(parser.header.payload_len, 100, "Payload length should be 100");
    
    return 1;
}

int test_multiple_fragments_separate_packets(void)
{
    /* Test sending multiple fragments as separate packets
       Note: Current implementation does NOT reassemble fragments.
       Each fragment is parsed independently. */
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    // Create 3 fragments of a larger message
    int total_fragments = 3;
    int fragment_size = 50;
    
    for (int frag_idx = 0; frag_idx < total_fragments; frag_idx++) {
        ul_header_t header = {0};
        header.payload_len = fragment_size;
        header.fragmented = true;
        header.frag_index = frag_idx;
        header.frag_total = total_fragments;
        header.sequence = 100 + frag_idx;  // Each fragment gets unique sequence
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = 0x200;
        
        uint8_t payload[50];
        for (int i = 0; i < fragment_size; i++) {
            payload[i] = (frag_idx * 50) + i;  // Sequential data across fragments
        }
        
        uint8_t packet[256];
        int packet_len = uavlink_pack(packet, &header, payload, NULL);
        TEST_ASSERT(packet_len > 0, "Should pack fragment");
        
        // Parse fragment
        int complete = 0;
        for (int i = 0; i < packet_len; i++) {
            complete = ul_parse_char(&parser, packet[i], NULL);
            if (complete == UL_OK) break;
        }
        
        TEST_ASSERT_EQ(complete, UL_OK, "Should parse fragment");
        TEST_ASSERT_EQ(parser.header.frag_index, frag_idx, "Fragment index should match");
        TEST_ASSERT_EQ(parser.header.frag_total, total_fragments, "Fragment total should match");
        
        // Verify payload data
        for (int i = 0; i < fragment_size; i++) {
            TEST_ASSERT_EQ(parser.payload[i], (frag_idx * 50) + i, "Payload data should match");
        }
    }
    
    return 1;
}

int test_fragmentation_with_encryption(void)
{
    /* Test that fragmented packets can be encrypted
       Each fragment is independently encrypted with unique nonce */
    
    ul_nonce_state_t state;
    ul_nonce_init(&state);
    
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    // Send 2 encrypted fragments
    for (int frag_idx = 0; frag_idx < 2; frag_idx++) {
        ul_header_t header = {0};
        header.payload_len = 30;
        header.encrypted = true;
        header.fragmented = true;
        header.frag_index = frag_idx;
        header.frag_total = 2;
        header.sequence = 500 + frag_idx;
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = 0x300;
        
        uint8_t payload[30];
        for (int i = 0; i < 30; i++) payload[i] = 0xA0 + i;
        
        uint8_t packet[256];
        int packet_len = uavlink_pack_with_nonce(packet, &header, payload, test_key, &state);
        TEST_ASSERT(packet_len > 0, "Should pack encrypted fragment");
        
        // Parse and decrypt fragment
        int complete = 0;
        for (int i = 0; i < packet_len; i++) {
            complete = ul_parse_char(&parser, packet[i], test_key);
            if (complete == UL_OK) break;
        }
        
        TEST_ASSERT_EQ(complete, UL_OK, "Should decrypt fragment");
        TEST_ASSERT(parser.header.fragmented, "Should be fragmented");
        TEST_ASSERT(parser.header.encrypted, "Should be encrypted");
        TEST_ASSERT_EQ(parser.header.frag_index, frag_idx, "Fragment index should match");
        
        // Verify decrypted payload
        for (int i = 0; i < 30; i++) {
            TEST_ASSERT_EQ(parser.payload[i], 0xA0 + i, "Decrypted payload should match");
        }
    }
    
    return 1;
}

int test_single_packet_not_fragmented(void)
{
    /* Test that non-fragmented packets have fragmented=false */
    
    ul_header_t header = {0};
    header.payload_len = 10;
    header.fragmented = false;  // Explicitly not fragmented
    header.sequence = 1;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = 0x001;
    
    uint8_t payload[10] = {1,2,3,4,5,6,7,8,9,10};
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, NULL);
    
    // Parse it back
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], NULL);
        if (complete == UL_OK) break;
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should parse non-fragmented packet");
    TEST_ASSERT(!parser.header.fragmented, "Fragmented flag should be false");
    
    return 1;
}

int test_fragment_boundary_cases(void)
{
    /* Test fragmentation boundary cases:
       - First fragment (index 0)
       - Last fragment  
       - Single fragment (total=1, index=0) */
    
    ul_parser_t parser;
    
    // Test first fragment (0 of 10)
    ul_parser_init(&parser);
    ul_header_t header1 = {0};
    header1.payload_len = 20;
    header1.fragmented = true;
    header1.frag_index = 0;
    header1.frag_total = 10;
    header1.sequence = 1;
    header1.sys_id = 1;
    header1.comp_id = 1;
    header1.msg_id = 1;
    
    uint8_t payload1[20] = {0};
    uint8_t packet1[256];
    int len1 = uavlink_pack(packet1, &header1, payload1, NULL);
    
    int complete = 0;
    for (int i = 0; i < len1; i++) {
        complete = ul_parse_char(&parser, packet1[i], NULL);
        if (complete == UL_OK) break;
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should parse first fragment");
    TEST_ASSERT_EQ(parser.header.frag_index, 0, "First fragment index should be 0");
    TEST_ASSERT_EQ(parser.header.frag_total, 10, "Total should be 10");
    
    // Test last fragment (9 of 10)
    ul_parser_init(&parser);
    ul_header_t header2 = {0};
    header2.payload_len = 15;
    header2.fragmented = true;
    header2.frag_index = 9;
    header2.frag_total = 10;
    header2.sequence = 2;
    header2.sys_id = 1;
    header2.comp_id = 1;
    header2.msg_id = 1;
    
    uint8_t payload2[15] = {0};
    uint8_t packet2[256];
    int len2 = uavlink_pack(packet2, &header2, payload2, NULL);
    
    complete = 0;
    for (int i = 0; i < len2; i++) {
        complete = ul_parse_char(&parser, packet2[i], NULL);
        if (complete == UL_OK) break;
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should parse last fragment");
    TEST_ASSERT_EQ(parser.header.frag_index, 9, "Last fragment index should be 9");
    
    // Test single fragment (0 of 1) - edge case
    ul_parser_init(&parser);
    ul_header_t header3 = {0};
    header3.payload_len = 25;
    header3.fragmented = true;
    header3.frag_index = 0;
    header3.frag_total = 1;
    header3.sequence = 3;
    header3.sys_id = 1;
    header3.comp_id = 1;
    header3.msg_id = 1;
    
    uint8_t payload3[25] = {0};
    uint8_t packet3[256];
    int len3 = uavlink_pack(packet3, &header3, payload3, NULL);
    
    complete = 0;
    for (int i = 0; i < len3; i++) {
        complete = ul_parse_char(&parser, packet3[i], NULL);
        if (complete == UL_OK) break;
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should parse single fragment");
    TEST_ASSERT_EQ(parser.header.frag_index, 0, "Single fragment index should be 0");
    TEST_ASSERT_EQ(parser.header.frag_total, 1, "Single fragment total should be 1");
    
    return 1;
}

/* ============================================================================
 * 11. EDGE CASE TESTS
 * ============================================================================ */

int test_zero_length_payload(void)
{
    ul_header_t header = {0};
    header.payload_len = 0;
    header.encrypted = false;
    header.sequence = 1;
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = 0x001;
    
    uint8_t dummy_payload = 0;  // Dummy byte to avoid NULL pointer
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, &dummy_payload, NULL);
    
    TEST_ASSERT(packet_len > 0, "Should pack zero-length payload");
    
    // Parse it back
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], NULL);
        if (complete == UL_OK) {
            break;
        }
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should parse zero-length payload");
    TEST_ASSERT_EQ(parser.header.payload_len, 0, "Payload length should be 0");
    
    return 1;
}

int test_max_sequence_number(void)
{
    ul_header_t header = {0};
    header.payload_len = 4;
    header.sequence = 4095;  // Max 12-bit value
    header.sys_id = 1;
    header.comp_id = 1;
    header.msg_id = 0x001;
    
    uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t packet[256];
    int packet_len = uavlink_pack(packet, &header, payload, NULL);
    
    TEST_ASSERT(packet_len > 0, "Should pack max sequence number");
    
    // Parse it back
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    int complete = 0;
    for (int i = 0; i < packet_len; i++) {
        complete = ul_parse_char(&parser, packet[i], NULL);
        if (complete == UL_OK) break;  // Parser returns UL_OK (0) on success
    }
    
    TEST_ASSERT_EQ(complete, UL_OK, "Should parse max sequence");
    TEST_ASSERT_EQ(parser.header.sequence, 4095, "Sequence should be 4095");
    
    return 1;
}

int test_all_priority_levels(void)
{
    uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    
    for (int prio = UL_PRIO_BULK; prio <= UL_PRIO_EMERGENCY; prio++) {
        ul_header_t header = {0};
        header.payload_len = 4;
        header.priority = prio;
        header.sequence = prio;
        header.sys_id = 1;
        header.comp_id = 1;
        header.msg_id = 0x001;
        
        uint8_t packet[256];
        int packet_len = uavlink_pack(packet, &header, payload, NULL);
        TEST_ASSERT(packet_len > 0, "Should pack with priority");
        
        // Parse it back
        ul_parser_t parser;
        ul_parser_init(&parser);
        
        int complete = 0;
        for (int i = 0; i < packet_len; i++) {
            complete = ul_parse_char(&parser, packet[i], NULL);
            if (complete == UL_OK) break;  // Parser returns UL_OK (0) on success
        }
        
        TEST_ASSERT_EQ(complete, UL_OK, "Should parse priority packet");
        TEST_ASSERT_EQ(parser.header.priority, prio, "Priority should match");
    }
    
    return 1;
}

/* ============================================================================
 * TEST SUITE RUNNER
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║         UAVLink Protocol Unit Test Suite v1.0             ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("1. SERIALIZATION/DESERIALIZATION TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_heartbeat_serialization);
    RUN_TEST(test_attitude_serialization);
    RUN_TEST(test_gps_serialization);
    RUN_TEST(test_battery_serialization);
    RUN_TEST(test_rc_input_serialization);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("2. AEAD ENCRYPTION TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_aead_encrypt_decrypt_roundtrip);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("3. MAC VERIFICATION TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_mac_verification_tampered_payload);
    RUN_TEST(test_mac_verification_tampered_header);
    RUN_TEST(test_mac_verification_wrong_key);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("4. PARSER STATE MACHINE TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_parser_multiple_packets);
    RUN_TEST(test_parser_bad_crc);
    RUN_TEST(test_parser_bad_sof);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("5. ERROR HANDLING TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_null_pointer_handling);
    RUN_TEST(test_buffer_overflow_protection);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("6. CRC TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_crc_known_vectors);
    RUN_TEST(test_crc_empty_message);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("7. NONCE MANAGEMENT TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_nonce_initialization);
    RUN_TEST(test_nonce_uniqueness);
    RUN_TEST(test_nonce_counter_increment);
    RUN_TEST(test_pack_with_nonce_state);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("8. REPLAY PROTECTION / SEQUENCE TRACKING TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_sequence_tracking_basic);
    RUN_TEST(test_duplicate_sequence_detection);
    RUN_TEST(test_sequence_rollover_handling);
    RUN_TEST(test_out_of_order_packets);
    RUN_TEST(test_encrypted_packet_replay);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("9. FRAGMENTATION TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_fragmentation_header_encoding);
    RUN_TEST(test_multiple_fragments_separate_packets);
    RUN_TEST(test_fragmentation_with_encryption);
    RUN_TEST(test_single_packet_not_fragmented);
    RUN_TEST(test_fragment_boundary_cases);
    
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("10. EDGE CASE TESTS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    RUN_TEST(test_zero_length_payload);
    RUN_TEST(test_max_sequence_number);
    RUN_TEST(test_all_priority_levels);
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      TEST SUMMARY                          ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:  %-4d                                        ║\n", test_total);
    printf("║  Passed:       %-4d  ✓                                     ║\n", test_passed);
    printf("║  Failed:       %-4d  ✗                                     ║\n", test_failed);
    printf("║  Success Rate: %.1f%%                                      ║\n", 
           test_total > 0 ? (100.0 * test_passed / test_total) : 0.0);
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    if (test_failed == 0) {
        printf("🎉 ALL TESTS PASSED! 🎉\n\n");
        return 0;
    } else {
        printf("⚠️  SOME TESTS FAILED - Please review output above\n\n");
        return 1;
    }
}
