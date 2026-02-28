#include <stdio.h>
#include <string.h>
#include "uavlink.h"

void print_hex(const char *label, uint8_t *data, int len)
{
    printf("%s (%d bytes): ", label, len);
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main()
{
    printf("=== UAVLink Message Types Demo ===\n\n");

    // Initialize nonce state for encryption
    ul_nonce_state_t nonce_state;
    ul_nonce_init(&nonce_state);

    uint8_t key[32] = "SUPER_SECRET_UAVLINK_KEY_32BYTES";
    uint8_t packet[256];
    uint16_t sequence = 0;

    // ===== 1. HEARTBEAT MESSAGE =====
    printf("--- 1. HEARTBEAT MESSAGE (0x001) ---\n");
    ul_heartbeat_t heartbeat = {
        .system_status = 4,   // MAV_STATE_ACTIVE
        .system_type = 2,     // MAV_TYPE_QUADROTOR
        .autopilot_type = 12, // MAV_AUTOPILOT_PX4
        .base_mode = 0x81     // Armed + Custom mode
    };

    uint8_t hb_payload[7];
    int hb_len = ul_serialize_heartbeat(&heartbeat, hb_payload);

    ul_header_t hb_header = {
        .payload_len = hb_len,
        .priority = UL_PRIO_HIGH,
        .stream_type = UL_STREAM_HEARTBEAT,
        .sequence = sequence++,
        .sys_id = 1,
        .comp_id = 0,
        .msg_id = UL_MSG_HEARTBEAT};

    int pkt_len = uavlink_pack_with_nonce(packet, &hb_header, hb_payload, key, &nonce_state);
    print_hex("Heartbeat Packet", packet, pkt_len);
    printf("  System Status: %u, Type: %u, Autopilot: %u\n\n",
           heartbeat.system_status, heartbeat.system_type, heartbeat.autopilot_type);

    // ===== 2. ATTITUDE MESSAGE =====
    printf("--- 2. ATTITUDE MESSAGE (0x002) ---\n");
    ul_attitude_t attitude = {
        .roll = 0.1f,
        .pitch = -0.2f,
        .yaw = 3.14159f,
        .rollspeed = 0.05f,
        .pitchspeed = -0.05f,
        .yawspeed = 0.1f};

    uint8_t att_payload[18];
    int att_len = ul_serialize_attitude(&attitude, att_payload);

    ul_header_t att_header = {
        .payload_len = att_len,
        .priority = UL_PRIO_NORMAL,
        .stream_type = UL_STREAM_TELEM_FAST,
        .sequence = sequence++,
        .sys_id = 1,
        .comp_id = 0,
        .msg_id = UL_MSG_ATTITUDE};

    pkt_len = uavlink_pack_with_nonce(packet, &att_header, att_payload, key, &nonce_state);
    print_hex("Attitude Packet", packet, pkt_len);
    printf("  Roll: %.2f, Pitch: %.2f, Yaw: %.2f rad\n\n",
           attitude.roll, attitude.pitch, attitude.yaw);

    // ===== 3. GPS RAW MESSAGE =====
    printf("--- 3. GPS RAW MESSAGE (0x003) ---\n");
    ul_gps_raw_t gps = {
        .lat = 473977420, // 47.3977420° N (degrees × 1e7)
        .lon = 85241320,  // 8.5241320° E
        .alt = 500000,    // 500m AMSL (mm)
        .eph = 150,       // 1.5m horizontal accuracy (cm)
        .epv = 200,       // 2.0m vertical accuracy (cm)
        .vel = 1250,      // 12.5 m/s ground speed (cm/s)
        .cog = 18500,     // 185° course over ground (deg × 100)
        .fix_type = 3,    // 3D fix
        .satellites = 12  // 12 satellites visible
    };

    uint8_t gps_payload[22];
    int gps_len = ul_serialize_gps_raw(&gps, gps_payload);

    ul_header_t gps_header = {
        .payload_len = gps_len,
        .priority = UL_PRIO_NORMAL,
        .stream_type = UL_STREAM_TELEM_FAST,
        .sequence = sequence++,
        .sys_id = 1,
        .comp_id = 1, // GPS component
        .msg_id = UL_MSG_GPS_RAW};

    pkt_len = uavlink_pack_with_nonce(packet, &gps_header, gps_payload, key, &nonce_state);
    print_hex("GPS Packet", packet, pkt_len);
    printf("  Position: %.7f°N, %.7f°E, %dm\n",
           gps.lat / 1e7, gps.lon / 1e7, gps.alt / 1000);
    printf("  Fix: %d, Sats: %d, Speed: %.1f m/s\n\n",
           gps.fix_type, gps.satellites, gps.vel / 100.0);

    // ===== 4. BATTERY MESSAGE =====
    printf("--- 4. BATTERY MESSAGE (0x004) ---\n");
    ul_battery_t battery = {
        .voltage = 16800, // 16.8V (mV)
        .current = -1850, // -18.5A discharging (cA)
        .remaining = 65,  // 65% capacity
        .cell_count = 4,  // 4S LiPo
        .status = 0x01    // Battery good
    };

    uint8_t bat_payload[8];
    int bat_len = ul_serialize_battery(&battery, bat_payload);

    ul_header_t bat_header = {
        .payload_len = bat_len,
        .priority = UL_PRIO_NORMAL,
        .stream_type = UL_STREAM_TELEM_SLOW,
        .sequence = sequence++,
        .sys_id = 1,
        .comp_id = 0,
        .msg_id = UL_MSG_BATTERY};

    pkt_len = uavlink_pack_with_nonce(packet, &bat_header, bat_payload, key, &nonce_state);
    print_hex("Battery Packet", packet, pkt_len);
    printf("  Voltage: %.2fV, Current: %.2fA, Remaining: %d%%\n",
           battery.voltage / 1000.0, battery.current / 100.0, battery.remaining);
    printf("  Cells: %dS, Status: 0x%02X\n\n", battery.cell_count, battery.status);

    // ===== 5. RC INPUT MESSAGE =====
    printf("--- 5. RC INPUT MESSAGE (0x005) ---\n");
    ul_rc_input_t rc = {
        .channels = {1500, 1200, 1800, 1500, 1000, 2000, 1500, 1500},
        .rssi = 95,   // 95% signal strength
        .quality = 88 // 88% link quality
    };

    uint8_t rc_payload[18];
    int rc_len = ul_serialize_rc_input(&rc, rc_payload);

    ul_header_t rc_header = {
        .payload_len = rc_len,
        .priority = UL_PRIO_HIGH,
        .stream_type = UL_STREAM_TELEM_FAST,
        .sequence = sequence++,
        .sys_id = 1,
        .comp_id = 0,
        .msg_id = UL_MSG_RC_INPUT};

    pkt_len = uavlink_pack_with_nonce(packet, &rc_header, rc_payload, key, &nonce_state);
    print_hex("RC Input Packet", packet, pkt_len);
    printf("  Channels: [");
    for (int i = 0; i < 8; i++)
    {
        printf("%d", rc.channels[i]);
        if (i < 7)
            printf(", ");
    }
    printf("]\n");
    printf("  RSSI: %d%%, Quality: %d%%\n\n", rc.rssi, rc.quality);

    // ===== PARSING DEMONSTRATION =====
    printf("--- PARSING DEMO ---\n");
    printf("Parsing the GPS packet byte-by-byte...\n");

    // Re-generate GPS packet for parsing
    pkt_len = uavlink_pack_with_nonce(packet, &gps_header, gps_payload, key, &nonce_state);

    ul_parser_t parser;
    ul_parser_init(&parser);

    for (int i = 0; i < pkt_len; i++)
    {
        int result = ul_parse_char(&parser, packet[i], key);
        if (result == UL_OK)
        {
            printf("✓ Packet parsed successfully!\n");
            printf("  Message ID: 0x%03X, Sequence: %d, Payload: %d bytes\n",
                   parser.header.msg_id, parser.header.sequence, parser.header.payload_len);

            if (parser.header.msg_id == UL_MSG_GPS_RAW)
            {
                ul_gps_raw_t parsed_gps;
                ul_deserialize_gps_raw(&parsed_gps, parser.payload);
                printf("  Parsed GPS: %.7f°N, %.7f°E\n",
                       parsed_gps.lat / 1e7, parsed_gps.lon / 1e7);
            }
            break;
        }
        else if (result < 0)
        {
            printf("✗ Parse error: %d\n", result);
            break;
        }
    }

    printf("\n=== Summary ===\n");
    printf("Message Sizes:\n");
    printf("  HEARTBEAT  : 7 bytes\n");
    printf("  ATTITUDE   : 18 bytes\n");
    printf("  GPS_RAW    : 22 bytes\n");
    printf("  BATTERY    : 8 bytes\n");
    printf("  RC_INPUT   : 18 bytes\n");
    printf("\nAll message types demonstrated successfully!\n");

    return 0;
}
