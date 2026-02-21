#include <stdio.h>
#include <string.h>
#include "uavlink.h"

int main() {
    printf("=== UAVLink Complete Protocol Demo ===\n\n");
    
    // 1. Prepare Payload Data
    ul_attitude_t att_out = {
        .roll = 0.1f, .pitch = -0.2f, .yaw = 3.14f,
        .rollspeed = 0.05f, .pitchspeed = -0.05f, .yawspeed = 0.1f
    };
    
    uint8_t payload_bytes[32];
    int payload_len = ul_serialize_attitude(&att_out, payload_bytes);
    
    // 2. Prepare Header
    ul_header_t h_out = {0};
    h_out.payload_len = payload_len;
    h_out.priority = UL_PRIO_NORMAL;
    h_out.stream_type = UL_STREAM_TELEM_FAST;
    h_out.sequence = 42;
    h_out.sys_id = 1;
    h_out.comp_id = 1;
    h_out.target_sys_id = 0;
    h_out.msg_id = UL_MSG_ATTITUDE;
    
    // 3. Encrypt and Pack for Transmission
    uint8_t tx_buffer[256];
    uint8_t tx_key[32] = "SUPER_SECRET_UAVLINK_KEY_32BYTES"; // 256-bit key
    
    int tx_len = uavlink_pack(tx_buffer, &h_out, payload_bytes, tx_key);
    
    printf("Transmitting Packet (%d bytes):\n", tx_len);
    for(int i=0; i<tx_len; i++) printf("%02X ", tx_buffer[i]);
    printf("\n\n");
    
    // 4. Receive and Parse
    ul_parser_t parser;
    ul_parser_init(&parser);
    
    printf("Parsing stream byte-by-byte...\n");
    for(int i=0; i<tx_len; i++) {
        int res = ul_parse_char(&parser, tx_buffer[i], tx_key);
        if (res == 1) {
            printf("SUCCESS: Valid Packet Fully Received & Decrypted (Len: %d, Seq: %d)\n", 
                   parser.header.payload_len, parser.header.sequence);
            
            printf("Raw Decrypted Bytes: ");
            for(int j=0; j<parser.header.payload_len; j++) printf("%02X ", parser.payload[j]);
            printf("\n");
            
            // 5. Deserialize Payload
            ul_attitude_t att_in;
            ul_deserialize_attitude(&att_in, parser.payload);
            
            printf("\nDecoded Attitude Payload:\n");
            printf("  Roll:   %f\n  Pitch:  %f\n  Yaw:    %f\n", att_in.roll, att_in.pitch, att_in.yaw);
            printf("  RollSp: %f\n  PitchSp:%f\n  YawSp:  %f\n", att_in.rollspeed, att_in.pitchspeed, att_in.yawspeed);
            
        } else if (res < 0) {
            printf("PARSE ERROR: %d\n", res);
        }
    }

    return 0;
}
