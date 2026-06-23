#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "kestrel_legion.h"

int test_address_space() {
    ksl_header_t hdr = {0};
    hdr.payload_len = 10;
    hdr.priority = 1;
    hdr.stream_type = KS_STREAM_CMD;
    hdr.encrypted = false;
    hdr.fragmented = false;
    hdr.sequence = 1234;
    
    // Test Max Address limits
    hdr.sys_id = 8191;       // 13-bit max
    hdr.comp_id = 15;        // 4-bit max
    hdr.target_sys_id = 8190;
    hdr.msg_id = 4095;       // 12-bit max
    
    uint8_t payload[10] = "TEST_DATA";
    uint8_t buffer[256];
    int len = ksl_pack(buffer, &hdr, payload, NULL);
    assert(len > 0);
    
    ksl_parser_t parser;
    memset(&parser, 0, sizeof(parser));
    ksl_parser_init(&parser);
    
    uint8_t output[256];
    int parse_res = 0;
    for (int i = 0; i < len; i++) {
        parse_res = ksl_parse_byte(&parser, buffer[i], output, sizeof(output));
        if (parse_res < 0) {
            printf("Error: ksl_parse_byte returned %d at byte %d\n", parse_res, i);
            break;
        }
        if (parse_res == 1) break;
    }

    if (parse_res != 1) {
        fprintf(stderr, "DEBUG: len = %d, parser state = %d, bytes_received = %d, parse_res = %d\n", len, parser.state, parser.bytes_received, parse_res);
    }
    if (parser.out_sys_id != hdr.sys_id) {
        fprintf(stderr, "FAIL sys_id: expected %d, got %d\n", hdr.sys_id, parser.out_sys_id);
    }
    if (parser.out_target_sys_id != hdr.target_sys_id) {
        fprintf(stderr, "FAIL target_sys_id: expected %d, got %d\n", hdr.target_sys_id, parser.out_target_sys_id);
    }
    if (parser.msg_id != hdr.msg_id) {
        fprintf(stderr, "FAIL msg_id: expected %d, got %d\n", hdr.msg_id, parser.msg_id);
    }
    if (parser.out_sequence != hdr.sequence) {
        fprintf(stderr, "FAIL sequence: expected %d, got %d\n", hdr.sequence, parser.out_sequence);
    }
    assert(parser.out_sys_id == hdr.sys_id);
    assert(parser.out_target_sys_id == hdr.target_sys_id);
    assert(parser.msg_id == hdr.msg_id);
    assert(parser.out_sequence == hdr.sequence);
    assert(memcmp(parser.last_payload, payload, hdr.payload_len) == 0);
    
    return 1;
}

int test_mempool() {
    ksl_mempool_t pool;
    ksl_mempool_init(&pool);
    
    void* pointers[KSL_MEMPOOL_NUM_BUFFERS];
    for (int i = 0; i < KSL_MEMPOOL_NUM_BUFFERS; i++) {
        pointers[i] = ksl_mempool_alloc(&pool);
        assert(pointers[i] != NULL);
    }
    
    void* extra = ksl_mempool_alloc(&pool);
    assert(extra == NULL); // Pool exactly exhausted
    
    for (int i = 0; i < KSL_MEMPOOL_NUM_BUFFERS; i++) {
        ksl_mempool_free(&pool, pointers[i]);
    }
    
    assert(pool.free_count == KSL_MEMPOOL_NUM_BUFFERS);
    return 1;
}

int test_replay_window() {
    ksl_parser_t p;
    memset(&p, 0, sizeof(p));
    ksl_parser_init(&p);
    
    assert(ksl_check_replay(&p, 100) == KS_OK);
    assert(ksl_check_replay(&p, 101) == KS_OK);
    // Deep replay within 64 packets
    assert(ksl_check_replay(&p, 100) == KS_ERR_REPLAY);
    assert(ksl_check_replay(&p, 30) == KS_ERR_REPLAY); // beyond 64 packets (101-30=71)
    
    // Advance window
    assert(ksl_check_replay(&p, 150) == KS_OK);
    // Legitimate old packet within the 64-packet window (150 - 63 = 87)
    assert(ksl_check_replay(&p, 102) == KS_OK);
    assert(ksl_check_replay(&p, 102) == KS_ERR_REPLAY); // already replayed
    
    return 1;
}

int main() {
    printf("Starting Kestrel Legion tests...\n");
    if (test_address_space()) printf("test_address_space... PASS\n");
    if (test_mempool())       printf("test_mempool...       PASS\n");
    if (test_replay_window()) printf("test_replay_window... PASS\n");
    printf("\nAll Kestrel Legion tests PASSED!\n");
    return 0;
}
