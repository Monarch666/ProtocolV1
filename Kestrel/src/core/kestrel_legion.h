/*
 * =============================================================================
 *  KESTREL LEGION — Large-Scale Extension
 *  kestrel_legion.h
 *
 *  Sits alongside Kestrel Core v1.2.9 exactly the way kestrel_fast.h does —
 *  include both headers; Core is unchanged.
 *
 *  Purpose:
 *    Extend Kestrel Core to support up to 8,192 simultaneous devices by
 *    widening the address space, scaling the reassembly context, expanding
 *    the memory pool, and deepening the replay-protection window — all
 *    without touching a single byte of kestrel.c / kestrel.h.
 *
 *  What Legion adds over Core:
 *  ┌──────────────────────────────┬──────────────────┬──────────────────────┐
 *  │ Feature                      │ Core             │ Legion               │
 *  ├──────────────────────────────┼──────────────────┼──────────────────────┤
 *  │ Device address space         │ 6-bit  (64 max)  │ 13-bit (8,192 max)   │
 *  │ Target address width         │ 6-bit  (1 byte)  │ 13-bit (2 bytes LE)  │
 *  │ Concurrent reassembly slots  │ 4                │ 128                  │
 *  │ Memory pool buffers          │ 32  (16 KB)      │ 256 (128 KB)         │
 *  │ Replay window                │ 32-packet        │ 64-packet            │
 *  └──────────────────────────────┴──────────────────┴──────────────────────┘
 *
 *  Wire-format compatibility:
 *    Base header (4 bytes) — IDENTICAL to Core.
 *    Extended header routing word — DIFFERENT (grows by 3 bytes for the
 *    wider sys_id; 1 extra byte for target_sys_id on CMD/CMD_ACK streams).
 *    Legion endpoints cannot interoperate with Core endpoints on the wire
 *    without a gateway/bridge.  All-Legion networks are fully compatible.
 *
 *  Usage:
 *    #include "kestrel.h"          // Core types, unchanged
 *    #include "kestrel_legion.h"   // Legion extensions
 *
 *    // Use ksl_* functions and types for large-scale operation.
 *    // kestrel_* / ks_* Core functions still work for non-Legion traffic.
 *
 *  Prefix convention:
 *    ksl_   — Legion public API functions
 *    KSL_   — Legion macros / constants
 *    ksl_*_t — Legion-specific structs (parser, pool, reassembly ctx)
 *
 * =============================================================================
 */

#ifndef KESTREL_LEGION_H
#define KESTREL_LEGION_H

#include "kestrel.h"  /* Core types: ks_header_t, ks_session_t, etc. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * LEGION IDENTITY & LIMITS
 * ============================================================================= */

#define KSL_VARIANT_NAME    "Kestrel Legion"
#define KSL_VARIANT_VERSION "1.0.0"         /* First Legion release              */
#define KSL_BASED_ON_CORE   "1.2.9"         /* Core version this extends         */

#define KSL_MAX_NODES       8192u           /* 2^13 — maximum addressable nodes  */
#define KSL_ADDR_BITS       13u             /* Bits used for sys_id / target_sys  */
#define KSL_ADDR_MASK       0x1FFFu         /* 13-bit mask                        */
#define KSL_BROADCAST       0u              /* 0 = broadcast (same as Core)       */

/* =============================================================================
 * LEGION EXTENDED HEADER
 *
 * Core extended header routing layout (5 bytes for CMD, 4 for others):
 *   [0..1]  seq_sys  : seq[9:0](10) | sys_id(6)       — 2 bytes
 *   [2..3]  comp_msg : comp_id(4)   | msg_id(12)      — 2 bytes
 *   [4]     target_sys_id(6)        — 1 byte, CMD/CMD_ACK only
 *
 * Legion extended header routing layout (7 bytes for CMD, 5 for others):
 *   [0..1]  legion_sys_a : seq[9:3](7) | sys_id[12:8](5)  — 2 bytes
 *   [2..3]  legion_sys_b : sys_id[7:0](8) | seq[2:0](3) | comp_id[3:1](3) — not quite
 *
 * Simplified clean packing chosen for Legion (easier to implement & audit):
 *
 *   Byte 0:  seq[9:2]             (8 bits of the 10 lower sequence bits)
 *   Byte 1:  seq[1:0] | sys_id[12:7]    (2 + 6 = 8 bits)
 *   Byte 2:  sys_id[6:0] | comp_id[3]   (7 + 1 = 8 bits)
 *   Byte 3:  comp_id[2:0] | msg_id[11:8] (3 + 4 = 7... round to 8)
 *   Byte 4:  msg_id[7:0]          (8 bits)
 *   [CMD/CMD_ACK only:]
 *   Byte 5:  target_sys_id[7:0]   (low 8 bits)
 *   Byte 6:  target_sys_id[12:8]  (high 5 bits, LE)
 *
 * Total routing: 5 bytes (non-CMD) or 7 bytes (CMD/CMD_ACK)
 * vs Core:       4 bytes (non-CMD) or 5 bytes (CMD/CMD_ACK)
 * ============================================================================= */

#define KSL_EXT_HDR_ROUTING_BASE 5u   /* Routing bytes for non-CMD streams      */
#define KSL_EXT_HDR_ROUTING_CMD  7u   /* Routing bytes for CMD/CMD_ACK streams  */

/* =============================================================================
 * LEGION HEADER — mirrors ks_header_t but with wider address fields
 * ============================================================================= */

/**
 * Legion message header.
 * All fields identical to ks_header_t except sys_id and target_sys_id,
 * which are widened to 13 bits (uint16_t).
 */
typedef struct
{
    uint16_t payload_len; /* 12-bit payload length                      */
    uint8_t  priority;    /* 2-bit priority                             */
    uint8_t  stream_type; /* 4-bit stream type (KS_STREAM_*)            */
    bool     encrypted;   /* 1-bit encryption flag                      */
    bool     fragmented;  /* 1-bit fragmentation flag                   */
    uint16_t sequence;    /* 12-bit sequence number                     */

    /* Extended Header — Legion-specific widths */
    uint16_t sys_id;        /* 13-bit source system ID (0x0000–0x1FFF)  */
    uint8_t  comp_id;       /* 4-bit component ID (unchanged)           */
    uint16_t target_sys_id; /* 13-bit target system ID; 0 = broadcast   */
    uint16_t msg_id;        /* 12-bit message ID (unchanged)            */

    /* Fragmentation (unchanged) */
    uint8_t frag_index;
    uint8_t frag_total;

    /* Encryption nonce (unchanged) */
    uint8_t nonce[8];
} ksl_header_t;

/* =============================================================================
 * LEGION ZERO-COPY PARSER
 *
 * Extends the Core zerocopy parser design (ks_parser_zerocopy_t) with:
 *   - 13-bit sys_id / target_sys_id decoding in EXT_HDR state
 *   - uint64_t replay window (64-packet depth vs Core's 32)
 *   - Larger header_buf (34 bytes: 4 base + 7 routing + 8 nonce + 16 MAC + slack)
 * ============================================================================= */

typedef struct
{
    uint8_t  state;           /* Current parse state (0-5)               */
    uint16_t payload_len;     /* Expected payload length                  */
    uint16_t bytes_received;  /* Bytes received in current state          */

    uint8_t  header_buf[40];  /* Header scratch buffer (Legion: 40 bytes) */
    const uint8_t *input_ptr; /* Direct pointer to input (zero-copy)      */
    uint8_t *output_payload;  /* User-provided output buffer              */

    uint16_t msg_id;          /* Decoded message ID                       */
    uint8_t  stream_type;     /* Decoded stream type                      */
    uint8_t  cipher_nonce[8]; /* Nonce for decryption                     */
    uint8_t  cipher_tag[16];  /* Authentication tag                       */
    uint8_t *last_payload;    /* Pointer to most recently completed payload */

    bool     fragmented;      /* Raw fragmented bit from base header      */
    bool     out_fragmented;  /* Fragmented flag for last completed packet */
    uint32_t out_sequence;    /* 32-bit anti-replay seq for last completed packet */

    /* Legion: decoded 13-bit address fields for last completed packet */
    uint16_t out_sys_id;
    uint16_t out_target_sys_id;

    const uint8_t *key_32b;   /* 32-byte session key (NULL = unencrypted) */

    uint16_t crc_in;          /* Incoming CRC from packet                 */
    uint16_t crc_calc;        /* Calculated CRC for validation            */

    /* Replay protection — LEGION: uint64_t (64-packet window, was 32)
     * last_seq holds the 32-bit nonce counter for encrypted packets, or the
     * 12-bit wire sequence for unencrypted packets. */
    uint8_t  replay_init;
    uint32_t last_seq;        /* Highest accepted seq (nonce counter or 12-bit) */
    uint64_t replay_window;   /* KSL: widened from uint32_t               */

    /* Statistics */
    uint32_t rx_count;
    uint32_t error_count;
} ksl_parser_t;

/**
 * Initialise Legion zero-copy parser.
 */
void ksl_parser_init(ksl_parser_t *parser);

/**
 * Parse one byte of incoming stream.
 * @param parser       Legion parser state
 * @param byte         Incoming byte
 * @param output_buf   Caller-provided payload output buffer (min 512 bytes)
 * @param output_size  Size of output_buf
 * @return  1 on complete valid packet, 0 if still parsing, negative on error
 *
 * On return == 1, read decoded header fields from parser->out_* and
 * parser->last_payload.
 */
int ksl_parse_byte(ksl_parser_t *parser, uint8_t byte,
                   uint8_t *output_buf, size_t output_size);

/**
 * Check sequence number against the 64-packet sliding replay window.
 * Call AFTER MAC authentication.
 * @return 0 on success, KS_ERR_REPLAY if replay detected.
 */
int ksl_check_replay(ksl_parser_t *parser, uint32_t seq);

/**
 * Get link quality (0–100) based on rx_count vs error_count.
 */
uint8_t ksl_link_quality(const ksl_parser_t *parser);

/* =============================================================================
 * LEGION MEMORY POOL
 *
 * Core pool: 32 buffers × 512 B = 16 KB,  uint32_t free_mask (32 bits)
 * Legion pool: 256 buffers × 512 B = 128 KB, uint8_t free_mask[32] (256 bits)
 * ============================================================================= */

#define KSL_MEMPOOL_NUM_BUFFERS 256u  /* KSL: was 32 in Core              */
#define KSL_MEMPOOL_BUFFER_SIZE 512u  /* Unchanged: matches max packet     */

typedef struct
{
    uint8_t  buffers[KSL_MEMPOOL_NUM_BUFFERS][KSL_MEMPOOL_BUFFER_SIZE];

    /* KSL: 256-bit bitmap — 1 bit per buffer; 1 = free, 0 = allocated.
     * Stored as uint8_t[32]: 32 bytes × 8 bits = 256 bits.             */
    uint8_t  free_mask[32];

    /* Statistics */
    uint32_t alloc_count;
    uint32_t free_count;
    uint32_t peak_usage;
    uint32_t current_usage;
} ksl_mempool_t;

/**
 * Initialise Legion memory pool (all buffers free).
 */
void ksl_mempool_init(ksl_mempool_t *pool);

/**
 * Allocate one 512-byte buffer from the pool. O(1).
 * @return Pointer to buffer, or NULL if pool exhausted.
 */
void *ksl_mempool_alloc(ksl_mempool_t *pool);

/**
 * Return a buffer to the pool. O(1). Zeros the buffer on release.
 * Silently ignores double-free.
 */
void ksl_mempool_free(ksl_mempool_t *pool, void *ptr);

/**
 * Read pool statistics.
 */
void ksl_mempool_stats(const ksl_mempool_t *pool,
                       uint32_t *alloc_count, uint32_t *free_count,
                       uint32_t *peak_usage,  uint32_t *current_usage);

/* =============================================================================
 * LEGION REASSEMBLY CONTEXT
 *
 * Core:   4 concurrent reassembly slots, sys_id = uint8_t (6-bit)
 * Legion: 128 concurrent reassembly slots, sys_id = uint16_t (13-bit)
 * ============================================================================= */

#define KSL_REASSEMBLY_SLOTS     128u  /* KSL: was 4 in Core                */
#define KSL_FRAG_MAX_PAYLOAD     256u  
#define KSL_FRAG_MAX_FRAGMENTS   16u   
#define KSL_FRAG_MAX_TOTAL       4096u 
#define KSL_FRAG_TIMEOUT_MS      5000u 

typedef struct
{
    bool     active;
    uint16_t msg_id;
    uint16_t sys_id;          /* KSL: widened from uint8_t to uint16_t    */
    uint8_t  frag_total;
    bool     received[KSL_FRAG_MAX_FRAGMENTS];
    uint8_t  data[KSL_FRAG_MAX_TOTAL];
    uint16_t frag_lens[KSL_FRAG_MAX_FRAGMENTS];
    uint8_t  frags_received;
    uint32_t start_time_ms;
} ksl_reassembly_slot_t;

typedef struct
{
    ksl_reassembly_slot_t slots[KSL_REASSEMBLY_SLOTS]; /* KSL: was 4      */
} ksl_reassembly_ctx_t;

/**
 * Initialise Legion reassembly context (clears all 128 slots).
 */
void ksl_reassembly_init(ksl_reassembly_ctx_t *ctx);

/**
 * Add a received fragment. Evicts timed-out slots before inserting.
 * @param ctx         Reassembly context
 * @param hdr         Legion header of the received fragment
 * @param payload     Fragment payload bytes
 * @param payload_len Length of fragment payload
 * @param output      Buffer to receive the reassembled message (min 4096 bytes)
 * @param output_len  Receives total reassembled length on success
 * @param now_ms      Current time in milliseconds (for timeout eviction)
 * @return  1 if message is complete (output is valid),
 *          0 if more fragments needed,
 *         -1 on error (bad args, no free slot, oversized fragment)
 */
int ksl_reassembly_add(ksl_reassembly_ctx_t *ctx,
                       const ksl_header_t *hdr,
                       const uint8_t *payload, uint16_t payload_len,
                       uint8_t *output, uint16_t *output_len,
                       uint32_t now_ms);

/* =============================================================================
 * LEGION PACK / ENCODE
 * ============================================================================= */

/**
 * Encode a Legion extended header into buf.
 * Handles the 13-bit sys_id / target_sys_id wire format.
 *
 * Wire layout produced (see top-of-file comment for full breakdown):
 *   5 bytes for all streams, +2 bytes for CMD/CMD_ACK (target address).
 *   +8 bytes for encrypted packets (nonce).
 *   +2 bytes for fragmented packets (frag_index, frag_total).
 *
 * @param buf  Output buffer (must have space for up to 17 bytes)
 * @param h    Legion header to encode
 * @return Number of bytes written, or negative on error.
 */
int ksl_encode_ext_header(uint8_t *buf, const ksl_header_t *h);

/**
 * Decode a Legion extended header from buf into h.
 * @param buf  Input buffer
 * @param h    Output header (base fields must already be decoded)
 * @return Number of bytes consumed, or negative on error.
 */
int ksl_decode_ext_header(const uint8_t *buf, ksl_header_t *h);

/**
 * Pack a complete Legion packet (base header + Legion ext header + payload + CRC).
 * Uses kestrel_pack_with_nonce() semantics: NULL session = unencrypted.
 *
 * @param buf      Output buffer (must be >= payload_len + 30 bytes)
 * @param h        Legion header
 * @param payload  Payload bytes
 * @param session  Crypto session (NULL for unencrypted)
 * @return Total packed length, or negative on error.
 */
int ksl_pack(uint8_t *buf, const ksl_header_t *h,
             const uint8_t *payload, ks_session_t *session);

/* =============================================================================
 * LEGION COMBINED FAST API
 * (mirrors ks_pack_fast / ks_parse_char_fast from kestrel_fast.h)
 * ============================================================================= */

/**
 * Fast Legion pack: pool-allocated output buffer + Legion wire format.
 * Caller must free *buffer with ksl_mempool_free() when done.
 *
 * @param pool     Legion memory pool
 * @param h        Legion header
 * @param payload  Payload data
 * @param session  Crypto session (NULL = unencrypted)
 * @param buffer   OUT: pointer to allocated buffer
 * @return Number of bytes packed, or negative error code.
 */
int ksl_pack_fast(ksl_mempool_t *pool, const ksl_header_t *h,
                  const uint8_t *payload, ks_session_t *session,
                  uint8_t **buffer);

/**
 * Fast Legion parse: feed one byte to the zero-copy parser with
 * pool-backed output buffers.  On return == 1, parser->last_payload
 * holds the payload; call ksl_mempool_free() on it when done.
 *
 * @param parser Legion parser
 * @param byte   Input byte
 * @param pool   Legion memory pool
 * @return 1 on complete packet, 0 if incomplete, negative on error.
 */
int ksl_parse_fast(ksl_parser_t *parser, uint8_t byte, ksl_mempool_t *pool);

/* =============================================================================
 * LEGION STATISTICS
 * ============================================================================= */

typedef struct
{
    /* Parser */
    uint32_t rx_count;
    uint32_t error_count;
    uint8_t  link_quality;   /* 0–100 */

    /* Pool */
    uint32_t pool_alloc_count;
    uint32_t pool_free_count;
    uint32_t pool_peak_usage;
    uint32_t pool_current_usage;

    /* Reassembly */
    uint32_t reassembly_completed;
    uint32_t reassembly_timeouts;
    uint32_t reassembly_slot_full;
} ksl_stats_t;

/**
 * Gather combined statistics from a parser + pool.
 */
void ksl_get_stats(const ksl_parser_t *parser,
                   const ksl_mempool_t *pool,
                   ksl_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* KESTREL_LEGION_H */
