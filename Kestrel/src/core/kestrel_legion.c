/*
 * =============================================================================
 *  KESTREL LEGION — Implementation
 *  kestrel_legion.c
 *
 *  This file adds Legion-specific structs and functions (ksl_* prefix) alongside 
 *  Core's ks_* functions.
 *
 *  Build alongside Core:
 *  gcc kestrel.c kestrel_legion.c monocypher.c ... -o your_app
 * =============================================================================
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "kestrel_legion.h"
#include "kestrel.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* =============================================================================
 * INTERNAL BITMAP HELPERS (256-bit free_mask for 256-buffer pool)
 * ============================================================================= */

static inline void bmap_set(uint8_t mask[32], int idx)
{
    mask[idx >> 3] |= (uint8_t)(1u << (idx & 7));
}

static inline void bmap_clear(uint8_t mask[32], int idx)
{
    mask[idx >> 3] &= (uint8_t)(~(1u << (idx & 7)));
}

static inline int bmap_test(const uint8_t mask[32], int idx)
{
    return (mask[idx >> 3] >> (idx & 7)) & 1;
}

/* Find first set bit (first free buffer). Returns -1 if none. */
static int bmap_ffs(const uint8_t mask[32])
{
    for (int b = 0; b < 32; b++) {
        if (mask[b]) {
#ifdef _MSC_VER
            unsigned long bit;
            _BitScanForward(&bit, mask[b]);
            return b * 8 + (int)bit;
#else
            return b * 8 + (__builtin_ffs((int)(unsigned int)mask[b]) - 1);
#endif
        }
    }
    return -1;
}

static int bmap_empty(const uint8_t mask[32])
{
    for (int b = 0; b < 32; b++)
        if (mask[b]) return 0;
    return 1;
}

/* =============================================================================
 * LEGION MEMORY POOL
 * ============================================================================= */

void ksl_mempool_init(ksl_mempool_t *pool)
{
    if (!pool) return;
    memset(pool, 0, sizeof(ksl_mempool_t));
    /* All 256 bits set: every buffer starts free. */
    memset(pool->free_mask, 0xFF, sizeof(pool->free_mask));
}

void *ksl_mempool_alloc(ksl_mempool_t *pool)
{
    if (!pool || bmap_empty(pool->free_mask))
        return NULL;

    int index = bmap_ffs(pool->free_mask);
    if (index < 0 || index >= (int)KSL_MEMPOOL_NUM_BUFFERS)
        return NULL;

    bmap_clear(pool->free_mask, index);

    pool->alloc_count++;
    pool->current_usage++;
    if (pool->current_usage > pool->peak_usage)
        pool->peak_usage = pool->current_usage;

    return pool->buffers[index];
}

void ksl_mempool_free(ksl_mempool_t *pool, void *ptr)
{
    if (!pool || !ptr) return;

    uintptr_t pool_start = (uintptr_t)pool->buffers;
    uintptr_t ptr_addr   = (uintptr_t)ptr;

    if (ptr_addr < pool_start ||
        ptr_addr >= pool_start + ((uintptr_t)KSL_MEMPOOL_NUM_BUFFERS * KSL_MEMPOOL_BUFFER_SIZE) ||
        ((ptr_addr - pool_start) % KSL_MEMPOOL_BUFFER_SIZE) != 0)
        return; /* Not a valid pool buffer pointer */

    size_t index = (ptr_addr - pool_start) / KSL_MEMPOOL_BUFFER_SIZE;
    if (index >= KSL_MEMPOOL_NUM_BUFFERS) return;

    /* Double-free guard */
    if (bmap_test(pool->free_mask, (int)index)) return;

    bmap_set(pool->free_mask, (int)index);

    /* Zero on release: prevent plaintext / key material from lingering */
    memset(pool->buffers[index], 0, KSL_MEMPOOL_BUFFER_SIZE);

    pool->free_count++;
    if (pool->current_usage > 0)
        pool->current_usage--;
}

void ksl_mempool_stats(const ksl_mempool_t *pool,
                       uint32_t *alloc_count, uint32_t *free_count,
                       uint32_t *peak_usage,  uint32_t *current_usage)
{
    if (!pool) return;
    if (alloc_count)   *alloc_count   = pool->alloc_count;
    if (free_count)    *free_count    = pool->free_count;
    if (peak_usage)    *peak_usage    = pool->peak_usage;
    if (current_usage) *current_usage = pool->current_usage;
}

/* =============================================================================
 * LEGION HEADER ENCODE / DECODE
 *
 * Wire layout for the Legion extended routing section:
 *
 *   Byte 0: seq[9:2]                    — upper 8 bits of the 10-bit lower seq
 *   Byte 1: seq[1:0] | sys_id[12:7]     — 2 bits seq + 6 high bits of 13-bit ID
 *   Byte 2: sys_id[6:0] | comp_id[3]    — 7 low bits of ID + high bit of comp_id
 *   Byte 3: comp_id[2:0] | msg_id[11:8] — low 3 bits comp_id + high 4 of msg_id
 *   Byte 4: msg_id[7:0]                 — low 8 bits of msg_id
 *   [CMD/CMD_ACK only:]
 *   Byte 5: target_sys_id[7:0]          — low byte of 13-bit target
 *   Byte 6: target_sys_id[12:8]         — high 5 bits of 13-bit target
 *   [fragmented flag set:]
 *   Byte +0: frag_index
 *   Byte +1: frag_total
 *   [encrypted flag set:]
 *   Byte +0 .. +7: nonce (8 bytes)
 *
 * Note: The base header's top-of-sequence bits (seq[11:10]) are encoded in
 * byte 3 of the base header exactly as in Core (KS_SEQ_HI_MASK).
 * Legion carries seq[9:0] in routing bytes 0-1.
 * ============================================================================= */

int ksl_encode_ext_header(uint8_t *buf, const ksl_header_t *h)
{
    if (!buf || !h) return KS_ERR_NULL_POINTER;

    int offset = 0;

    /* seq[9:2] — upper 8 bits of the lower 10 sequence bits */
    buf[offset++] = (uint8_t)((h->sequence >> 2) & 0xFF);

    /* seq[1:0] | sys_id[12:7] */
    buf[offset++] = (uint8_t)(((h->sequence & 0x3) << 6) | ((h->sys_id >> 7) & 0x3F));

    /* sys_id[6:0] | comp_id[3] */
    buf[offset++] = (uint8_t)(((h->sys_id & 0x7F) << 1) | ((h->comp_id >> 3) & 0x1));

    /* comp_id[2:0] | msg_id[11:8] */
    buf[offset++] = (uint8_t)(((h->comp_id & 0x7) << 5) | ((h->msg_id >> 8) & 0x0F));

    /* msg_id[7:0] */
    buf[offset++] = (uint8_t)(h->msg_id & 0xFF);

    /* CMD/CMD_ACK: 13-bit target_sys_id, little-endian 2 bytes */
    if (h->stream_type == KS_STREAM_CMD || h->stream_type == KS_STREAM_CMD_ACK)
    {
        buf[offset++] = (uint8_t)(h->target_sys_id & 0xFF);
        buf[offset++] = (uint8_t)((h->target_sys_id >> 8) & 0x1F);
    }

    /* Fragmentation info */
    if (h->fragmented)
    {
        buf[offset++] = h->frag_index;
        buf[offset++] = h->frag_total;
    }

    /* Nonce */
    if (h->encrypted)
    {
        memcpy(&buf[offset], h->nonce, 8);
        offset += 8;
    }

    return offset;
}

int ksl_decode_ext_header(const uint8_t *buf, ksl_header_t *h)
{
    if (!buf || !h) return KS_ERR_NULL_POINTER;

    int offset = 0;

    /* Byte 0: seq[9:2] */
    uint16_t seq_low = (uint16_t)((uint16_t)buf[offset++] << 2);

    /* Byte 1: seq[1:0] | sys_id[12:7] */
    uint8_t b1 = buf[offset++];
    seq_low |= (uint16_t)((b1 >> 6) & 0x3);
    h->sys_id = (uint16_t)((b1 & 0x3F) << 7);

    /* Byte 2: sys_id[6:0] | comp_id[3] */
    uint8_t b2 = buf[offset++];
    h->sys_id |= (uint16_t)((b2 >> 1) & 0x7F);
    h->comp_id = (uint8_t)((b2 & 0x1) << 3);

    /* Byte 3: comp_id[2:0] | msg_id[11:8] */
    uint8_t b3 = buf[offset++];
    h->comp_id |= (uint8_t)((b3 >> 5) & 0x7);
    h->msg_id   = (uint16_t)((b3 & 0x0F) << 8);

    /* Byte 4: msg_id[7:0] */
    h->msg_id |= (uint16_t)buf[offset++];

    /* Merge seq_low with the top 2 bits already set by base header decode.
     * Base header sets h->sequence = seq[11:10] << 10.
     * Legion routing carries seq[9:0]; OR them together. */
    h->sequence |= seq_low & 0x3FF;

    /* CMD/CMD_ACK: 2-byte LE target_sys_id */
    if (h->stream_type == KS_STREAM_CMD || h->stream_type == KS_STREAM_CMD_ACK)
    {
        uint8_t tlo = buf[offset++];
        uint8_t thi = buf[offset++];
        h->target_sys_id = (uint16_t)(tlo | ((uint16_t)(thi & 0x1F) << 8));
    }
    else
    {
        h->target_sys_id = KSL_BROADCAST;
    }

    /* Fragmentation */
    if (h->fragmented)
    {
        h->frag_index = buf[offset++];
        h->frag_total = buf[offset++];
    }

    /* Nonce */
    if (h->encrypted)
    {
        memcpy(h->nonce, &buf[offset], 8);
        offset += 8;
    }

    return offset;
}

/* =============================================================================
 * LEGION PACK
 * ============================================================================= */

int ksl_pack(uint8_t *buf, const ksl_header_t *h,
             const uint8_t *payload, ks_session_t *session)
{
    if (!buf || !h) return KS_ERR_NULL_POINTER;
    if (session && !session->initialized) return KS_ERR_NO_KEY;
    if (h->payload_len > KS_MAX_PAYLOAD_SIZE) return KS_ERR_BUFFER_OVERFLOW;

    /* -----------------------------------------------------------
     * Build a ks_header_t shim so we can reuse Core's
     * ks_encode_base_header().  Only the base-4-byte fields are
     * used by that function (payload_len, priority, stream_type,
     * encrypted, fragmented, sequence) — which are identical in
     * both header types.
     * ----------------------------------------------------------- */
    ks_header_t core_hdr;
    memset(&core_hdr, 0, sizeof(core_hdr));
    core_hdr.payload_len  = h->payload_len;
    core_hdr.priority     = h->priority;
    core_hdr.stream_type  = h->stream_type;
    core_hdr.encrypted    = h->encrypted && (session != NULL);
    core_hdr.fragmented   = h->fragmented;
    core_hdr.sequence     = h->sequence;

    int offset = 0;



    /* Base header (4 bytes from Core — unchanged format, includes SOF) */
    ks_encode_base_header(&buf[offset], &core_hdr);
    offset += 4;

    /* Legion extended header */
    /* Pass a local copy with encrypted flag reflecting actual encryption state */
    ksl_header_t hdr_enc = *h;
    hdr_enc.encrypted = core_hdr.encrypted;

    int ext_len = ksl_encode_ext_header(&buf[offset], &hdr_enc);
    if (ext_len < 0) return ext_len;
    offset += ext_len;

    /* Payload */
    if (payload && h->payload_len > 0)
    {
        if (core_hdr.encrypted)
        {
            /* Generate nonce, encrypt payload inline, append MAC */
            uint8_t nonce[8];
            ks_nonce_generate(&session->nonce_state, nonce);

            /* AEAD: header bytes 1..(offset-1) are associated data */
            /* Use monocypher via kestrel's internal include path.
             * We call crypto_aead_lock directly — same as Core does. */
            extern void crypto_aead_lock(uint8_t *cipher_text, uint8_t mac[16],
                                         const uint8_t key[32], const uint8_t nonce_24[24],
                                         const uint8_t *ad, size_t ad_size,
                                         const uint8_t *plain_text, size_t text_size);

            /* Monocypher uses a 24-byte nonce; Legion uses 8 bytes.
             * Expand: place the 8-byte nonce at bytes [0..7], zero-pad [8..23]. */
            uint8_t nonce24[24];
            memset(nonce24, 0, 24);
            memcpy(nonce24, nonce, 8);

            uint8_t mac[16];
            crypto_aead_lock(&buf[offset], mac,
                             session->key, nonce24,
                             &buf[1], (size_t)(offset - 1), /* AD: everything after SOF */
                             payload, h->payload_len);
            offset += h->payload_len;

            /* Append MAC tag */
            memcpy(&buf[offset], mac, 16);
            offset += 16;
        }
        else
        {
            memcpy(&buf[offset], payload, h->payload_len);
            offset += h->payload_len;
        }
    }

    /* CRC-16 over bytes [1..offset-1] (skip SOF) */
    uint16_t crc;
    ks_crc_init(&crc);
    for (int i = 1; i < offset; i++)
        ks_crc_accumulate(buf[i], &crc);

    buf[offset++] = (uint8_t)(crc & 0xFF);
    buf[offset++] = (uint8_t)((crc >> 8) & 0xFF);

    return offset;
}

/* =============================================================================
 * LEGION ZERO-COPY PARSER
 * ============================================================================= */

void ksl_parser_init(ksl_parser_t *parser)
{
    if (!parser) return;
    parser->state          = 0;
    parser->payload_len    = 0;
    parser->bytes_received = 0;
    parser->msg_id         = 0;
    parser->stream_type    = 0;
    parser->fragmented     = false;
    parser->output_payload = NULL;
    parser->last_payload   = NULL;
    parser->crc_in         = 0;
    parser->crc_calc       = 0;
    /* Do NOT reset: key_32b, rx_count, error_count, replay_* */
}

uint8_t ksl_link_quality(const ksl_parser_t *p)
{
    if (!p) return 0;
    uint32_t total = p->rx_count + p->error_count;
    if (total == 0) return 100;
    return (uint8_t)(((uint64_t)p->rx_count * 100u) / total);
}

int ksl_check_replay(ksl_parser_t *p, uint32_t seq)
{
    if (!p) return KS_ERR_NULL_POINTER;

    if (p->replay_init)
    {
        int32_t diff = (int32_t)(seq - p->last_seq);

        if (diff <= 0)
        {
            int32_t back = -diff;
            /* Legion: 64-packet window */
            if (back >= 64 || (p->replay_window & (1ULL << (uint8_t)back)))
            {
                p->error_count++;
                return KS_ERR_REPLAY;
            }
            p->replay_window |= (1ULL << (uint8_t)back);
        }
        else
        {
            uint32_t shift = (uint32_t)diff;
            p->replay_window = (shift >= 64) ? 0ULL : (p->replay_window << shift);
            p->replay_window |= 1ULL;
            p->last_seq = seq;
        }
    }
    else
    {
        p->replay_init   = 1;
        p->last_seq      = seq;
        p->replay_window = 1ULL;
    }

    p->rx_count++;
    return KS_OK;
}

int ksl_parse_byte(ksl_parser_t *parser, uint8_t byte,
                   uint8_t *output_buf, size_t output_size)
{
    if (!parser || !output_buf) return KS_ERR_NULL_POINTER;

    switch (parser->state)
    {
    /* ---- State 0: IDLE — hunt for SOF ---- */
    case 0:
        if (byte == KS_SOF)
        {
            memset(parser->header_buf, 0, sizeof(parser->header_buf));
            parser->header_buf[0] = byte;
            parser->state         = 1;
            parser->bytes_received = 1;
        }
        break;

    /* ---- State 1: BASE HEADER (4 bytes including SOF) ---- */
    case 1:
        parser->header_buf[parser->bytes_received++] = byte;

        if (parser->bytes_received >= 4)
        {
            uint8_t b1 = parser->header_buf[1];
            uint8_t b2 = parser->header_buf[2];
            uint8_t b3 = parser->header_buf[3];

            parser->payload_len =
                (uint16_t)(((b1 & 0xF0) << 4) | ((b2 & 0x3F) << 2) | ((b3 & 0xC0) >> 6));

            if (parser->payload_len > KS_MAX_PAYLOAD_SIZE)
            {
                parser->state = 0;
                parser->error_count++;
                return KS_ERR_BUFFER_OVERFLOW;
            }

            parser->fragmented  = (b3 & KS_FLAG_FRAGMENTED) != 0;
            parser->stream_type = (uint8_t)(((b1 & 0x3) << 2) | ((b2 >> 6) & 0x3));
            parser->state       = 2; /* → EXT_HDR */
        }
        break;

    /* ---- State 2: LEGION EXTENDED HEADER ---- */
    case 2:
        parser->header_buf[parser->bytes_received++] = byte;

        {
            bool is_cmd = (parser->stream_type == KS_STREAM_CMD ||
                           parser->stream_type == KS_STREAM_CMD_ACK);
            bool encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
            bool fragmented = parser->fragmented;

            /* Routing section size:
             *   5 bytes (non-CMD) or 7 bytes (CMD/CMD_ACK)
             *   base offset 4 (we're still counting from header_buf[0]) */
            uint16_t routing_end = (uint16_t)(4u + (is_cmd ? KSL_EXT_HDR_ROUTING_CMD
                                                           : KSL_EXT_HDR_ROUTING_BASE));

            /* Decode msg_id once we have all 5 routing bytes (bytes 4-8) */
            if (parser->bytes_received == (4u + 5u))
            {
                /* Bytes [4..8] are the 5 routing bytes.
                 * msg_id is in bytes 3 (high nibble) and 4 (low byte) of routing. */
                uint8_t r3 = parser->header_buf[7]; /* routing byte 3 */
                uint8_t r4 = parser->header_buf[8]; /* routing byte 4 */
                parser->msg_id = (uint16_t)(((r3 & 0x0F) << 8) | r4);
            }

            uint16_t frag_end = routing_end + (fragmented ? 2u : 0u);
            uint16_t nonce_end = frag_end + (encrypted ? 8u : 0u);

            if (encrypted)
            {
                if (parser->bytes_received == nonce_end)
                {
                    /* Extract nonce from header_buf[frag_end..frag_end+7] */
                    memcpy(parser->cipher_nonce, &parser->header_buf[frag_end], 8);
                    parser->state          = 3; /* → PAYLOAD */
                    parser->bytes_received = 0;
                }
            }
            else
            {
                if (parser->bytes_received >= frag_end)
                {
                    parser->state = (parser->payload_len == 0) ? 4 : 3;
                    parser->bytes_received = 0;
                }
            }
        }
        break;

    /* ---- State 3: PAYLOAD ---- */
    case 3:
        if (parser->bytes_received < parser->payload_len)
        {
            if (parser->bytes_received >= output_size)
            {
                parser->state = 0;
                parser->error_count++;
                return KS_ERR_BUFFER_OVERFLOW;
            }
            output_buf[parser->bytes_received] = byte;
            parser->bytes_received++;

            if (parser->bytes_received >= parser->payload_len)
            {
                bool encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
                parser->state          = encrypted ? 5 : 4; /* MAC or CRC */
                parser->bytes_received = 0;
            }
        }
        break;

    /* ---- State 5: MAC TAG (16 bytes, encrypted packets only) ---- */
    case 5:
        parser->cipher_tag[parser->bytes_received++] = byte;
        if (parser->bytes_received >= 16)
        {
            parser->state          = 4; /* → CRC */
            parser->bytes_received = 0;
        }
        break;

    /* ---- State 4: CRC (2 bytes, little-endian) ---- */
    case 4:
        if (parser->bytes_received == 0)
            parser->crc_in = byte;
        else
            parser->crc_in |= (uint16_t)((uint16_t)byte << 8);

        parser->bytes_received++;

        if (parser->bytes_received >= 2)
        {
            /* Reconstruct CRC header length for this Legion packet */
            bool crc_encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
            bool crc_cmd       = (parser->stream_type == KS_STREAM_CMD ||
                                  parser->stream_type == KS_STREAM_CMD_ACK);
            bool crc_frag      = parser->fragmented;

            uint16_t routing = (uint16_t)(crc_cmd ? KSL_EXT_HDR_ROUTING_CMD
                                                   : KSL_EXT_HDR_ROUTING_BASE);
            uint16_t frag_b  = crc_frag ? 2u : 0u;
            uint16_t nonce_b = crc_encrypted ? 8u : 0u;
            int crc_hdr_len  = (int)(4 + routing + frag_b + nonce_b);

            ks_crc_init(&parser->crc_calc);

            /* Hash header bytes [1..crc_hdr_len-1] (skip SOF at [0]) */
            for (int i = 1; i < crc_hdr_len; i++)
                ks_crc_accumulate(parser->header_buf[i], &parser->crc_calc);

            /* Hash payload */
            for (int i = 0; i < (int)parser->payload_len; i++)
                ks_crc_accumulate(output_buf[i], &parser->crc_calc);

            /* For encrypted packets, also hash the 16-byte MAC */
            if (crc_encrypted)
                for (int i = 0; i < 16; i++)
                    ks_crc_accumulate(parser->cipher_tag[i], &parser->crc_calc);

            if (parser->crc_calc != parser->crc_in)
            {
                ksl_parser_init(parser);
                parser->error_count++;
                return KS_ERR_CRC;
            }

            /* ---- Decrypt if needed ---- */
            if (crc_encrypted)
            {
                if (!parser->key_32b)
                {
                    ksl_parser_init(parser);
                    parser->error_count++;
                    return KS_ERR_NO_KEY;
                }

                extern int crypto_aead_unlock(uint8_t *plain_text,
                                              const uint8_t mac[16],
                                              const uint8_t key[32],
                                              const uint8_t nonce_24[24],
                                              const uint8_t *ad, size_t ad_size,
                                              const uint8_t *cipher_text, size_t text_size);

                uint8_t nonce24[24];
                memset(nonce24, 0, 24);
                memcpy(nonce24, parser->cipher_nonce, 8);

                int crc_ad_len = crc_hdr_len - 1; /* AD = header bytes [1..end] */
                uint8_t decrypted[KS_MAX_PAYLOAD_SIZE];

                int rc = crypto_aead_unlock(decrypted,
                                            parser->cipher_tag,
                                            parser->key_32b,
                                            nonce24,
                                            &parser->header_buf[1], (size_t)crc_ad_len,
                                            output_buf, parser->payload_len);
                if (rc != 0)
                {
                    ksl_parser_init(parser);
                    parser->error_count++;
                    return KS_ERR_MAC_VERIFICATION;
                }
                memcpy(output_buf, decrypted, parser->payload_len);
            }

            /* ---- Replay protection (64-packet window) ---- */
            /* Extract seq[11:10] from base header byte 3, seq[9:0] from routing */
            uint16_t seq = (uint16_t)((parser->header_buf[3] & KS_SEQ_HI_MASK) << 10);
            /* routing bytes start at header_buf[4]; byte 0 = seq[9:2], byte 1 bits[7:6] = seq[1:0] */
            seq |= (uint16_t)((parser->header_buf[4] << 2) & 0x3FC);
            seq |= (uint16_t)((parser->header_buf[5] >> 6) & 0x3);

            uint32_t replay_seq;
            if (crc_encrypted)
            {
                replay_seq = (uint32_t)parser->cipher_nonce[0]
                           | ((uint32_t)parser->cipher_nonce[1] << 8)
                           | ((uint32_t)parser->cipher_nonce[2] << 16)
                           | ((uint32_t)parser->cipher_nonce[3] << 24);
            }
            else
            {
                replay_seq = (uint32_t)seq;
            }

            int replay_rc = ksl_check_replay(parser, replay_seq);
            if (replay_rc != KS_OK)
            {
                ksl_parser_init(parser);
                return replay_rc;
            }

            /* ---- Decode Legion address fields for caller ---- */
            uint8_t b1 = parser->header_buf[5]; /* routing byte 1 */
            uint8_t b2 = parser->header_buf[6]; /* routing byte 2 */
            parser->out_sys_id = (uint16_t)(((b1 & 0x3F) << 7) | ((b2 >> 1) & 0x7F));

            if (crc_cmd)
            {
                uint8_t tlo = parser->header_buf[4 + 5]; /* routing byte 5 */
                uint8_t thi = parser->header_buf[4 + 6]; /* routing byte 6 */
                parser->out_target_sys_id =
                    (uint16_t)(tlo | ((uint16_t)(thi & 0x1F) << 8));
            }
            else
            {
                parser->out_target_sys_id = KSL_BROADCAST;
            }

            parser->out_fragmented = parser->fragmented;
            parser->out_sequence   = replay_seq;
            parser->last_payload   = output_buf;

            parser->state          = 0;
            parser->bytes_received = 0;
            /* rx_count already incremented by ksl_check_replay() */
            return 1; /* Complete packet */
        }
        break;

    default:
        parser->state = 0;
        return -1;
    }

    return 0; /* Still parsing */
}

/* =============================================================================
 * LEGION FAST COMBINED API
 * ============================================================================= */

int ksl_pack_fast(ksl_mempool_t *pool, const ksl_header_t *h,
                  const uint8_t *payload, ks_session_t *session,
                  uint8_t **buffer)
{
    if (!pool || !h || !buffer) return KS_ERR_NULL_POINTER;

    *buffer = (uint8_t *)ksl_mempool_alloc(pool);
    if (!*buffer) return -1; /* Pool exhausted */

    int result = ksl_pack(*buffer, h, payload, session);
    if (result < 0)
    {
        ksl_mempool_free(pool, *buffer);
        *buffer = NULL;
    }
    return result;
}

int ksl_parse_fast(ksl_parser_t *parser, uint8_t byte, ksl_mempool_t *pool)
{
    if (!parser || !pool) return KS_ERR_NULL_POINTER;

    /* Allocate output buffer on first byte of a new packet (state 0 → 1) */
    if (parser->state == 0 || parser->output_payload == NULL)
    {
        if (parser->last_payload)
        {
            ksl_mempool_free(pool, parser->last_payload);
            parser->last_payload = NULL;
        }
        if (byte == KS_SOF)
        {
            parser->output_payload = (uint8_t *)ksl_mempool_alloc(pool);
            if (!parser->output_payload)
                return -2; /* Pool exhausted */
        }
        else
        {
            return 0; /* Not SOF, stay idle */
        }
    }

    int result = ksl_parse_byte(parser, byte,
                                parser->output_payload, KSL_MEMPOOL_BUFFER_SIZE);

    if (result == 1)
    {
        /* Complete — save pointer for caller; clear working ptr */
        parser->last_payload   = parser->output_payload;
        parser->output_payload = NULL;
    }
    else if (result < 0)
    {
        /* Error — release buffer */
        if (parser->output_payload)
        {
            ksl_mempool_free(pool, parser->output_payload);
            parser->output_payload = NULL;
        }
    }

    return result;
}

/* =============================================================================
 * LEGION REASSEMBLY
 * ============================================================================= */

void ksl_reassembly_init(ksl_reassembly_ctx_t *ctx)
{
    if (!ctx) return;
    for (int i = 0; i < (int)KSL_REASSEMBLY_SLOTS; i++)
        ctx->slots[i].active = false;
}

int ksl_reassembly_add(ksl_reassembly_ctx_t *ctx,
                       const ksl_header_t *hdr,
                       const uint8_t *payload, uint16_t payload_len,
                       uint8_t *output, uint16_t *output_len,
                       uint32_t now_ms)
{
    if (!ctx || !hdr || !payload || !output || !output_len) return -1;
    if (!hdr->fragmented)  return -1;
    if (hdr->frag_index >= KSL_FRAG_MAX_FRAGMENTS) return -1;
    if (payload_len > KSL_FRAG_MAX_PAYLOAD) return -1;

    /* --- Evict timed-out slots --- */
    for (int i = 0; i < (int)KSL_REASSEMBLY_SLOTS; i++)
    {
        ksl_reassembly_slot_t *s = &ctx->slots[i];
        if (s->active && now_ms > 0 &&
            (now_ms - s->start_time_ms) > KSL_FRAG_TIMEOUT_MS)
        {
            s->active = false;
        }
    }

    /* --- Find existing slot for (msg_id, sys_id) or a free one --- */
    int slot_idx = -1;
    for (int i = 0; i < (int)KSL_REASSEMBLY_SLOTS; i++)
    {
        if (ctx->slots[i].active &&
            ctx->slots[i].msg_id == hdr->msg_id &&
            ctx->slots[i].sys_id == hdr->sys_id)
        {
            slot_idx = i;
            break;
        }
    }

    if (slot_idx == -1)
    {
        for (int i = 0; i < (int)KSL_REASSEMBLY_SLOTS; i++)
        {
            if (!ctx->slots[i].active)
            {
                slot_idx = i;
                break;
            }
        }
    }

    if (slot_idx == -1) return -1; /* All 128 slots in use */

    ksl_reassembly_slot_t *slot = &ctx->slots[slot_idx];

    if (!slot->active)
    {
        slot->active         = true;
        slot->msg_id         = hdr->msg_id;
        slot->sys_id         = hdr->sys_id;
        slot->frag_total     = hdr->frag_total;
        slot->frags_received = 0;
        slot->start_time_ms  = now_ms;
        for (int i = 0; i < (int)KSL_FRAG_MAX_FRAGMENTS; i++)
            slot->received[i] = false;
    }

    if (!slot->received[hdr->frag_index])
    {
        slot->received[hdr->frag_index] = true;
        slot->frags_received++;
        slot->frag_lens[hdr->frag_index] = payload_len;

        size_t dst_offset = (size_t)hdr->frag_index * KSL_FRAG_MAX_PAYLOAD;
        for (size_t i = 0; i < payload_len; i++)
        {
            if (dst_offset + i < KSL_FRAG_MAX_TOTAL)
                slot->data[dst_offset + i] = payload[i];
        }
    }

    if (slot->frags_received == slot->frag_total)
    {
        uint16_t total = 0;
        for (int i = 0; i < (int)slot->frag_total; i++)
            total = (uint16_t)(total + slot->frag_lens[i]);

        for (uint16_t i = 0; i < total; i++)
            output[i] = slot->data[i];

        *output_len  = total;
        slot->active = false;
        return 1; /* Complete */
    }

    return 0; /* More fragments needed */
}

/* =============================================================================
 * STATISTICS
 * ============================================================================= */

void ksl_get_stats(const ksl_parser_t *parser,
                   const ksl_mempool_t *pool,
                   ksl_stats_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));

    if (parser)
    {
        out->rx_count     = parser->rx_count;
        out->error_count  = parser->error_count;
        out->link_quality = ksl_link_quality(parser);
    }

    if (pool)
    {
        out->pool_alloc_count   = pool->alloc_count;
        out->pool_free_count    = pool->free_count;
        out->pool_peak_usage    = pool->peak_usage;
        out->pool_current_usage = pool->current_usage;
    }
}
