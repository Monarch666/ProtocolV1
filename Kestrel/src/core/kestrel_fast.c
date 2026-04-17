#include "kestrel_fast.h"
#include "kestrel.h"
#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* =============================================================================
 * PHASE 2 IMPLEMENTATION
 * ============================================================================= */

/* --- Zero-Copy Parser Implementation --- */

void ks_parser_zerocopy_init(ks_parser_zerocopy_t *parser)
{
    /* Only reset ephemeral parsing state. Preserve key_32b, rx_count, replay_init, etc. */
    parser->state = 0;
    parser->payload_len = 0;
    parser->bytes_received = 0;
    parser->msg_id = 0;
    parser->stream_type = 0;
    parser->fragmented = false;
    parser->output_payload = NULL;
    parser->last_payload = NULL;
    parser->crc_in = 0;
    parser->crc_calc = 0;
}

uint8_t ks_get_link_quality(const ks_parser_zerocopy_t *p)
{
    if (!p)
        return 0;

    /* Bug-8 FIX (a): The second `total == 0` check was dead code — total was just
       computed from the same values and could not have changed. Removed.
       Bug-8 FIX (b): p->rx_count * 100 silently overflows uint32_t at ~42.9 million
       packets, producing a wildly wrong quality reading. Cast to uint64_t first. */
    uint32_t total = p->rx_count + p->error_count;
    if (total == 0)
        return 0;

    return (uint8_t)(((uint64_t)p->rx_count * 100U) / total);
}

int ks_parse_char_zerocopy(ks_parser_zerocopy_t *parser, uint8_t byte, uint8_t *output_buf, size_t output_buf_size)
{
    if (!parser || !output_buf)
    {
        return -1; // Error
    }

    /* Bug-5 FIX: The original guard set output_payload once on the very first call and
       then silently ignored any different buffer supplied on later calls — even for a
       brand-new packet. In streaming scenarios where the caller provides a fresh buffer
       per packet, all writes went into the first buffer ever supplied.

       Fix: update output_payload whenever the parser is in IDLE state (state==0),
       i.e. at the start of a new packet. Mid-packet the pointer must stay stable;
       switching buffers mid-flight is a caller error and we reset with an error. */
    if (parser->state == 0)
    {
        parser->output_payload = output_buf;
    }
    else if (parser->output_payload != output_buf && parser->output_payload != NULL)
    {
        /* Mid-packet buffer pointer switch — treat as caller error, reset parser */
        ks_parser_zerocopy_init(parser);
        parser->error_count++;
        return -1;
    }

    switch (parser->state)
    {
    case 0: // IDLE - waiting for SOF
        if (byte == KS_SOF)
        {
            parser->header_buf[0] = byte;
            parser->state = 1; // BASE_HDR
            parser->bytes_received = 1;
        }
        break;

    case 1: // BASE_HDR (4 bytes total including SOF)
        parser->header_buf[parser->bytes_received++] = byte;

        if (parser->bytes_received >= 4)
        {
            // Decode base header to get payload length
            // Simplified: extract payload length from compact header
            uint8_t byte1 = parser->header_buf[1];
            uint8_t byte2 = parser->header_buf[2];
            uint8_t byte3 = parser->header_buf[3];

            parser->payload_len = ((byte1 & 0xF0) << 4) | ((byte2 & 0x3F) << 2) | ((byte3 & 0xC0) >> 6);

            if (parser->payload_len > KS_MAX_PAYLOAD_SIZE)
            {
                parser->state = 0;
                parser->error_count++;
                return -1;
            }

            /* Decode fragmented flag from byte3 bit 2 */
            parser->fragmented = (byte3 & KS_FLAG_FRAGMENTED) != 0;

            parser->stream_type = ((byte1 & 0x3) << 2) | ((byte2 >> 6) & 0x3);
            parser->state = 2; // EXT_HDR
        }
        break;

    case 2: // EXT_HDR (both encrypted and unencrypted)
        parser->header_buf[parser->bytes_received++] = byte;

        // Extended header layout (bytes counted from start of header_buf):
        //   [0..3]  base header (4 bytes)
        //   [4..5]  seq_sys: sequence upper bits + sys_id
        //   [6..7]  comp_msg: comp_id + msg_id
        //   [8]     target_sys_id (CMD/CMD_ACK only)
        //   [8 or 9] nonce start (8 bytes, if encrypted)

        // Extract message ID after reading bytes 6-7 (comp_msg)
        if (parser->bytes_received == 8)
        {
            // comp_msg is in header_buf[6] (high) and header_buf[7] (low)
            uint16_t comp_msg = (parser->header_buf[6] << 8) | parser->header_buf[7];
            parser->msg_id = comp_msg & 0xFFF; // Lower 12 bits are msg_id
        }

        // Determine whether this is a CMD/CMD_ACK stream (has extra target_sys_id byte)
        bool is_cmd = (parser->stream_type == KS_STREAM_CMD ||
                       parser->stream_type == KS_STREAM_CMD_ACK);

        // Routing section ends at bytes_received == 8 (non-CMD) or 9 (CMD)
        uint16_t routing_end = is_cmd ? 9u : 8u;

        // Check if encrypted to determine total extended header length
        bool encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;

        if (encrypted)
        {
            uint16_t nonce_end = routing_end + 8u;

            /* BUG-5 FIX: nonce extraction condition was `== nonce_end` but the transition to
               PAYLOAD also fires at `>= nonce_end` — they match, so this is fine. However the
               original code always branched on `==` first and `>=` second, meaning nonce_end
               was reached twice if nonce_end happened to be skipped. Make both conditions
               identical to be safe. */
            if (parser->bytes_received == nonce_end)
            {
                memcpy(parser->cipher_nonce, &parser->header_buf[routing_end], 8);
                parser->state = 3; // PAYLOAD
                parser->bytes_received = 0;
            }
        }
        else
        {
            if (parser->bytes_received >= routing_end)
            {
                /* BUG-A FIX: If payload_len == 0, skip PAYLOAD state entirely and go
                   directly to CRC. The PAYLOAD case only fires when bytes_received < payload_len,
                   so with payload_len=0 the parser would hang forever in state 3. */
                if (parser->payload_len == 0)
                {
                    parser->state = 4; // CRC
                }
                else
                {
                    parser->state = 3; // PAYLOAD
                }
                parser->bytes_received = 0;
            }
        }
        break;

    case 3: // PAYLOAD
        /* BUG-A FIX: payload_len==0 packets never enter this case (transitioned
           directly to CRC in EXT_HDR). The check below is still here for safety. */
        if (parser->bytes_received < parser->payload_len)
        {
            if (parser->bytes_received < output_buf_size)
            {
                parser->output_payload[parser->bytes_received] = byte;
            }
            else
            {
                parser->state = 0;
                parser->error_count++;
                return -1;
            }
            parser->bytes_received++;

            if (parser->bytes_received >= parser->payload_len)
            {
                bool encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
                if (encrypted)
                    parser->state = 5; // MAC_TAG
                else
                    parser->state = 4; // CRC
                parser->bytes_received = 0;
            }
        }
        break;

    case 5: // MAC_TAG (16 bytes for encrypted packets)
        parser->cipher_tag[parser->bytes_received++] = byte;

        if (parser->bytes_received >= 16)
        {
            parser->state = 4; // Now read CRC
            parser->bytes_received = 0;
        }
        break;

    case 4: // CRC (2 bytes)
        if (parser->bytes_received == 0)
            parser->crc_in = byte;
        else
            parser->crc_in |= ((uint16_t)byte << 8);

        parser->bytes_received++;

        if (parser->bytes_received >= 2)
        {
            // Verify CRC over header bytes 1..crc_header_len-1, payload, and MAC (if encrypted)
            bool crc_encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
            bool crc_cmd = (parser->stream_type == KS_STREAM_CMD ||
                            parser->stream_type == KS_STREAM_CMD_ACK);

            // header_buf index where header ends:
            //   base(4 bytes) + routing(4 bytes + 1 target_sys_id for CMD) + nonce(8 if encrypted)
            int routing_end = crc_cmd ? 9 : 8;
            int crc_header_len = crc_encrypted ? (routing_end + 8) : routing_end;

            ks_crc_init(&parser->crc_calc);

            // Hash header bytes (skip SOF at index 0)
            for (int i = 1; i < crc_header_len; i++)
                ks_crc_accumulate(parser->header_buf[i], &parser->crc_calc);

            // Hash payload (ciphertext for encrypted, plaintext for unencrypted)
            for (int i = 0; i < parser->payload_len; i++)
                ks_crc_accumulate(parser->output_payload[i], &parser->crc_calc);

            // For encrypted packets, also hash the 16-byte MAC tag
            if (crc_encrypted)
            {
                for (int i = 0; i < 16; i++)
                    ks_crc_accumulate(parser->cipher_tag[i], &parser->crc_calc);
            }

            ks_crc_accumulate(ks_get_crc_seed(parser->msg_id), &parser->crc_calc);

            if (parser->crc_in != parser->crc_calc)
            {
                ks_parser_zerocopy_init(parser);
                return KS_ERR_CRC;
            }

            /* BUG-1 FIX: Zero-copy parser skipped MAC authentication and replay check.
               The original code returned success after CRC alone, allowing an attacker to
               forge encrypted packets whose ciphertext was never MAC-verified. */
            bool is_encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
            if (is_encrypted)
            {
                /* MAC tag was collected in cipher_tag[]; nonce in cipher_nonce[].
                   Build the 24-byte nonce monocypher expects (pad with zeros). */
                uint8_t nonce24[24] = {0};
                memcpy(nonce24, parser->cipher_nonce, 8);

                /* Determine header (AAD) length */
                bool is_cmd = (parser->stream_type == KS_STREAM_CMD ||
                               parser->stream_type == KS_STREAM_CMD_ACK);
                int routing_end = is_cmd ? 9 : 8;
                int aad_len = routing_end + 8; /* routing + nonce */

                /* Caller must set parser->key_32b before parsing encrypted packets */
                if (!parser->key_32b)
                {
                    ks_parser_zerocopy_init(parser);
                    parser->error_count++;
                    return KS_ERR_NO_KEY;
                }

                extern int crypto_aead_unlock(
                    uint8_t *plain_text, const uint8_t mac[16], const uint8_t key[32],
                    const uint8_t nonce[24], const uint8_t *ad, size_t ad_size,
                    const uint8_t *cipher_text, size_t text_size);

                /* Use a separate plaintext buffer to avoid aliasing (same lesson as BUG-01) */
                uint8_t decrypted[KS_MAX_PAYLOAD_SIZE];
                int auth = crypto_aead_unlock(
                    decrypted, parser->cipher_tag, parser->key_32b, nonce24,
                    parser->header_buf, aad_len,
                    parser->output_payload, parser->payload_len);

                if (auth != 0)
                {
                    ks_parser_zerocopy_init(parser);
                    parser->error_count++;
                    return KS_ERR_MAC_VERIFICATION;
                }
                memcpy(parser->output_payload, decrypted, parser->payload_len);
            }

            /* ------------------------------------------------------------
             * Replay protection — 64-packet sliding window.
             *
             * For encrypted packets: use the 32-bit nonce counter from
             * cipher_nonce[0..3] (little-endian). The nonce counter is
             * already MAC-authenticated at this point, so it cannot be
             * spoofed. This extends anti-replay from 12-bit (~40 s at
             * 100 Hz) to 32-bit (~497 days at 100 Hz).
             *
             * For unencrypted packets: fall back to the 12-bit wire
             * sequence. Replay detection on unauthenticated traffic has
             * limited value (no MAC), but prevents obvious duplicates.
             * ------------------------------------------------------------ */
            uint16_t seq = ((uint16_t)(parser->header_buf[3] & 0x3) << 10)
                         | (((uint16_t)parser->header_buf[4] << 8 | parser->header_buf[5]) >> 6);

            bool pkt_encrypted = (parser->header_buf[3] & KS_FLAG_ENCRYPTED) != 0;
            uint32_t replay_seq;
            if (pkt_encrypted)
            {
                replay_seq = (uint32_t)parser->cipher_nonce[0]
                           | ((uint32_t)parser->cipher_nonce[1] << 8)
                           | ((uint32_t)parser->cipher_nonce[2] << 16)
                           | ((uint32_t)parser->cipher_nonce[3] << 24);
            }
            else
            {
                replay_seq = (uint32_t)seq; /* 12-bit wire sequence */
            }

            if (parser->replay_init)
            {
                int32_t diff = (int32_t)(replay_seq - parser->last_seq);
                if (diff <= 0)
                {
                    int32_t back = -diff;
                    if (back >= 64 || (parser->replay_window & (1ULL << (uint8_t)back)))
                    {
                        ks_parser_zerocopy_init(parser);
                        parser->error_count++;
                        return KS_ERR_REPLAY;
                    }
                    parser->replay_window |= (1ULL << (uint8_t)back);
                }
                else
                {
                    uint32_t shift = (uint32_t)diff;
                    parser->replay_window = (shift >= 64) ? 0ULL
                                                           : (parser->replay_window << shift);
                    parser->replay_window |= 1ULL;
                    parser->last_seq = replay_seq;
                }
            }
            else
            {
                parser->replay_init   = 1;
                parser->last_seq      = replay_seq;
                parser->replay_window = 1ULL;
            }

            /* BUG-B FIX: Populate header fields so callers can read fragmented/sequence.
               The original code returned 1 (success) without ever writing parsed header
               fields into a struct the caller could inspect, so rx_hdr.fragmented was always
               false for fragmented packets parsed via the zero-copy path. */
            parser->out_fragmented = parser->fragmented;
            parser->out_sequence   = replay_seq;

            // Success!
            parser->state = 0;
            parser->bytes_received = 0;
            parser->rx_count++;
            return 1; /* Complete packet */
        }
        break;

    default:
        parser->state = 0;
        return -1; // Error
    }

    return 0; // Incomplete
}

/* --- Memory Pool Implementation --- */

void ks_mempool_init(ks_mempool_t *pool)
{
    memset(pool, 0, sizeof(ks_mempool_t));
    pool->free_mask = 0xFFFFFFFF; // All buffers free (32 bits set)
}

void *ks_mempool_alloc(ks_mempool_t *pool)
{
    if (!pool || pool->free_mask == 0)
    {
        return NULL; // Pool exhausted
    }

    // Find first free buffer using builtin (O(1) operation)
    int index;
#ifdef _MSC_VER
    // MSVC: use _BitScanForward (returns 1 on success, sets index to bit position)
    unsigned long idx;
    _BitScanForward(&idx, pool->free_mask);
    index = (int)idx;
#else
    // GCC/Clang: use __builtin_ffs (returns 1-based index, so subtract 1)
    index = __builtin_ffs(pool->free_mask) - 1;
#endif

    // Mark as allocated
    pool->free_mask &= ~(1U << index);

    // Update statistics
    pool->alloc_count++;
    pool->current_usage++;
    if (pool->current_usage > pool->peak_usage)
    {
        pool->peak_usage = pool->current_usage;
    }

    return pool->buffers[index];
}

void ks_mempool_free(ks_mempool_t *pool, void *ptr)
{
    if (!pool || !ptr)
    {
        return;
    }

    // Calculate buffer index from pointer
    uintptr_t pool_start = (uintptr_t)pool->buffers;
    uintptr_t ptr_addr = (uintptr_t)ptr;

    if (ptr_addr < pool_start ||
        ptr_addr >= pool_start + (KS_MEMPOOL_NUM_BUFFERS * KS_MEMPOOL_BUFFER_SIZE) ||
        ((ptr_addr - pool_start) % KS_MEMPOOL_BUFFER_SIZE) != 0)
    {
        return; // Invalid or misaligned pointer (not a buffer start)
    }

    size_t index = (ptr_addr - pool_start) / KS_MEMPOOL_BUFFER_SIZE;

    if (index >= KS_MEMPOOL_NUM_BUFFERS)
    {
        return; // Invalid index
    }

    /* Bug-6 FIX: No double-free guard existed. A second call with the same pointer
       set the free-bit again (idempotent on free_mask) but also decremented
       current_usage and incremented free_count a second time, corrupting statistics
       and potentially triggering false "pool full" behaviour.
       Detect double-free by checking whether the bit is already set and bail out. */
    if (pool->free_mask & (1U << index))
    {
        /* Double-free: buffer already in the free pool — silently ignore to match
           the defensive style of the rest of the codebase. */
        return;
    }

    /* Mark as free */
    pool->free_mask |= (1U << index);

    /* Zero the released buffer: prevents decrypted plaintext / key material
       from persisting in memory and being readable via a later allocation. */
    memset(pool->buffers[index], 0, KS_MEMPOOL_BUFFER_SIZE);

    /* Update statistics */
    pool->free_count++;
    if (pool->current_usage > 0)
    {
        pool->current_usage--;
    }
}

void ks_mempool_stats(const ks_mempool_t *pool, uint32_t *alloc_count,
                      uint32_t *free_count, uint32_t *peak_usage,
                      uint32_t *current_usage)
{
    if (!pool)
    {
        return;
    }

    if (alloc_count)
        *alloc_count = pool->alloc_count;
    if (free_count)
        *free_count = pool->free_count;
    if (peak_usage)
        *peak_usage = pool->peak_usage;
    if (current_usage)
        *current_usage = pool->current_usage;
}

/* --- Hardware Crypto Detection --- */

static ks_crypto_caps_t g_crypto_caps = {0};
static bool g_crypto_caps_initialized = false;

ks_crypto_caps_t ks_crypto_detect_caps(void)
{
    ks_crypto_caps_t caps = {0};
    caps.backend = KS_CRYPTO_SOFTWARE; // Default to software
    caps.speedup_factor = 1;

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    // ARM NEON - usually fixed at compile time for ARM targets
    caps.has_neon = true;
    caps.backend = KS_CRYPTO_ARM_NEON;
    caps.speedup_factor = 4;
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    // x86/x64 - Runtime SIMD detection
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    caps.has_sse = (cpuInfo[3] & (1 << 26)) != 0; // SSE2
    __cpuidex(cpuInfo, 7, 0);
    caps.has_avx2 = (cpuInfo[1] & (1 << 5)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    caps.has_avx2 = __builtin_cpu_supports("avx2");
    caps.has_sse = __builtin_cpu_supports("sse2");
#endif

    if (caps.has_avx2)
    {
        caps.backend = KS_CRYPTO_X86_AVX2;
        caps.speedup_factor = 4;
    }
    else if (caps.has_sse)
    {
        caps.backend = KS_CRYPTO_X86_SSE;
        caps.speedup_factor = 2;
    }
#endif

    return caps;
}

const ks_crypto_caps_t *ks_crypto_get_caps(void)
{
    if (!g_crypto_caps_initialized)
    {
        g_crypto_caps = ks_crypto_detect_caps();
        g_crypto_caps_initialized = true;
    }
    return &g_crypto_caps;
}

/* --- Fast Combined API --- */

int ks_pack_fast(ks_mempool_t *pool, const ks_header_t *h, const uint8_t *payload,
                 ks_session_t *session, ks_crypto_ctx_t *crypto_ctx, uint8_t **buffer)
{
    if (!pool || !h || !payload || !buffer)
    {
        return -1;
    }

    // Allocate buffer from pool (O(1))
    uint8_t *buf = (uint8_t *)ks_mempool_alloc(pool);
    if (!buf)
    {
        return -2; // Pool exhausted
    }

    int packed_len;

    if (session && crypto_ctx)
    {
        /* Session + crypto cache: cached selective encryption */
        packed_len = kestrel_pack_cached(buf, h, payload, session, crypto_ctx);
    }
    else
    {
        /* session=NULL = transmit unencrypted; session non-NULL without cache = selective encrypt */
        packed_len = kestrel_pack_with_nonce(buf, h, payload, session);
    }

    if (packed_len < 0)
    {
        ks_mempool_free(pool, buf);
        return packed_len;
    }

    *buffer = buf;
    return packed_len;
}

int ks_parse_char_fast(ks_parser_zerocopy_t *parser, uint8_t byte, ks_mempool_t *pool)
{
    if (!parser || !pool)
    {
        return -1;
    }

    // On first byte of new packet, allocate output buffer.
    // If the caller never consumed last_payload from the previous packet, free it
    // now to prevent pool exhaustion — the data is lost, but the pool doesn't leak.
    if (parser->state == 0 && !parser->output_payload)
    {
        if (parser->last_payload)
        {
            ks_mempool_free(pool, parser->last_payload);
            parser->last_payload = NULL;
        }
        parser->output_payload = (uint8_t *)ks_mempool_alloc(pool);
        if (!parser->output_payload)
        {
            return -2; // Pool exhausted
        }
    }

    // Parse byte using zero-copy parser
    int result = ks_parse_char_zerocopy(parser, byte, parser->output_payload, KS_MEMPOOL_BUFFER_SIZE);

    if (result == 1)
    {
        // Complete packet — save completed buffer pointer for caller BEFORE clearing output_payload
        parser->last_payload = parser->output_payload;
        parser->output_payload = NULL; // Ready for next packet allocation
    }
    else if (result < 0)
    {
        // Error - free buffer
        if (parser->output_payload)
        {
            ks_mempool_free(pool, parser->output_payload);
            parser->output_payload = NULL;
        }
    }

    return result;
}

int ks_check_replay_window(ks_parser_zerocopy_t *p, uint32_t seq)
{
    if (!p)
        return KS_ERR_NULL_POINTER;

    /* Same nonce-counter strategy as ks_parse_char_zerocopy().
     * Callers should pass the nonce counter for encrypted packets
     * and the 12-bit wire sequence (cast to uint32_t) for unencrypted. */
    if (p->replay_init)
    {
        int32_t diff = (int32_t)(seq - p->last_seq);
        if (diff <= 0)
        {
            int32_t back = -diff;
            if (back >= 64 || (p->replay_window & (1ULL << (uint8_t)back)))
            {
                p->error_count++;
                return KS_ERR_REPLAY; /* BUG-02 FIX (fast path): distinguish replay attacks from link errors */
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
    /* Bug-9 FIX: ks_check_replay_window() never incremented rx_count on success.
       Callers who use this function instead of ks_parse_char_zerocopy() (e.g. after
       out-of-band MAC verification) saw ks_get_link_quality() permanently return 0%
       because rx_count remained 0 while error_count grew normally.
       Increment rx_count here so link quality statistics remain consistent. */
    p->rx_count++;
    return 0; /* Success — packet accepted into replay window */
}