#ifndef KESTREL_RID_H
#define KESTREL_RID_H

#include "kestrel.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the Remote ID module with the UAV's serial/assigned ID */
void ks_rid_init(const char *uas_id);

/* Generate ASTM F3411 Remote ID payloads from current state.
 * This populates two independent frame buffers:
 * 1. KS_MSG_RID_BASIC_ID (placed in basic_buf)
 * 2. KS_MSG_RID_LOCATION (placed in loc_buf)
 * Returns 0 on success.
 */
int ks_rid_generate_payloads(uint8_t *basic_buf, int *basic_len,
                             uint8_t *loc_buf, int *loc_len,
                             int32_t lat, int32_t lon, int16_t alt_m, 
                             uint16_t speed_cm_s, int16_t track_deg, 
                             uint8_t status);

#ifdef __cplusplus
}
#endif

#endif // KESTREL_RID_H
