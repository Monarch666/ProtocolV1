#include "kestrel_rid.h"
#include <string.h>

static ks_rid_basic_id_t g_rid_basic = {0};

void ks_rid_init(const char *uas_id)
{
    g_rid_basic.id_type = 0x10; /* Serial Number */
    g_rid_basic.ua_type = 0x05; /* Rotorcraft */
    memset(g_rid_basic.uas_id, 0, sizeof(g_rid_basic.uas_id));
    if (uas_id) {
        strncpy(g_rid_basic.uas_id, uas_id, sizeof(g_rid_basic.uas_id) - 1);
    }
}

int ks_rid_generate_payloads(uint8_t *basic_buf, int *basic_len,
                             uint8_t *loc_buf, int *loc_len,
                             int32_t lat, int32_t lon, int16_t alt_m,
                             uint16_t speed_cm_s, int16_t track_deg,
                             uint8_t status)
{
    if (!basic_buf || !basic_len || !loc_buf || !loc_len) 
        return KS_ERR_NULL_POINTER;

    /* 1. Basic ID Frame */
    *basic_len = ks_serialize_rid_basic_id(&g_rid_basic, basic_buf);

    /* 2. Location Frame */
    ks_rid_location_t loc = {0};
    loc.status = status;
    loc.lat = lat;
    loc.lon = lon;
    loc.geodetic_alt = alt_m;
    loc.speed = speed_cm_s;
    loc.track_deg = track_deg;
    
    *loc_len = ks_serialize_rid_location(&loc, loc_buf);

    return 0;
}
