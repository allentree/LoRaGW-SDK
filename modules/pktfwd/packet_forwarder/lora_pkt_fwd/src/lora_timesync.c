
/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#define _GNU_SOURCE     /* needed for qsort_r to be defined */
#include <stdlib.h>     /* qsort_r */
#include <stdio.h>      /* printf, fprintf, snprintf, fopen, fputs */
#include <string.h>     /* memset, memcpy */
#include <netinet/in.h>     /* INET constants and stuff */
#include <pthread.h>
#include <assert.h>
#include <math.h>

#include "trace.h"
#include "base64.h"
#include "parson.h"
#include "lora_timesync.h"
#include "aes.h"
#include "cmac.h"
#include "loragw_aux.h"
#include "loragw_hal.h"
#include "loragw_reg.h"
#include "timersync.h"
#include "jitqueue.h"

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */
#define STD_LORA_PREAMB 8

#define UTC_GPS_EPOCH_OFFSET 315964800

#define LEAP_SECONDS 18

#define ADJUST_SECOND 2

#define TMST_COUNT_MAX 4294967296


/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS & TYPES -------------------------------------------- */


/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES (GLOBAL) ------------------------------------------- */
/*!
 * CMAC computation context variable
 */
static AES_CMAC_CTX AesCmacCtx[1];

/*!
 * Contains the computed MIC field.
 *
 * \remark Only the 4 first bytes are used
 */
static uint8_t Mic[16];

struct lora_time_sync_s lora_timesync;
pthread_mutex_t mx_timesync = PTHREAD_MUTEX_INITIALIZER;

/* -------------------------------------------------------------------------- */
/* --- PRIVATE SHARED VARIABLES (GLOBAL) ------------------------------------ */
extern bool exit_sig;
extern bool quit_sig;
extern pthread_mutex_t mx_concent;
extern struct jit_queue_s jit_queue;
extern uint32_t net_mac_h;
extern uint32_t net_mac_l;
extern pthread_mutex_t mx_timeref;
extern struct tref time_reference_gps;
extern bool gps_ref_valid;
extern bool lora_ref_valid;
extern bool utc_ref_valid;
extern uint32_t lora_timesync_freq_hz;
extern uint8_t ntp_update;

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */


/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS DEFINITION ----------------------------------------- */

#if defined(USE_LORA_TIME_SYNC)
static void compute_mic(const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t *mic) {
    AES_CMAC_Init(AesCmacCtx);

    AES_CMAC_SetKey(AesCmacCtx, key);

    AES_CMAC_Update(AesCmacCtx, buffer, size & 0xFF);

    AES_CMAC_Final(Mic, AesCmacCtx);

    *mic = (uint32_t)((uint32_t)Mic[3] << 24 | (uint32_t)Mic[2] << 16 | (uint32_t)Mic[1] << 8 | (uint32_t)Mic[0]);
    MSG("INFO: [lora_timesync] MIC: %02x %02x %02x %02x, mic: %08x\n", Mic[0], Mic[1], Mic[2], Mic[3], *mic);
}

int lora_timesync_set(struct tref *ref, bool need_update) {
    int ret = 0;
    uint32_t cur_tref;
    uint32_t tref;
    uint64_t tgps;
    double x1, x2;
    struct timespec gps_time;

    if (ref == NULL) {
        MSG("ERROR: [lora_timesync] ref is NULL\n");
        return -1;
    }

    pthread_mutex_lock(&mx_concent);
    lgw_reg_w(LGW_GPS_EN, 0);
    ret = lgw_get_trigcnt(&cur_tref);
    lgw_reg_w(LGW_GPS_EN, 1);
    pthread_mutex_unlock(&mx_concent);
    if (ret != LGW_HAL_SUCCESS) {
        MSG("WARNING: [lora_timesync] failed to get concentrator timestamp\n");
        return -1;
    }

    if (cur_tref > lora_timesync.last_tref) {
        tref = cur_tref;
        tgps = lora_timesync.last_tgps + ((uint64_t)cur_tref - (uint64_t)lora_timesync.last_tref);
    } else {
        tref = cur_tref;
        tgps = lora_timesync.last_tgps + (uint64_t)(TMST_COUNT_MAX) + (uint64_t)cur_tref - (uint64_t)lora_timesync.last_tref;
    }
    MSG("INFO: [lora_timesync] now tref: %u\n", tref);
    MSG("INFO: [lora_timesync] now tgps: %llu\n", tgps);

    if (need_update) {
        pthread_mutex_lock(&mx_timesync);
        lora_timesync.last_tref = tref;
        lora_timesync.last_tgps = tgps;
        MSG("INFO: [lora_timesync] last_tref: %u\n", lora_timesync.last_tref);
        MSG("INFO: [lora_timesync] last_tgps: %llu\n", lora_timesync.last_tgps);
        pthread_mutex_unlock(&mx_timesync);

        ref->systime = time(NULL);
        lora_ref_valid = true;
    }

    x1 = modf((double)tgps / 1E6, &x2);
    gps_time.tv_sec = (time_t)x2;
    gps_time.tv_nsec = (long)(x1 * 1E9);

    clock_gettime(CLOCK_REALTIME, &ref->utc);
    ref->count_us = cur_tref;
    ref->gps.tv_sec = gps_time.tv_sec;
    ref->gps.tv_nsec = gps_time.tv_nsec;
    ref->xtal_err = 1;
    MSG("INFO: [lora_timesync] gps.tv_sec: %ld, gps.tv_nsec: %ld\n", ref->gps.tv_sec, ref->gps.tv_nsec);

    return 0;
}

int lora_timesync_check(uint64_t tgps_val) {
    struct timespec cur_utc;
    uint64_t cur_gps_val = 0;
    uint64_t diff = 0;
    int valid = 0;

    if (ntp_update == 1) {
        clock_gettime(CLOCK_REALTIME, &cur_utc);
        cur_gps_val = ((uint64_t)(cur_utc.tv_sec - UTC_GPS_EPOCH_OFFSET + LEAP_SECONDS)) * 1E6 + ((uint64_t)cur_utc.tv_nsec) / 1E3;
        MSG("INFO: [lora_timesync] cur_gps_val: %llu\n", cur_gps_val);
        if (cur_gps_val > tgps_val) {
            diff = cur_gps_val - tgps_val;
        } else {
            diff = tgps_val - cur_gps_val;
        }
    } else if (lora_timesync.last_tgps > 0) {
        if (tgps_val > lora_timesync.last_tgps) {
            diff = tgps_val - lora_timesync.last_tgps;
        } else {
            diff = lora_timesync.last_tgps - tgps_val;
        }
    }

    if (diff <= TIME_SYNC_INTERVAL_MAX * 2 * 1E6) {
        valid = 1;
    }

    MSG("INFO: [lora_timesync] valid: %d\n", valid);
    return valid;
}

int lora_timesync_down(const uint8_t *msg_buf, uint16_t msg_len) {
    JSON_Object *txpk_obj = NULL;
    JSON_Object *tadj_obj = NULL;
    JSON_Object *bsgw_obj = NULL;
    JSON_Value *root_val = NULL;
    JSON_Value *val = NULL;
    const char *str;
    uint8_t msg_id = 0;
    uint64_t tgps_val = 0;
    uint32_t tref_val = 0;
    uint16_t interval = 0;
    int enable = 0;
    int selected = 0;
    int valid = 0;

    if (msg_len < 4) {
        MSG("WARNING: [lora_timesync] ignoring invalid packet, len: %d\n", msg_len);
        return -1;
    }

    msg_id = msg_buf[3];
    if (msg_id == LORA_TIME_SYNC_DOWN) {
        MSG("INFO: [lora_timesync] down msg: %s\n", (msg_buf + 4));
        root_val = json_parse_string_with_comments((const char *)(msg_buf + 4));
        if (root_val == NULL) {
            MSG("WARNING: [lora_timesync] invalid JSON\n");
            return -1;
        }

        txpk_obj = json_object_get_object(json_value_get_object(root_val), "txpk");
        if (NULL != txpk_obj) {
            enable = json_object_get_boolean(txpk_obj, "sync");
            MSG("INFO: [lora_timesync] enable: %d\n", enable);
            if (enable == 1) {
                pthread_mutex_lock(&mx_timesync);
                lora_timesync.enable = 1;

                val = json_object_get_value(txpk_obj, "syncinterval");
                if (val != NULL) {
                    if (json_value_get_type(val) == JSONNumber) {
                        interval = (uint16_t)json_value_get_number(val);
                        if ((interval == 0) || (interval > TIME_SYNC_INTERVAL_MAX)) {
                            interval = TIME_SYNC_INTERVAL_DEFAULT;
                        }
                        lora_timesync.interval = interval;
                    } else {
                        lora_timesync.interval = TIME_SYNC_INTERVAL_DEFAULT;
                    }
                }

                val = json_object_get_value(txpk_obj, "synctimes");
                if (val != NULL) {
                    if (json_value_get_type(val) == JSONNumber) {
                        lora_timesync.times = (uint16_t)json_value_get_number(val);
                    } else {
                        lora_timesync.times = 0;
                    }
                }

                val = json_object_get_value(txpk_obj, "synctoken");
                if (val != NULL) {
                    if (json_value_get_type(val) == JSONNumber) {
                        lora_timesync.token = (uint8_t)json_value_get_number(val);
                    } else {
                        lora_timesync.token = 0;
                    }
                }

                str = json_object_get_string(txpk_obj, "synckey");
                if (str != NULL) {
                    MSG("INFO: [lora_timesync] synckey:%s\n", str);
                    if (b64_to_bin(str, strlen(str), lora_timesync.key, sizeof(lora_timesync.key)) > 0) {
                        lora_timesync.use_key = 1;
                    }
                }

                lora_timesync.count = 0;
                lora_timesync.rf_chain = 0;
                lora_timesync.rf_power = 17;
                lora_timesync.freq_hz = lora_timesync_freq_hz;
                lora_timesync.net_mac_h = net_mac_h;
                lora_timesync.net_mac_l = net_mac_l;
                pthread_mutex_unlock(&mx_timesync);
            } else if (enable == 0) {
                pthread_mutex_lock(&mx_timesync);
                lora_timesync.enable = 0;
                pthread_mutex_unlock(&mx_timesync);
            }
        }

        tadj_obj = json_object_get_object(json_value_get_object(root_val), "set");
        if (NULL != tadj_obj) {
            tadj_obj = json_object_get_object(tadj_obj, "tadj");
            if (NULL != tadj_obj) {
                val = json_object_get_value(tadj_obj, "tgps");
                if (val != NULL) {
                    tgps_val = (uint64_t)json_value_get_number(val);
                    if (tgps_val > 0) {
                        valid = lora_timesync_check(tgps_val);
                        val = json_object_get_value(tadj_obj, "tref");
                        if ((val != NULL) && (valid == 1)) {
                            tref_val = (uint32_t)json_value_get_number(val);
                            if (tref_val > 0) {
                                pthread_mutex_lock(&mx_timesync);
                                lora_timesync.last_tgps = tgps_val;
                                MSG("INFO: [lora_timesync] down tgps: %llu\n", lora_timesync.last_tgps);

                                lora_timesync.last_tref = tref_val;
                                MSG("INFO: [lora_timesync] down tref: %u\n", lora_timesync.last_tref);
                                pthread_mutex_unlock(&mx_timesync);
                            }
                        }  
                    }
                }

                pthread_mutex_lock(&mx_timeref);
                if (!gps_ref_valid && !utc_ref_valid) {
                    lora_timesync_set(&time_reference_gps, true);
                }
                pthread_mutex_unlock(&mx_timeref);
            }
        }

        bsgw_obj = json_object_get_object(json_value_get_object(root_val), "set");
        if (NULL != bsgw_obj) {
            selected = json_object_get_boolean(bsgw_obj, "bsgw");
            pthread_mutex_lock(&mx_timesync);
            if (selected == 1) {
                lora_timesync.bsgw_selected = 1;
            } else if (selected == 0) {
                lora_timesync.bsgw_selected = 0;
            }
            pthread_mutex_unlock(&mx_timesync);
        }

        json_value_free(root_val);

        return 1;
    }

    return 0;
}

void thread_lora_timesync(void) {
    struct timeval cur_unix;
    struct timeval cur_tmst;
    enum jit_error_e jit_result = JIT_ERROR_OK;
    enum jit_pkt_type_e pkt_type = JIT_PKT_TYPE_DOWNLINK_CLASS_A;
    struct lgw_pkt_tx_s pkt;
    uint32_t sx1301_count_us;
    int ret = 0;
    uint8_t data[256];
    uint32_t toa_us;
    uint32_t mic = 0;
    uint32_t count = 0;

    while (!exit_sig && !quit_sig) {
        wait_ms(1000);
        count++;

        if ((lora_timesync.enable == 1) && !gps_ref_valid && !utc_ref_valid) {
            if ((lora_timesync.times > 0) && (lora_timesync.count >= lora_timesync.times)) {
                continue;
            }

            if (lora_timesync.interval == 0) {
                pthread_mutex_lock(&mx_timesync);
                lora_timesync.interval = TIME_SYNC_INTERVAL_DEFAULT;
                pthread_mutex_unlock(&mx_timesync);
            }

            if ((lora_timesync.count > 0) && (count < lora_timesync.interval)) {
                continue;
            }

            memset(&pkt, 0x0, sizeof(pkt));

            pkt.bandwidth = BW_125KHZ;
            pkt.coderate = CR_LORA_4_5;
            pkt.modulation = MOD_LORA;
            pkt.datarate = DR_LORA_SF9;
            pkt.preamble = STD_LORA_PREAMB;
            pkt.tx_mode = TIMESTAMPED;
            pkt.invert_pol = false;
            pkt.no_crc = false;
            pkt.rf_chain = lora_timesync.rf_chain;
            pkt.rf_power = lora_timesync.rf_power;
            pkt.freq_hz = lora_timesync.freq_hz;
            MSG("INFO: [lora_timesync] pkt rf_chain: %d, rf_power: %d, freq_hz: %u\n", pkt.rf_chain, pkt.rf_power, pkt.freq_hz);

            pthread_mutex_lock(&mx_concent);
            lgw_reg_w(LGW_GPS_EN, 0);
            ret = lgw_get_trigcnt(&sx1301_count_us);
            lgw_reg_w(LGW_GPS_EN, 1);
            pthread_mutex_unlock(&mx_concent);
            if (ret != LGW_HAL_SUCCESS) {
                MSG("INFO: [lora_timesync] failed to read concentrator timestamp\n");
                continue;
            }
            pkt.count_us = sx1301_count_us + 1000000;

            memset(&data, 0x0, sizeof(data));
            data[0] = 0b11100100;                                 //MHDR: 1 octets
            data[1] = 0xFF & (lora_timesync.net_mac_l >> 24);     //Gateway A EUI: 8 octets
            data[2] = 0xFF & (lora_timesync.net_mac_l >> 16);     //Gateway A EUI
            data[3] = 0xFF & (lora_timesync.net_mac_l >> 8);      //Gateway A EUI
            data[4] = 0xFF & (lora_timesync.net_mac_l);           //Gateway A EUI
            data[5] = 0xFF & (lora_timesync.net_mac_h >> 24);     //Gateway A EUI
            data[6] = 0xFF & (lora_timesync.net_mac_h >> 16);     //Gateway A EUI
            data[7] = 0xFF & (lora_timesync.net_mac_h >> 8);      //Gateway A EUI
            data[8] = 0xFF & (lora_timesync.net_mac_h);           //Gateway A EUI
            data[9]  = 0xFF & (pkt.count_us);                     //Gateway A tmst: 4 octets
            data[10] = 0xFF & (pkt.count_us >> 8);                //Gateway A tmst
            data[11] = 0xFF & (pkt.count_us >> 16);               //Gateway A tmst
            data[12] = 0xFF & (pkt.count_us >> 24);               //Gateway A tmst
            data[13] = 0;                                         //stat: 2 octets
            data[14] = 0;                                         //stat
            data[15] = lora_timesync.token & 0xFF;                //synctoken
            data[16] = lora_timesync.count % 256;                 //token

            if (1 == lora_timesync.use_key) {
                compute_mic(data, 17, lora_timesync.key, &mic);
                data[17] = mic & 0xFF;                            //MIC: 2 octets
                data[18] = (mic >> 8) & 0xFF;                     //MIC
            } else {
                data[17] = 0;                                     //MIC: 2 octets
                data[18] = 0;                                     //MIC
            }

            pkt.size = 19;
            printf("[lora_timesync] data: 0x");
            for (int i = 0; i < pkt.size; i++) {
                printf("%02x", data[i]);
            }
            printf("\n");

            memcpy(pkt.payload, data, pkt.size);
            MSG("INFO: [lora_timesync] pkt count_us: %u, size: %d\n", pkt.count_us, pkt.size);

            toa_us = lgw_time_on_air(&pkt) * 1000UL;
            MSG("INFO: [lora_timesync] pkt TOA us: %u\n", toa_us);

            pkt_type = JIT_PKT_TYPE_DOWNLINK_CLASS_A;
            gettimeofday(&cur_unix, NULL);
            get_concentrator_time(&cur_tmst, cur_unix);
            jit_result = jit_enqueue(&jit_queue, &cur_tmst, &pkt, pkt_type);
            if (jit_result != JIT_ERROR_OK) {
                MSG("ERROR: [lora_timesync] Packet REJECTED (jit error=%d)\n", jit_result);
            } else {
                pthread_mutex_lock(&mx_timesync);
                lora_timesync.count++;
                pthread_mutex_unlock(&mx_timesync);
                count = 0;
            }

            MSG("INFO: [lora_timesync] count: %d, interval: %d\n", lora_timesync.count, lora_timesync.interval);
        }

        if ((lora_timesync.bsgw_selected == 1) && (ntp_update == 1) && !gps_ref_valid) {
            pthread_mutex_lock(&mx_concent);
            lgw_reg_w(LGW_GPS_EN, 0);
            ret = lgw_get_trigcnt(&sx1301_count_us);
            lgw_reg_w(LGW_GPS_EN, 1);
            pthread_mutex_unlock(&mx_concent);
            if (ret != LGW_HAL_SUCCESS) {
                MSG("WARNING: [lora_timesync] failed to get concentrator timestamp\n");
                continue;
            }

            pthread_mutex_lock(&mx_timeref);          
            clock_gettime(CLOCK_REALTIME, &time_reference_gps.utc);
            time_reference_gps.systime = time(NULL);
            time_reference_gps.count_us = sx1301_count_us;
            time_reference_gps.gps.tv_sec = time_reference_gps.utc.tv_sec - UTC_GPS_EPOCH_OFFSET + LEAP_SECONDS - ADJUST_SECOND;
            time_reference_gps.gps.tv_nsec = time_reference_gps.utc.tv_nsec;
            time_reference_gps.xtal_err = 1;
            utc_ref_valid = true;
            lora_ref_valid = false;
            // MSG("INFO: [lora_timesync] gps.tv_sec: %ld, gps.tv_nsec: %ld\n", time_reference_gps.gps.tv_sec, time_reference_gps.gps.tv_nsec);
            pthread_mutex_unlock(&mx_timeref);
        }

    }
}
#endif

