
#ifndef _LORA_TIME_SYNC_H
#define _LORA_TIME_SYNC_H

/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */
#include "loragw_gps.h"

/* -------------------------------------------------------------------------- */
/* --- PUBLIC CONSTANTS ----------------------------------------------------- */

#define USE_LORA_TIME_SYNC

#define LORA_TIME_SYNC_UP           0x83
#define LORA_TIME_SYNC_DOWN         0x84

#define TIME_SYNC_INTERVAL_DEFAULT  120
#define TIME_SYNC_INTERVAL_MAX      300

/* -------------------------------------------------------------------------- */
/* --- PUBLIC TYPES --------------------------------------------------------- */

struct lora_time_sync_s {
    uint8_t enable;
    uint8_t bsgw_selected;
    uint16_t interval;
    uint16_t times;
    uint8_t token;
    uint8_t use_key;
    uint8_t key[16];
    uint32_t freq_hz;
    uint8_t  rf_chain;
    int8_t   rf_power;
    uint16_t count;
    uint32_t net_mac_h;
    uint32_t net_mac_l;
    uint64_t last_tgps;
    uint32_t last_tref;
};


/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS PROTOTYPES ------------------------------------------ */
int lora_timesync_down(const uint8_t *msg_buf, uint16_t msg_len);
int lora_timesync_set(struct tref *ref, bool need_update);
void thread_lora_timesync(void);

extern pthread_mutex_t mx_timesync;
extern struct lora_time_sync_s lora_timesync;

#endif
/* --- EOF ------------------------------------------------------------------ */
