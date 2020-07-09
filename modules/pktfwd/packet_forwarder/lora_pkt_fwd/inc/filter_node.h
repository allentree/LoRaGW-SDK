
#ifndef _LORA_PKTFWD_FILTER_H
#define _LORA_PKTFWD_FILTER_H

/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#include <stdint.h>     /* C99 types */
#include <stdbool.h>    /* bool type */

#include <sys/time.h>

/* -------------------------------------------------------------------------- */
/* --- PUBLIC CONSTANTS ----------------------------------------------------- */
#define USE_FILTER_NODE

/* The blacklist default discard time period threshold for Nodes (in seconds)  */
#define DEFAULT_BLACK_LIST_DURATION  1800
/* The same deveui twice consecutive join request default time interval threshold (in seconds)   */
#define DEFAULT_JOIN_TIME_INTERVAL   6
/* Statistics on the latest  join request default time period threshold */
#define DEFAULT_JOIN_TIME_PERIOD     1800
#define DEFAULT_JOIN_COUNT1_MAX      5
#define DEFAULT_JOIN_COUNT2_MAX      20

#define JOIN_QUEUE_MAX       1024
#define BLACK_LIST_MAX       1000
#define WHITE_LIST_MAX       100


/* -------------------------------------------------------------------------- */
/* --- PUBLIC TYPES --------------------------------------------------------- */
enum filter_type_e {
    FILTER_TYPE_DEVEUI = 0,
    FILTER_TYPE_DEVADDR,
    FILTER_TYPE_OUI,
    FILTER_TYPE_NETID,
    FILTER_TYPE_MAX
};

enum filter_w_msg_type_e {
    FILTER_W_G_NOTIFY = 10,
    FILTER_W_G_ADD,
    FILTER_W_G_DELETE,
    FILTER_W_S_ADD,
    FILTER_W_S_DELETE,
    FILTER_W_S_GET,
    FILTER_W_TYPE_MAX
};

enum filter_b_msg_type_e {
    FILTER_B_G_NOTIFY = 20,
    FILTER_B_G_ADD,
    FILTER_B_G_DELETE,
    FILTER_B_S_ADD,
    FILTER_B_S_DELETE,
    FILTER_B_S_GET,
    FILTER_B_TYPE_MAX
};

enum filter_c_msg_type_e {
    FILTER_C_G_NOTIFY = 30,
    FILTER_C_S_CONFIG,
    FILTER_C_S_GET,
    FILTER_C_TYPE_MAX
};

struct filter_s {
    uint8_t inited;
    uint32_t bl_duration;
    uint32_t join_period;
    uint32_t join_interval;
    uint32_t join_count1;
    uint32_t join_count2;
    pthread_t thrid_id;
};

struct white_list_node_s {
    uint8_t enable;
    uint8_t type;
    uint64_t time;
    uint64_t value;
};

struct white_list_s {
    uint8_t  enable;
    uint8_t  binding;
    uint32_t num;
    struct white_list_node_s nodes[WHITE_LIST_MAX];
};

struct black_list_node_s {
    uint8_t type;
    uint32_t duration;
    uint64_t time;
    uint64_t value;
};

struct black_list_s {
    uint8_t  enable;
    uint32_t num;
    struct black_list_node_s nodes[BLACK_LIST_MAX];
};

struct join_node_s {
    uint64_t value;
    uint64_t f_time;
    uint64_t l_time;
    uint32_t count1;
    uint32_t count2;
};

struct join_list_s {
    uint32_t num;
    struct join_node_s nodes[JOIN_QUEUE_MAX];
};

/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS PROTOTYPES ------------------------------------------ */
int filter_init(void);
int filter_deinit(void);
int filter_up_proc(const uint8_t *payload, uint16_t size);
int filter_down_proc(const uint8_t *buff_down, uint16_t msg_len);


#endif
/* --- EOF ------------------------------------------------------------------ */
