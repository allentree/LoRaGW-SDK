
/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#define _GNU_SOURCE         /* needed for qsort_r to be defined */
#include <stdlib.h>         /* qsort_r */
#include <stdio.h>          /* printf, fprintf, snprintf, fopen, fputs */

#include <string.h>         /* memset */
#include <signal.h>         /* sigaction */
#include <time.h>           /* time, clock_gettime, strftime, gmtime */
#include <sys/time.h>       /* timeval */
#include <unistd.h>         /* getopt, access */
#include <stdlib.h>         /* atoi, exit */
#include <errno.h>          /* error messages */
#include <math.h>           /* modf */
#include <sys/socket.h>     /* socket specific definitions */
#include <netinet/in.h>     /* INET constants and stuff */
#include <assert.h>

#include <pthread.h>

#include "trace.h"
#include "loragw_hal.h"
#include "loragw_reg.h"
#include "loragw_aux.h"
#include "parson.h"
#include "base64.h"

#include "filter_node.h"

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */
#define FILTER_CONF_NAME    "filter_conf.json"

#define PROTOCOL_VERSION    2

#define FILTER_UP           0x80
#define FILTER_DOWN         0x81

#define FILTER_BUFF_SIZE    8192

#define FILTER_INITED_FLAG  0x55


/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS & TYPES -------------------------------------------- */
static pthread_mutex_t mx_join_list  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mx_black_list = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mx_white_list = PTHREAD_MUTEX_INITIALIZER;

/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES (GLOBAL) ------------------------------------------- */
struct join_list_s    join_list;
struct black_list_s   black_list;
struct white_list_s   white_list;
struct filter_s       g_filter;

/* -------------------------------------------------------------------------- */
/* --- PRIVATE SHARED VARIABLES (GLOBAL) ------------------------------------ */


/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DECLARATION ---------------------------------------- */

extern uint32_t net_mac_h;
extern uint32_t net_mac_l;
extern int sock_up;

int send_white_list_up_msg(uint8_t msg_type, uint64_t value, uint8_t type, uint8_t enable) {
    uint8_t buff_up[FILTER_BUFF_SIZE];
    int buff_index = 0;
    uint8_t token_h;
    uint8_t token_l;
    int i = 0, j = 0;
    int count = 0;
    struct white_list_s *list = &white_list;

    if ((msg_type < FILTER_W_G_NOTIFY) || (msg_type > FILTER_W_G_DELETE)) {
        MSG("INFO: [filter] invalid type:%u\n", msg_type);
        return -1;
    }
    
    token_h = (uint8_t)rand();
    token_l = (uint8_t)rand();

    memset(buff_up, 0, sizeof(buff_up));
    buff_up[0] = PROTOCOL_VERSION;
    buff_up[1] = token_h;
    buff_up[2] = token_l;
    buff_up[3] = FILTER_UP;
    *(uint32_t *)(buff_up + 4) = net_mac_h;
    *(uint32_t *)(buff_up + 8) = net_mac_l;
    buff_index = 12;

    memcpy((void *)(buff_up + buff_index), (void *)"{\"whitelist\":{", 14);
    buff_index += 14;

    if (msg_type == FILTER_W_G_NOTIFY) {
        j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "\"enable\":%u", list->enable);
        if (j > 0) {
            buff_index += j;
            buff_up[buff_index] = ',';
            ++buff_index;
        }

        memcpy((void *)(buff_up + buff_index), (void *)"\"action\":\"notify\"", 17);
        buff_index += 17;

        memcpy((void *)(buff_up + buff_index), (void *)",\"ouis\":[", 9);
        buff_index += 9;
        count = 0;
        for (i = 0; i < (int)list->num; i++) {
            if (list->nodes[i].type == FILTER_TYPE_OUI) {
                j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"oui\":\"%llX\",\"enable\":%u},", 
                    list->nodes[i].value, list->nodes[i].enable);
                if (j > 0) {
                    buff_index += j;
                    count++;
                }
            }
        }
        if (count > 0) {
            buff_index -= 1;
            buff_up[buff_index] = ']';
            ++buff_index;
        } else {
            buff_index -= 9;
        }

        memcpy((void *)(buff_up + buff_index), (void *)",\"netids\":[", 11);
        buff_index += 11;
        count = 0;
        for (i = 0; i < (int)list->num; i++) {
            if (list->nodes[i].type == FILTER_TYPE_NETID) {
                j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"netid\":%llu,\"enable\":%u},", 
                    list->nodes[i].value, list->nodes[i].enable);
                if (j > 0) {
                    buff_index += j;
                    count++;
                }
            }
        }
        if (count > 0) {
            buff_index -= 1;
            buff_up[buff_index] = ']';
            ++buff_index;
        } else {
            buff_index -= 11;
        }

        memcpy((void *)(buff_up + buff_index), (void *)",\"deveuis\":[", 12);
        buff_index += 12;
        count = 0;
        for (i = 0; i < (int)list->num; i++) {
            if (list->nodes[i].type == FILTER_TYPE_DEVEUI) {
                j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"deveui\":\"%llX\"},", 
                    list->nodes[i].value);
                if (j > 0) {
                    buff_index += j;
                    count++;
                }
            }
        }
        if (count > 0) {
            buff_index -= 1;
            buff_up[buff_index] = ']';
            ++buff_index;
        } else {
            buff_index -= 12;
        }

        memcpy((void *)(buff_up + buff_index), (void *)",\"devaddrs\":[", 13);
        buff_index += 13;
        count = 0;
        for (i = 0; i < (int)list->num; i++) {
            if (list->nodes[i].type == FILTER_TYPE_DEVADDR) {
                j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"devaddr\":\"%llX\"},", 
                    list->nodes[i].value);
                if (j > 0) {
                    buff_index += j;
                    count++;
                }
            }
        }
        if (count > 0) {
            buff_index -= 1;
            buff_up[buff_index] = ']';
            ++buff_index;
        } else {
            buff_index -= 13;
        }
    } else if (msg_type == FILTER_W_G_ADD) { 
        memcpy((void *)(buff_up + buff_index), (void *)"\"action\":\"add\"", 14);
        buff_index += 14;

        if (type == FILTER_TYPE_OUI) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"oui\":\"%llX\",\"enable\":%u", value, enable);
            if (j > 0) {
                buff_index += j;
            }
        } else if (type == FILTER_TYPE_NETID) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"netid\":%llu,\"enable\":%u", value, enable);
            if (j > 0) {
                buff_index += j;
            }
        } else if (type == FILTER_TYPE_DEVEUI) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"deveui\":\"%llX\"", value);
            if (j > 0) {
                buff_index += j;
            }
        } else if (type == FILTER_TYPE_DEVADDR) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"devaddr\":\"%llX\"", value);
            if (j > 0) {
                buff_index += j;
            }
        }
    } else if (msg_type == FILTER_W_G_DELETE) { 
        memcpy((void *)(buff_up + buff_index), (void *)"\"action\":\"delete\"", 17);
        buff_index += 17;

        if (type == FILTER_TYPE_OUI) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"oui\":\"%llX\"", value);
            if (j > 0) {
                buff_index += j;
            }
        } else if (type == FILTER_TYPE_NETID) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"netid\":%llu", value);
            if (j > 0) {
                buff_index += j;
            }
        } else if (type == FILTER_TYPE_DEVEUI) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"deveui\":\"%llX\"", value);
            if (j > 0) {
                buff_index += j;
            }
        } else if (type == FILTER_TYPE_DEVADDR) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"devaddr\":\"%llX\"", value);
            if (j > 0) {
                buff_index += j;
            }
        }
    }

    memcpy((void *)(buff_up + buff_index), (void *)"}}", 2);
    buff_index += 2;
    buff_up[buff_index] = 0;

    MSG("INFO: [filter] white list up msg, buff_up: %s\n", (char *)(buff_up + 12));

    send(sock_up, (void *)buff_up, buff_index, 0);

    return 0;
}

int send_black_list_up_msg(uint8_t msg_type, uint64_t value, uint8_t type, uint32_t duration) {
    uint8_t buff_up[FILTER_BUFF_SIZE];
    int buff_index = 0;
    uint8_t token_h;
    uint8_t token_l;
    int i = 0, j = 0;
    int count = 0;
    struct black_list_s *list = &black_list;

    if ((msg_type < FILTER_B_G_NOTIFY) || (msg_type > FILTER_B_G_DELETE)) {
        MSG("INFO: [filter] invalid type:%u\n", msg_type);
        return -1;
    }

    token_h = (uint8_t)rand();
    token_l = (uint8_t)rand();

    memset(buff_up, 0, sizeof(buff_up));
    buff_up[0] = PROTOCOL_VERSION;
    buff_up[1] = token_h;
    buff_up[2] = token_l;
    buff_up[3] = FILTER_UP;
    *(uint32_t *)(buff_up + 4) = net_mac_h;
    *(uint32_t *)(buff_up + 8) = net_mac_l;
    buff_index = 12;

    memcpy((void *)(buff_up + buff_index), (void *)"{\"blacklist\":{", 14);
    buff_index += 14;
    
    if (msg_type == FILTER_B_G_NOTIFY) {
        j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "\"enable\":%u", list->enable);
        if (j > 0) {
            buff_index += j;
            buff_up[buff_index] = ',';
            ++buff_index;
        }

        memcpy((void *)(buff_up + buff_index), (void *)"\"action\":\"notify\"", 17);
        buff_index += 17;

        memcpy((void *)(buff_up + buff_index), (void *)",\"deveuis\":[", 12);
        buff_index += 12;
        count = 0;
        for (i = 0; i < (int)list->num; i++) {
            if (list->nodes[i].type == FILTER_TYPE_DEVEUI) {
                j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"deveui\":\"%llX\",\"duration\":%u},", 
                    list->nodes[i].value, list->nodes[i].duration);
                if (j > 0) {
                    buff_index += j;
                    count++;
                }
            }
        }
        if (count > 0) {
            buff_index -= 1;
            buff_up[buff_index] = ']';
            ++buff_index;
        } else {
            buff_index -= 12;
        }

        memcpy((void *)(buff_up + buff_index), (void *)",\"devaddrs\":[", 13);
        buff_index += 13;
        count = 0;
        for (i = 0; i < (int)list->num; i++) {
            if (list->nodes[i].type == FILTER_TYPE_DEVADDR) {
                j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"devaddr\":\"%llX\",\"duration\":%u},", 
                    list->nodes[i].value, list->nodes[i].duration);
                if (j > 0) {
                    buff_index += j;
                    count++;
                }
            }
        }
        if (count > 0) {
            buff_index -= 1;
            buff_up[buff_index] = ']';
            ++buff_index;
        } else {
            buff_index -= 13;
        }
    } else if (msg_type == FILTER_B_G_ADD) { 
        memcpy((void *)(buff_up + buff_index), (void *)"\"action\":\"add\"", 14);
        buff_index += 14;

        if ((type == FILTER_TYPE_DEVEUI) && (value != 0)) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"deveui\":\"%llX\",\"duration\":%u", 
                value, duration);
            if (j > 0) {
                buff_index += j;
            }
        } else if ((type == FILTER_TYPE_DEVADDR) && (value != 0)) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"devaddr\":\"%llX\",\"duration\":%u", 
                value, duration);
            if (j > 0) {
                buff_index += j;
            }
        }
    } else if (msg_type == FILTER_B_G_DELETE) { 
        memcpy((void *)(buff_up + buff_index), (void *)"\"action\":\"delete\"", 17);
        buff_index += 17;

        if ((type == FILTER_TYPE_DEVEUI) && (value != 0)) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"deveui\":\"%llX\"", value);
            if (j > 0) {
                buff_index += j;
            }
        } else if ((type == FILTER_TYPE_DEVADDR) && (value != 0)) {
            j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"devaddr\":\"%llX\"", value);
            if (j > 0) {
                buff_index += j;
            }
        }
    }

    memcpy((void *)(buff_up + buff_index), (void *)"}}", 2);
    buff_index += 2;
    buff_up[buff_index] = 0;

    MSG("INFO: [filter] black list up msg, buff_up: %s\n", (char *)(buff_up + 12));

    send(sock_up, (void *)buff_up, buff_index, 0);

    return 0;
}

int send_config_up_msg(uint8_t msg_type) {
    uint8_t buff_up[FILTER_BUFF_SIZE];
    int buff_index = 0;
    uint8_t token_h;
    uint8_t token_l;
    int j = 0;
    struct filter_s *filter = &g_filter;

    if (msg_type != FILTER_C_G_NOTIFY) {
        MSG("INFO: [filter] invalid type:%u\n", msg_type);
        return -1;
    }

    token_h = (uint8_t)rand();
    token_l = (uint8_t)rand();

    memset(buff_up, 0, sizeof(buff_up));
    buff_up[0] = PROTOCOL_VERSION;
    buff_up[1] = token_h;
    buff_up[2] = token_l;
    buff_up[3] = FILTER_UP;
    *(uint32_t *)(buff_up + 4) = net_mac_h;
    *(uint32_t *)(buff_up + 8) = net_mac_l;
    buff_index = 12;

    memcpy((void *)(buff_up + buff_index), (void *)"{\"filter_conf\":{", 16);
    buff_index += 16;
    
    memcpy((void *)(buff_up + buff_index), (void *)"\"action\":\"notify\"", 17);
    buff_index += 17;

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"wl_enable\":%u", white_list.enable);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"bl_enable\":%u", black_list.enable);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"binding\":%u", white_list.binding);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"bl_duration\":%u", filter->bl_duration);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_period\":%u", filter->join_period);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_interval\":%u", filter->join_interval);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_count1\":%u", filter->join_count1);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_up + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_count2\":%u", filter->join_count2);
    if (j > 0) {
        buff_index += j;
    }

    memcpy((void *)(buff_up + buff_index), (void *)"}}", 2);
    buff_index += 2;
    buff_up[buff_index] = 0;

    MSG("INFO: [filter] filter_conf up msg, buff_up: %s\n", (char *)(buff_up + 12));

    send(sock_up, (void *)buff_up, buff_index, 0);

    return 0;
}

int white_list_compare(const void *a, const void *b, void *arg)
{
    struct white_list_node_s *p = (struct white_list_node_s *)a;
    struct white_list_node_s *q = (struct white_list_node_s *)b;
    int *counter = (int *)arg;
    int p_count, q_count;

    p_count = p->time;
    q_count = q->time;

    if (p_count > q_count)
        *counter = *counter + 1;

    return p_count - q_count;
}

void white_list_sort(struct white_list_s *list) {
    int counter = 0;

    if (0 == list->num) {
        return;
    }

    qsort_r(list->nodes, list->num, sizeof(list->nodes[0]), white_list_compare, &counter);
}

void white_list_print(struct white_list_s *list) {
    int i = 0;

    if (0 == list->num) {
        MSG("INFO: [filter] white list is empty\n");
    } else {
        pthread_mutex_lock(&mx_white_list);

        MSG("INFO: [filter] white list contains %d nodes\n", list->num);
        for (i = 0; i < (int)list->num; i++) {
            MSG("INFO: [filter] - node[%d]: time:%llu, value:%llX, type:%u, enable:%u\n", i,
            list->nodes[i].time, list->nodes[i].value, list->nodes[i].type, list->nodes[i].enable);
        }

        pthread_mutex_unlock(&mx_white_list);
    }
}

int white_list_add_node(struct white_list_s *list, uint64_t value, uint8_t type, uint8_t enable, bool need_send) {
    struct timeval cur_unix_time;
    uint64_t time_us = 0;
    int i = 0;

    if (type >= FILTER_TYPE_MAX) {
        MSG("ERROR: [filter] the white list node type is invalid\n");
        return -1;
    }

    if ((0 != enable) && (1 != enable)) {
        MSG("ERROR: [filter] the white list node enable is invalid\n");
        return -1;
    }

    gettimeofday(&cur_unix_time, NULL);
    time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;

    for (i = 0; i < (int)list->num; i++) {
        if ((value == list->nodes[i].value) && (type == list->nodes[i].type)) {
            if (enable == list->nodes[i].enable) {
                MSG("INFO: [filter] the white list node:%llX is exist and no change\n", value);
                return -1;
            } else {
                pthread_mutex_lock(&mx_white_list);
                list->nodes[i].enable = enable;
                list->nodes[i].time = time_us;
                white_list_sort(list);
                pthread_mutex_unlock(&mx_white_list);

                MSG("INFO: [filter] white list update node, time_us: %llu, value: %llX\n", time_us, value);
                if (need_send) {
                    send_white_list_up_msg(FILTER_W_G_ADD, value, type, enable);
                }
                return 0;
            }
        }
    }

    if (list->num == WHITE_LIST_MAX) {
        MSG("INFO: [filter] white list is full, skip\n");
        return -1;
    }

    pthread_mutex_lock(&mx_white_list);
    list->nodes[list->num].type = type;
    list->nodes[list->num].value = value;
    list->nodes[list->num].enable = enable;
    list->nodes[list->num].time = time_us;
    list->num++;
    white_list_sort(list);
    pthread_mutex_unlock(&mx_white_list);

    MSG("INFO: [filter] white list add node, time_us: %llu, value: %llX\n", time_us, value);
    // white_list_print(list);

    if (need_send) {
        send_white_list_up_msg(FILTER_W_G_ADD, value, type, enable);
    }

    return 0;
}

int white_list_del_node(struct white_list_s *list, uint64_t value, uint8_t type) {
    int i = 0;
    int update = 0;
    struct timeval cur_unix_time;
    uint64_t time_us = 0;

    if (type >= FILTER_TYPE_MAX) {
        MSG("ERROR: [filter] the white list node type is invalid\n");
        return -1;
    }

    if (0 == list->num) {
        MSG("INFO: [filter] white list is empty\n");
        return -1;
    }

    gettimeofday(&cur_unix_time, NULL);
    time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;

    pthread_mutex_lock(&mx_white_list);
    for (i = 0; i < (int)list->num; i++) {
        if ((value == list->nodes[i].value) && (type == list->nodes[i].type)) {
            list->nodes[i].value = 0;
            list->nodes[i].type = FILTER_TYPE_MAX;
            list->nodes[i].time = time_us;
            white_list_sort(list);
            list->num--;
            update = 1;
            break;
        }
    }
    pthread_mutex_unlock(&mx_white_list);

    if (1 == update) {
        MSG("INFO: [filter] white list del node, value: %llX\n", value);
        // white_list_print(list);

        send_white_list_up_msg(FILTER_W_G_DELETE, value, type, 0);
        return 0;
    }

    return -1;
}

int black_list_compare(const void *a, const void *b, void *arg)
{
    struct black_list_node_s *p = (struct black_list_node_s *)a;
    struct black_list_node_s *q = (struct black_list_node_s *)b;
    int *counter = (int *)arg;
    int p_count, q_count;

    p_count = p->time;
    q_count = q->time;

    if (p_count > q_count)
        *counter = *counter + 1;

    return p_count - q_count;
}

void black_list_sort(struct black_list_s *list) {
    int counter = 0;

    if (0 == list->num) {
        return;
    }

    qsort_r(list->nodes, list->num, sizeof(list->nodes[0]), black_list_compare, &counter);
}

void black_list_print(struct black_list_s *list) {
    int i = 0;

    if (0 == list->num) {
        MSG("INFO: [filter] black list is empty\n");
    } else {
        pthread_mutex_lock(&mx_black_list);

        MSG("INFO: [filter] black list contains %d nodes\n", list->num);
        for (i = 0; i < (int)list->num; i++) {
            MSG("INFO: [filter] - node[%d]: time:%llu, type:%u, value:%llX, duration:%u\n", i,
            list->nodes[i].time, list->nodes[i].type, list->nodes[i].value, list->nodes[i].duration);
        }

        pthread_mutex_unlock(&mx_black_list);
    }
}

int black_list_add_node(struct black_list_s *list, uint64_t value, uint8_t type, uint32_t duration) {
    uint64_t old_value = 0;
    uint8_t old_type = 0;
    struct timeval cur_unix_time;
    uint64_t time_us = 0;
    int i = 0;

    if ((0 == value) || (type >= FILTER_TYPE_MAX)) {
        MSG("ERROR: [filter] the black list node value or type is invalid\n");
        return -1;
    }

    gettimeofday(&cur_unix_time, NULL);
    time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;

    for (i = 0; i < (int)list->num; i++) {
        if ((value == list->nodes[i].value) && (type == list->nodes[i].type)) {
            pthread_mutex_lock(&mx_black_list);
            list->nodes[i].time = time_us;
            list->nodes[i].duration = duration;
            black_list_sort(list);
            pthread_mutex_unlock(&mx_black_list);

            MSG("INFO: [filter] black list update node, time_us: %llu, value: %llX\n", time_us, value);
            send_black_list_up_msg(FILTER_B_G_ADD, value, type, duration);
            return 0;
        }
    }

    pthread_mutex_lock(&mx_black_list);
    if (list->num == BLACK_LIST_MAX) {
        old_value = list->nodes[0].value;
        old_type = list->nodes[0].type;
        list->nodes[0].type = type;
        list->nodes[0].value = value;
        list->nodes[0].time = time_us;
        list->nodes[0].duration = duration;
    } else {
        list->nodes[list->num].type = type;
        list->nodes[list->num].value = value;
        list->nodes[list->num].time = time_us;
        list->nodes[list->num].duration = duration;
        list->num++;
    }
    black_list_sort(list);
    pthread_mutex_unlock(&mx_black_list);

    MSG("INFO: [filter] black list add node, time_us: %llu, value: %llX\n", time_us, value);
    // black_list_print(list);

    if (0 != old_value) {
        send_black_list_up_msg(FILTER_B_G_DELETE, old_value, old_type, 0);
    }
    send_black_list_up_msg(FILTER_B_G_ADD, value, type, duration);

    return 0;
}

int black_list_del_node(struct black_list_s *list, uint64_t value, uint8_t type) {
    int i = 0;
    int update = 0;
    struct timeval cur_unix_time;
    uint64_t time_us = 0;

    if ((0 == value) || (type >= FILTER_TYPE_MAX)) {
        MSG("ERROR: [filter] the black list node value or type is invalid\n");
        return -1;
    }

    if (0 == list->num) {
        MSG("INFO: [filter] black list is empty\n");
        return -1;
    }

    gettimeofday(&cur_unix_time, NULL);
    time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;

    pthread_mutex_lock(&mx_black_list);
    for (i = 0; i < (int)list->num; i++) {
        if ((value == list->nodes[i].value) && (type == list->nodes[i].type)) {
            list->nodes[i].value = 0;
            list->nodes[i].type = FILTER_TYPE_MAX;
            list->nodes[i].time = time_us;
            black_list_sort(list);
            list->num--;
            update = 1;
            break;
        }
    }
    pthread_mutex_unlock(&mx_black_list);

    if (1 == update) {
        MSG("INFO: [filter] black list del node, value: %llX\n", value);
        // black_list_print(list);

        send_black_list_up_msg(FILTER_B_G_DELETE, value, type, 0);
    }

    return 0;
}

int join_list_compare(const void *a, const void *b, void *arg)
{
    struct join_node_s *p = (struct join_node_s *)a;
    struct join_node_s *q = (struct join_node_s *)b;
    int *counter = (int *)arg;
    int p_count, q_count;

    p_count = p->f_time;
    q_count = q->f_time;

    if (p_count > q_count)
        *counter = *counter + 1;

    return p_count - q_count;
}

void join_list_sort(struct join_list_s *list) {
    int counter = 0;

    if (0 == list->num) {
        return;
    }

    qsort_r(list->nodes, list->num, sizeof(list->nodes[0]), join_list_compare, &counter);
}

void join_list_print(struct join_list_s *list) {
    int i = 0;

    if (0 == list->num) {
        MSG("INFO: [filter] join list is empty\n");
    } else {
        pthread_mutex_lock(&mx_join_list);

        MSG("INFO: [filter] join list contains %d nodes\n", list->num);
        for (i = 0; i < (int)list->num; i++) {
            MSG("INFO: [filter] - node[%d]: f_time:%llu, l_time:%llu, value:%llX, count1:%u, count2:%u\n", i,
            list->nodes[i].f_time, list->nodes[i].l_time, list->nodes[i].value,
            list->nodes[i].count1, list->nodes[i].count2);
        }

        pthread_mutex_unlock(&mx_join_list);
    }
}

int join_list_del_node(struct join_list_s *list, uint64_t value) {
    int i = 0;
    int update = 0;
    struct timeval cur_unix_time;
    uint64_t time_us = 0;

    if (0 == value) {
        MSG("INFO: [filter] the join list node value is invalid\n");
        return -1;
    }

    if (0 == list->num) {
        MSG("INFO: [filter] join list is empty\n");
        return -1;
    }

    gettimeofday(&cur_unix_time, NULL);
    time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;

    pthread_mutex_lock(&mx_join_list);
    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].value == value) {
            list->nodes[i].value = 0;
            list->nodes[i].f_time = time_us;
            join_list_sort(list);
            list->num--;
            update = 1;
            break;
        }
    }
    pthread_mutex_unlock(&mx_join_list);

    if (1 == update) {
        MSG("INFO: [filter] join list del node, value: %llX\n", value);
        // join_list_print(list);
    }

    return 0;
}

int join_list_add_node(struct join_list_s *list, uint64_t time_us, uint64_t value) {
    int i = 0;
    struct filter_s *filter = &g_filter;

    if (0 == value) {
        MSG("INFO: [filter] the join list node value is invalid\n");
        return -1;
    }

    pthread_mutex_lock(&mx_join_list);

    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].value == value) {
            if ((time_us > list->nodes[i].l_time) 
                && (time_us - list->nodes[i].l_time) < ((uint64_t)filter->join_interval * 1000000UL)) {
                list->nodes[i].count1++;
            } else {
                list->nodes[i].count1 = 1;
            }

            list->nodes[i].count2++;
            list->nodes[i].l_time = time_us;

            if ((list->nodes[i].count1 >= filter->join_count1)
                || (list->nodes[i].count2 >= filter->join_count2)) {
                MSG("INFO: [filter] The deveui:%llX join count1:%u or count2:%u out of threshold, need add to black list\n", 
                    value, list->nodes[i].count1, list->nodes[i].count2);
                black_list_add_node(&black_list, value, FILTER_TYPE_DEVEUI, filter->bl_duration);

                pthread_mutex_unlock(&mx_join_list);

                join_list_del_node(list, value);
            } else {
                pthread_mutex_unlock(&mx_join_list);
            }

            // join_list_print(list);

            return 0;
        }
    }

    if (list->num == JOIN_QUEUE_MAX) {
        list->nodes[0].value = value;
        list->nodes[0].f_time = time_us;
        list->nodes[0].l_time = time_us;
        list->nodes[0].count1 = 1;
        list->nodes[0].count2 = 1;
    } else {
        list->nodes[list->num].value = value;
        list->nodes[list->num].f_time = time_us;
        list->nodes[list->num].l_time = time_us;
        list->nodes[list->num].count1 = 1;
        list->nodes[list->num].count2 = 1;
        list->num++;
    }
    join_list_sort(list);

    pthread_mutex_unlock(&mx_join_list);

    MSG("INFO: [filter] join list add node, time_us: %llu, value: %llX\n", time_us, value);
    // join_list_print(list);

    return 0;
}

int parse_white_list_conf(const char *conf_file) {
    const char conf_obj_name[] = "whitelist";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    JSON_Value *val = NULL;
    JSON_Array *node_array = NULL;
    JSON_Object *node_obj = NULL;
    uint64_t value = 0;
    uint8_t enable = 0;
    uint8_t binding = 0;
    const char *str;
    int i = 0;
    int node_cnt = 0;

    root_val = json_parse_file_with_comments(conf_file);
    if (root_val == NULL) {
        MSG("ERROR: [filter] %s is not a valid JSON file\n", conf_file);
        return -1;
    }

    conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
    if (conf_obj == NULL) {
        MSG("ERROR: [filter] %s does not contain a JSON object named %s\n", conf_file, conf_obj_name);
        json_value_free(root_val);
        return -1;
    }

    val = json_object_get_value(conf_obj, "enable");
    if (val != NULL) {
        enable = (uint8_t)json_value_get_number(val);
        if (1 != enable) {
            enable = 0;
        }
        MSG("INFO: [filter] white list enable: %u\n", enable);
        white_list.enable = enable;
    } 

    val = json_object_get_value(conf_obj, "binding");
    if (val != NULL) {
        binding = (uint8_t)json_value_get_number(val);
        if (1 != binding) {
            binding = 0;
        }
        MSG("INFO: [filter] white list binding: %u\n", binding);
        white_list.binding = binding;
    } 

    node_array = json_object_get_array(conf_obj, "ouis");
    if (node_array != NULL) {
        node_cnt = (int)json_array_get_count(node_array);
        MSG("INFO: [filter] white list contains ouis count: %u\n", node_cnt);

        for (i = 0; i < node_cnt; i++) {
            node_obj = json_array_get_object(node_array, i);
            str = json_object_get_string(node_obj, "oui");
            if (str != NULL) {
                sscanf(str, "%llX", &value);
                MSG("INFO: [filter] oui: %llX\n", value);

                enable = 0;
                val = json_object_dotget_value(node_obj, "enable");
                if (val != NULL) {
                    enable = (uint8_t)json_value_get_number(val);
                    if (1 != enable) {
                        enable = 0;
                    }
                }

                white_list_add_node(&white_list, value, FILTER_TYPE_OUI, enable, false);
            }
        }
    }

    node_array = json_object_get_array(conf_obj, "netids");
    if (node_array != NULL) {
        node_cnt = (int)json_array_get_count(node_array);
        MSG("INFO: [filter] white list contains netids count: %u\n", node_cnt);

        for (i = 0; i < node_cnt; i++) {
            node_obj = json_array_get_object(node_array, i);
            val = json_object_dotget_value(node_obj, "netid");
            if (val != NULL) {
                value = (uint32_t)json_value_get_number(val);
                MSG("INFO: [filter] netid: %llu\n", value);
        
                enable = 0;
                val = json_object_dotget_value(node_obj, "enable");
                if (val != NULL) {
                    enable = (uint8_t)json_value_get_number(val);
                    if (1 != enable) {
                        enable = 0;
                    }
                }
        
                white_list_add_node(&white_list, value, FILTER_TYPE_NETID, enable, false);
            }
        }
    }

    node_array = json_object_get_array(conf_obj, "deveuis");
    if (node_array != NULL) {
        node_cnt = (int)json_array_get_count(node_array);
        MSG("INFO: [filter] white list contains deveuis count: %u\n", node_cnt);

        for (i = 0; i < node_cnt; i++) {
            node_obj = json_array_get_object(node_array, i);
            str = json_object_get_string(node_obj, "deveui");
            if (str != NULL) {
                sscanf(str, "%llX", &value);
                MSG("INFO: [filter] deveui: %llX\n", value);

                white_list_add_node(&white_list, value, FILTER_TYPE_DEVEUI, 1, false);
            }
        }
    }

    node_array = json_object_get_array(conf_obj, "devaddrs");
    if (node_array != NULL) {
        node_cnt = (int)json_array_get_count(node_array);
        MSG("INFO: [filter] white list contains devaddrs count: %u\n", node_cnt);

        for (i = 0; i < node_cnt; i++) {
            node_obj = json_array_get_object(node_array, i);
            str = json_object_get_string(node_obj, "devaddr");
            if (str != NULL) {
                sscanf(str, "%llX", &value);
                MSG("INFO: [filter] devaddr: %llX\n", value);

                white_list_add_node(&white_list, value, FILTER_TYPE_DEVADDR, 1, false);
            }
        }
    }

    json_value_free(root_val);
    return 0;
}

int parse_filter_conf(const char *conf_file) {
    const char conf_obj_name[] = "filter_conf";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    JSON_Value *val = NULL;
    uint8_t enable = 0;
    struct filter_s *filter = &g_filter;

    root_val = json_parse_file_with_comments(conf_file);
    if (root_val == NULL) {
        MSG("ERROR: [filter] %s is not a valid JSON file\n", conf_file);
        return -1;
    }

    conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
    if (conf_obj == NULL) {
        MSG("INFO: [filter] %s does not contain a JSON object named %s\n", conf_file, conf_obj_name);
        json_value_free(root_val);
        return -1;
    }

    val = json_object_get_value(conf_obj, "bl_enable");
    if (val != NULL) {
        enable = (uint8_t)json_value_get_number(val);
        if (1 != enable) {
            enable = 0;
        }
        MSG("INFO: [filter] bl_enable: %u\n", enable);
        black_list.enable = enable;
    }

    val = json_object_get_value(conf_obj, "bl_duration");
    if (val != NULL) {
        filter->bl_duration = (uint32_t)json_value_get_number(val);
        MSG("INFO: [filter] bl_duration: %u\n", filter->bl_duration);
    }

    val = json_object_get_value(conf_obj, "join_period");
    if (val != NULL) {
        filter->join_period = (uint32_t)json_value_get_number(val);
        MSG("INFO: [filter] join_period: %u\n", filter->join_period);
    }

    val = json_object_get_value(conf_obj, "join_interval");
    if (val != NULL) {
        filter->join_interval = (uint32_t)json_value_get_number(val);
        MSG("INFO: [filter] join_interval: %u\n", filter->join_interval);
    }

    val = json_object_get_value(conf_obj, "join_count1");
    if (val != NULL) {
        filter->join_count1 = (uint32_t)json_value_get_number(val);
        MSG("INFO: [filter] join_count1: %u\n", filter->join_count1);
    }

    val = json_object_get_value(conf_obj, "join_count2");
    if (val != NULL) {
        filter->join_count2 = (uint32_t)json_value_get_number(val);
        MSG("INFO: [filter] join_count2: %u\n", filter->join_count2);
    }

    json_value_free(root_val);
    return 0;
}

int update_filter_conf(const char *conf_file) {
    uint8_t buff_conf[FILTER_BUFF_SIZE];
    int buff_index = 0;
    int i = 0, j = 0;
    int node_cnt = 0;
    struct white_list_s *list = &white_list;
    struct filter_s *filter = &g_filter;
    FILE *conf_fp = NULL;

    memset(buff_conf, 0, sizeof(buff_conf));

    memcpy((void *)(buff_conf + buff_index), (void *)"{\"whitelist\":{", 14);
    buff_index += 14;

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, "\"enable\":%u", list->enable);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"binding\":%u", list->binding);
    if (j > 0) {
        buff_index += j;
    }

    memcpy((void *)(buff_conf + buff_index), (void *)",\"ouis\":[", 9);
    buff_index += 9;
    node_cnt = 0;
    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].type == FILTER_TYPE_OUI) {
            j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"oui\":\"%llX\",\"enable\":%u},", 
                list->nodes[i].value, list->nodes[i].enable);
            if (j > 0) {
                buff_index += j;
                node_cnt++;
            }
        }
    }
    if (node_cnt > 0) {
        buff_index -= 1;
        buff_conf[buff_index] = ']';
        ++buff_index;
    } else {
        buff_index -= 9;
    }

    memcpy((void *)(buff_conf + buff_index), (void *)",\"netids\":[", 11);
    buff_index += 11;
    node_cnt = 0;
    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].type == FILTER_TYPE_NETID) {
            j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"netid\":%llu,\"enable\":%u},", 
                list->nodes[i].value, list->nodes[i].enable);
            if (j > 0) {
                buff_index += j;
                node_cnt++;
            }
        }
    }
    if (node_cnt > 0) {
        buff_index -= 1;
        buff_conf[buff_index] = ']';
        ++buff_index;
    } else {
        buff_index -= 11;
    }

    memcpy((void *)(buff_conf + buff_index), (void *)",\"deveuis\":[", 12);
    buff_index += 12;
    node_cnt = 0;
    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].type == FILTER_TYPE_DEVEUI) {
            j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"deveui\":\"%llX\"},", 
                list->nodes[i].value);
            if (j > 0) {
                buff_index += j;
                node_cnt++;
            }
        }
    }
    if (node_cnt > 0) {
        buff_index -= 1;
        buff_conf[buff_index] = ']';
        ++buff_index;
    } else {
        buff_index -= 12;
    }

    memcpy((void *)(buff_conf + buff_index), (void *)",\"devaddrs\":[", 13);
    buff_index += 13;
    node_cnt = 0;
    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].type == FILTER_TYPE_DEVADDR) {
            j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, "{\"devaddr\":\"%llX\"},", 
                list->nodes[i].value);
            if (j > 0) {
                buff_index += j;
                node_cnt++;
            }
        }
    }
    if (node_cnt > 0) {
        buff_index -= 1;
        buff_conf[buff_index] = ']';
        ++buff_index;
    } else {
        buff_index -= 13;
    }

    memcpy((void *)(buff_conf + buff_index), (void *)"},\"filter_conf\":{", 17);
    buff_index += 17;

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, "\"bl_enable\":%u", black_list.enable);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"bl_duration\":%u", filter->bl_duration);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_period\":%u", filter->join_period);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_interval\":%u", filter->join_interval);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_count1\":%u", filter->join_count1);
    if (j > 0) {
        buff_index += j;
    }

    j = snprintf((char *)(buff_conf + buff_index), FILTER_BUFF_SIZE-buff_index, ",\"join_count2\":%u", filter->join_count2);
    if (j > 0) {
        buff_index += j;
    }

    memcpy((void *)(buff_conf + buff_index), (void *)"}}", 2);
    buff_index += 2;
    buff_conf[buff_index] = 0;

    MSG("INFO: [filter] update filter config file, buff_conf: %s\n", (char *)buff_conf);

    conf_fp = fopen(conf_file, "wb");
    if (NULL == conf_fp) {
        MSG("INFO: [filter] fopen config file:%s failed\n", conf_file);
        return -1;
    }

    j = fwrite(buff_conf, 1, buff_index, conf_fp);
    if (j != buff_index) {
        MSG("INFO: [filter] fwrite failed, %d != %d\n", j, buff_index);
        fclose(conf_fp);
        conf_fp = NULL;
        return -1;
    }

    fclose(conf_fp);
    conf_fp = NULL;
    return 0;
}

int handle_white_list_down_msg(JSON_Object *conf_obj) {
    JSON_Value *val = NULL;
    const char *str;
    uint64_t value = 0;
    uint8_t enable = 0;
    uint8_t update = 0;
    int ret = -1; 

    if (conf_obj == NULL) {
        MSG("WARNING: [filter] no \"whitelist\" object in JSON\n");
        return -1;
    }

    val = json_object_get_value(conf_obj, "enable");
    if (val != NULL) {
        if (json_value_get_type(val) == JSONNumber) {
            enable = (uint8_t)json_value_get_number(val);
            MSG("INFO: [filter] enable: %u\n", enable);
        }
    }

    str = json_object_get_string(conf_obj, "action");
    if (str == NULL) {
        MSG("WARNING: [filter] no mandatory \"action\" object in JSON\n");
        return -1;
    }

    if (strcmp(str, "add") == 0) {
        MSG("INFO: [filter] white list add msg\n");
        str = json_object_get_string(conf_obj, "oui");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] oui: %llX\n", value);
            ret = white_list_add_node(&white_list, value, FILTER_TYPE_OUI, enable, true);
            if (0 == ret) {
                update = 1;
            }
        }

        str = json_object_get_string(conf_obj, "deveui");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] deveui: %llX\n", value);
            ret = white_list_add_node(&white_list, value, FILTER_TYPE_DEVEUI, enable, true);
            if (0 == ret) {
                update = 1;
            }
        }

        str = json_object_get_string(conf_obj, "devaddr");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] devaddr: %llX\n", value);
            ret = white_list_add_node(&white_list, value, FILTER_TYPE_DEVADDR, enable, true);
            if (0 == ret) {
                update = 1;
            }
        }

        val = json_object_get_value(conf_obj, "netid");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                value = (uint64_t)json_value_get_number(val);
                MSG("INFO: [filter] netid: %llu\n", value);
                ret = white_list_add_node(&white_list, value, FILTER_TYPE_NETID, enable, true);
                if (0 == ret) {
                    update = 1;
                }
            }
        }
    } else if (strcmp(str, "delete") == 0) {
        MSG("INFO: [filter] white list delete msg\n");
        str = json_object_get_string(conf_obj, "oui");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] oui: %llX\n", value);
            ret = white_list_del_node(&white_list, value, FILTER_TYPE_OUI);
            if (0 == ret) {
                update = 1;
            }
        }

        str = json_object_get_string(conf_obj, "deveui");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] deveui: %llX\n", value);
            ret = white_list_del_node(&white_list, value, FILTER_TYPE_DEVEUI);
            if (0 == ret) {
                update = 1;
            }
        }
        
        str = json_object_get_string(conf_obj, "devaddr");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] devaddr: %llX\n", value);
            ret = white_list_del_node(&white_list, value, FILTER_TYPE_DEVADDR);
            if (0 == ret) {
                update = 1;
            }
        }

        val = json_object_get_value(conf_obj, "netid");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                value = (uint64_t)json_value_get_number(val);
                MSG("INFO: [filter] netid: %llu\n", value);
                ret = white_list_del_node(&white_list, value, FILTER_TYPE_NETID);
                if (0 == ret) {
                    update = 1;
                }
            }
        }
    } else if (strcmp(str, "get") == 0) {
        MSG("INFO: [filter] white list get msg\n");
        send_white_list_up_msg(FILTER_W_G_NOTIFY, 0, 0, 0);
    }

    if (1 == update) {
        update_filter_conf(FILTER_CONF_NAME);
    }

    return 0;
}

int handle_black_list_down_msg(JSON_Object *conf_obj) {
    JSON_Value *val = NULL;
    const char *str;
    uint64_t value = 0;
    uint32_t duration = g_filter.bl_duration;

    if (conf_obj == NULL) {
        MSG("WARNING: [filter] no \"blacklist\" object in JSON\n");
        return -1;
    }

    val = json_object_get_value(conf_obj, "duration");
    if (val != NULL) {
        if (json_value_get_type(val) == JSONNumber) {
            duration = (uint32_t)json_value_get_number(val);
            MSG("INFO: [filter] duration: %u\n", duration); 
        }
    }

    str = json_object_get_string(conf_obj, "action");
    if (str == NULL) {
        MSG("WARNING: [filter] no mandatory \"action\" object in JSON\n");
        return -1;
    }

    if (strcmp(str, "add") == 0) {
        MSG("INFO: [filter] black list add msg\n");
        str = json_object_get_string(conf_obj, "deveui");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] deveui: %llX\n", value);
            black_list_add_node(&black_list, value, FILTER_TYPE_DEVEUI, duration);
        }

        str = json_object_get_string(conf_obj, "devaddr");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] devaddr: %llX\n", value);
            black_list_add_node(&black_list, value, FILTER_TYPE_DEVADDR, duration);
        }
    } else if (strcmp(str, "delete") == 0) {
        MSG("INFO: [filter] black list delete msg\n");
        str = json_object_get_string(conf_obj, "deveui");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] deveui: %llX\n", value);
            black_list_del_node(&black_list, value, FILTER_TYPE_DEVEUI);
        }

        str = json_object_get_string(conf_obj, "devaddr");
        if ((str != NULL) && (strlen(str) > 0)) {
            sscanf(str, "%llX", &value);
            MSG("INFO: [filter] devaddr: %llX\n", value);
            black_list_del_node(&black_list, value, FILTER_TYPE_DEVADDR);
        }
    } else if (strcmp(str, "get") == 0) {
        MSG("INFO: [filter] black list get msg\n");
        send_black_list_up_msg(FILTER_B_G_NOTIFY, 0, 0, 0);
    }

    return 0;
}

int handle_config_down_msg(JSON_Object *conf_obj) {
    JSON_Value *val = NULL;
    const char *str;
    uint32_t value = 0;
    uint8_t wl_enable = 0;
    uint8_t bl_enable = 0;
    uint8_t binding = 0;
    uint8_t update = 0;
    struct filter_s *filter = &g_filter;

    if (conf_obj == NULL) {
        MSG("WARNING: [filter] no \"filter_conf\" object in JSON\n");
        return -1;
    }

    str = json_object_get_string(conf_obj, "action");
    if (str == NULL) {
        MSG("WARNING: [filter] no mandatory \"action\" object in JSON\n");
        return -1;
    }

    if (strcmp(str, "config") == 0) {    
        val = json_object_get_value(conf_obj, "bl_duration");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                value = (uint32_t)json_value_get_number(val);
                if (value != filter->bl_duration) {
                    MSG("INFO: [filter] bl_duration: %u\n", value);
                    filter->bl_duration = value;
                    update = 1;
                }
            }
        }

        val = json_object_get_value(conf_obj, "join_period");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                value = (uint32_t)json_value_get_number(val);
                if (value != filter->join_period) {
                    MSG("INFO: [filter] join_period: %u\n", value);
                    filter->join_period = value;
                    update = 1;
                }
            }
        }

        val = json_object_get_value(conf_obj, "join_interval");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                value = (uint32_t)json_value_get_number(val);
                if (value != filter->join_interval) {
                    MSG("INFO: [filter] join_interval: %u\n", value);
                    filter->join_interval = value;
                    update = 1;
                }
            }
        }

        val = json_object_get_value(conf_obj, "join_count1");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                value = (uint32_t)json_value_get_number(val);
                if (value != filter->join_count1) {
                    MSG("INFO: [filter] join_count1: %u\n", value);
                    filter->join_count1 = value;
                    update = 1;
                }
            }
        }
        
        val = json_object_get_value(conf_obj, "join_count2");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                value = (uint32_t)json_value_get_number(val);
                if (value != filter->join_count2) {
                    MSG("INFO: [filter] join_count2: %u\n", value);
                    filter->join_count2 = value;
                    update = 1;
                }
            }
        }

        val = json_object_get_value(conf_obj, "bl_enable");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                bl_enable = (uint8_t)json_value_get_number(val);
                if ((bl_enable != black_list.enable) && ((bl_enable == 1) || (bl_enable == 0))) {
                    MSG("INFO: [filter] bl_enable: %u\n", bl_enable);
                    black_list.enable = bl_enable;
                    update = 1;
                }
            }
        }

        val = json_object_get_value(conf_obj, "wl_enable");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                wl_enable = (uint8_t)json_value_get_number(val);
                if ((wl_enable != white_list.enable) && ((wl_enable == 1) || (wl_enable == 0))) {
                    MSG("INFO: [filter] wl_enable: %u\n", wl_enable);
                    white_list.enable = wl_enable;
                    update = 1;
                }
            }
        }

        val = json_object_get_value(conf_obj, "binding");
        if (val != NULL) {
            if (json_value_get_type(val) == JSONNumber) {
                binding = (uint8_t)json_value_get_number(val);
                if ((binding != white_list.binding) && ((binding == 1) || (binding == 0))) {
                    MSG("INFO: [filter] binding: %u\n", binding); 
                    white_list.binding = binding;
                    update = 1;
                }
            }
        }
        if (update == 1) {
            update_filter_conf(FILTER_CONF_NAME);
            send_config_up_msg(FILTER_C_G_NOTIFY);
        }
    } else if (strcmp(str, "get") == 0) {
        MSG("INFO: [filter] filter_conf get msg\n");
        send_config_up_msg(FILTER_C_G_NOTIFY);
    }

    return 0;
}

void thread_check_valid(void) {
    int i = 0;
    uint64_t time_us = 0;
    uint64_t time_end = 0;
    uint64_t value = 0;
    uint8_t type = 0;
    struct timeval cur_unix_time;
    struct filter_s *filter = &g_filter;

    while (FILTER_INITED_FLAG == filter->inited) {
        wait_ms(1000);

        gettimeofday(&cur_unix_time, NULL);
        time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;

        for (i = 0; i < (int)black_list.num; i++) {
            time_end = black_list.nodes[i].time + black_list.nodes[i].duration * 1000000UL;
            if (time_us > time_end) {
                MSG("INFO: [filter] check_valid time_us: %llu, time_end: %llu\n", time_us, time_end);
                value = black_list.nodes[i].value;
                type = black_list.nodes[i].type;
                MSG("INFO: [filter] the value:%llX expired, need delete from black list\n", value);
                black_list_del_node(&black_list, value, type);
            }
        }

        for (i = 0; i < (int)join_list.num; i++) {
            if ((time_us > join_list.nodes[i].f_time) 
                && (time_us - join_list.nodes[i].f_time) > ((uint64_t)filter->join_period * 1000000UL)) {
                value = join_list.nodes[i].value;
                MSG("INFO: [filter] the value:%llX expired, need delete from join list\n", value);
                join_list_del_node(&join_list, value);
            }
        }      
    }
    MSG("INFO: [filter] end of valid thread\n");
}

int filter_white_list_join(uint64_t deveui) {
    int i = 0;
    int pass = 0;
    uint32_t oui = 0;
    struct white_list_s *list = &white_list;

    if (1 != list->enable) {
        MSG("INFO: [filter] white list join filter is not enable\n");
        return 1;
    }

    if (1 == list->binding) {
        for (i = 0; i < (int)list->num; i++) {
            if ((list->nodes[i].value == deveui) && (list->nodes[i].type == FILTER_TYPE_DEVEUI)) {
                pass = 1;
                break;
            }
        }
    } else {
        for (i = 0; i < (int)list->num; i++) {
            if ((1 == list->nodes[i].enable) && (list->nodes[i].type == FILTER_TYPE_OUI)) {
                oui = (uint32_t)(deveui >> 40);
                if (oui == list->nodes[i].value) {
                    pass = 1;
                    break;
                }
            }
        }
    }

    if (1 == pass) {
        MSG("INFO: [filter] The deveui: %llX in white list, pass\n", deveui);
    } else {
        MSG("INFO: [filter] The deveui: %llX not in white list, discard\n", deveui);
    }

    return pass;
}

int filter_white_list_data(uint32_t devaddr) {
    int i = 0;
    int pass = 0;
    uint8_t netid = 0;
    struct white_list_s *list = &white_list;

    if (1 != list->enable) {
        MSG("INFO: [filter] white list data filter is not enable\n");
        return 1;
    }

    if (1 == list->binding) {
        for (i = 0; i < (int)list->num; i++) {
            if ((list->nodes[i].value == devaddr) && (list->nodes[i].type == FILTER_TYPE_DEVADDR)) {
                pass = 1;
                break;
            }
        }
    } else {
        for (i = 0; i < (int)list->num; i++) {
            if ((1 == list->nodes[i].enable) && (list->nodes[i].type == FILTER_TYPE_NETID)) {
                netid = (uint8_t)(devaddr >> 25);
                if (netid == list->nodes[i].value) {
                    pass = 1;
                    break;
                }
            }
        }
    }

    if (1 == pass) {
        MSG("INFO: [filter] The devaddr: %X in white list, pass\n", devaddr);
    } else {
        MSG("INFO: [filter] The devaddr: %X not in white list, discard\n", devaddr);
    }

    return pass;
}


int filter_black_list_join(uint64_t deveui) {
    int i = 0;
    int pass = 1;
    struct black_list_s *list = &black_list;

    if (1 != list->enable) {
        MSG("INFO: [filter] black list join filter is not enable\n");
        return 1;
    }

    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].type == FILTER_TYPE_DEVEUI) {
            if (list->nodes[i].value == deveui) {
                pass = 0;
                break;
            }
        }
    }

    if (1 == pass) {
        MSG("INFO: [filter] The deveui: %llX not in black list, pass\n", deveui);
    } else {
        MSG("INFO: [filter] The deveui: %llX in black list, discard\n", deveui);
    }

    return pass;
}

int filter_black_list_data(uint32_t devaddr) {
    int i = 0;
    int pass = 1;
    struct black_list_s *list = &black_list;

    if (1 != list->enable) {
        MSG("INFO: [filter] black list data filter is not enable\n");
        return 1;
    }

    for (i = 0; i < (int)list->num; i++) {
        if (list->nodes[i].type == FILTER_TYPE_DEVADDR) {
            if (list->nodes[i].value == devaddr) {
                pass = 0;
                break;
            }
        }
    }

    if (1 == pass) {
        MSG("INFO: [filter] The devaddr: %X not in black list, pass\n", devaddr);
    } else {
        MSG("INFO: [filter] The devaddr: %X in black list, discard\n", devaddr);
    }

    return pass;
}

int filter_up_proc(const uint8_t *payload, uint16_t size) {
    uint8_t mtype = 0xFF;
    uint32_t deveui_h;
    uint32_t deveui_l;
    uint32_t devaddr;
    uint64_t deveui;
    int pass = 1;
    uint64_t time_us = 0;
    struct timeval cur_unix_time;

    if (FILTER_INITED_FLAG != g_filter.inited) {
        MSG("INFO: [filter] filter have no inited\n");
        return pass;
    }

    mtype = payload[0] & 0xE0;
    if ((0x00 == mtype) && (size > 16)) {
        deveui_l  = payload[9];
        deveui_l |= payload[10] << 8;
        deveui_l |= payload[11] << 16;
        deveui_l |= payload[12] << 24;

        deveui_h  = payload[13];
        deveui_h |= payload[14] << 8;
        deveui_h |= payload[15] << 16;
        deveui_h |= payload[16] << 24;

        deveui = ((uint64_t)deveui_h << 32) + deveui_l;
        pass = filter_white_list_join(deveui);
        if (1 == pass) {
            pass = filter_black_list_join(deveui);
            if (1 != pass) {
                MSG("INFO: [filter] deveui: %llX discard by black list filter\n", deveui);
            } else {
                gettimeofday(&cur_unix_time, NULL);
                time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;
                join_list_add_node(&join_list, time_us, deveui);
            }
        } else {
            MSG("INFO: [filter] deveui: %llX discard by white list filter\n", deveui);
        }
    } else if (((0x80 == mtype) || (0x40 == mtype)) && (size > 4)) {
        devaddr  = payload[1];
        devaddr |= payload[2] << 8;
        devaddr |= payload[3] << 16;
        devaddr |= payload[4] << 24;

        pass = filter_white_list_data(devaddr);
        if (1 == pass) {
            pass = filter_black_list_data(devaddr);
            if (1 != pass) {
                MSG("INFO: [filter] devaddr: %X discard by black list filter\n", devaddr);
            }
        } else {
            MSG("INFO: [filter] devaddr: %X discard by white list filter\n", devaddr);
        }
    } else if ((0xC0 == mtype) && (size > 1)) {
        uint8_t rejointype = 0xFF;
        int needcheck = 1;

        rejointype = payload[1];
        if (((0x00 == rejointype) || (0x02 == rejointype)) && (size > 12)) {
            deveui_l  = payload[5];
            deveui_l |= payload[6] << 8;
            deveui_l |= payload[7] << 16;
            deveui_l |= payload[8] << 24;

            deveui_h  = payload[9];
            deveui_h |= payload[10] << 8;
            deveui_h |= payload[11] << 16;
            deveui_h |= payload[12] << 24;
        } else if ((0x01 == rejointype) && (size > 17)) {
            deveui_l  = payload[10];
            deveui_l |= payload[11] << 8;
            deveui_l |= payload[12] << 16;
            deveui_l |= payload[13] << 24;

            deveui_h  = payload[14];
            deveui_h |= payload[15] << 8;
            deveui_h |= payload[16] << 16;
            deveui_h |= payload[17] << 24;
        } else {
            needcheck = 0;
        }
        if (needcheck == 1) {
            deveui = ((uint64_t)deveui_h << 32) + deveui_l;
            pass = filter_white_list_join(deveui);
            if (1 == pass) {
                pass = filter_black_list_join(deveui);
                if (1 != pass) {
                    MSG("INFO: [filter] deveui: %llX discard by black list filter\n", deveui);
                } else {
                    gettimeofday(&cur_unix_time, NULL);
                    time_us = (uint64_t)cur_unix_time.tv_sec * 1000000UL + cur_unix_time.tv_usec;
                    join_list_add_node(&join_list, time_us, deveui);
                }
            } else {
                MSG("INFO: [filter] deveui: %llX discard by white list filter\n", deveui);
            }
        } else {
            MSG("INFO: [filter] invalid rejoin-request packet(mtype:0x%02X size:%u), discard\n", mtype, size);
            pass = 0;
        }
    } else if (0xE0 == mtype) {
        if ((payload[0] == 0xE4) && (size == 19)) {
            MSG("INFO: [filter] this is lora time sync packet, pass\n");
            pass = 1;
        } else {
            MSG("INFO: [filter] invalid proprietary packet(mtype:0x%02X size:%u), discard\n", mtype, size);
            pass = 0;
        }
    } else {
        MSG("INFO: [filter] invalid packet(mtype:0x%02X size:%u), discard\n", mtype, size);
        pass = 0;
    }

    return pass;
}

int filter_down_proc(const uint8_t *msg_buf, uint16_t msg_len) {
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    uint8_t msg_id = 0;

    if (FILTER_INITED_FLAG != g_filter.inited) {
        MSG("INFO: [filter] filter have no inited\n");
        return -1;
    }

    if (msg_len < 4) {
        MSG("INFO: [filter] ignoring invalid packet, len: %d\n", msg_len);
        return -1;
    }

    msg_id = msg_buf[3];
    if (msg_id == FILTER_DOWN) {
        MSG("INFO: [filter] down msg: %s\n", (msg_buf + 4));
        root_val = json_parse_string_with_comments((const char *)(msg_buf + 4));
        if (root_val == NULL) {
            MSG("WARNING: [filter] invalid JSON\n");
            return -1;
        }

        conf_obj = json_object_get_object(json_value_get_object(root_val), "whitelist");
        if (NULL != conf_obj) {
            handle_white_list_down_msg(conf_obj);
        }

        conf_obj = NULL;
        conf_obj = json_object_get_object(json_value_get_object(root_val), "blacklist");
        if (NULL != conf_obj) {
            handle_black_list_down_msg(conf_obj);
        }

        conf_obj = NULL;
        conf_obj = json_object_get_object(json_value_get_object(root_val), "filter_conf");
        if (NULL != conf_obj) {
            handle_config_down_msg(conf_obj);
        }

        json_value_free(root_val);

        return 1;
    }

    return 0;
}

int filter_init(void) {
    int ret;
    struct filter_s *filter = &g_filter;

    if (FILTER_INITED_FLAG == filter->inited) {
        MSG("INFO: [filter] filter already inited\n");
        return 0;
    }

    memset(filter, 0, sizeof(struct filter_s));
    memset(&join_list, 0, sizeof(struct join_list_s));
    memset(&black_list, 0, sizeof(struct black_list_s));
    memset(&white_list, 0, sizeof(struct white_list_s));

    black_list.enable = 0;

    filter->inited = FILTER_INITED_FLAG;
    ret = pthread_create(&filter->thrid_id, NULL, (void * (*)(void *))thread_check_valid, NULL);
    if (ret != 0) {
        MSG("ERROR: [filter] impossible to create valid thread\n");
        filter->inited = 0;
        return -1;
    }

    filter->bl_duration = DEFAULT_BLACK_LIST_DURATION;
    filter->join_period = DEFAULT_JOIN_TIME_PERIOD;
    filter->join_interval = DEFAULT_JOIN_TIME_INTERVAL;
    filter->join_count1 = DEFAULT_JOIN_COUNT1_MAX;
    filter->join_count2 = DEFAULT_JOIN_COUNT2_MAX;
    parse_filter_conf(FILTER_CONF_NAME);

    parse_white_list_conf(FILTER_CONF_NAME);

    white_list_print(&white_list);

    send_white_list_up_msg(FILTER_W_G_NOTIFY, 0, 0, 0);

    return 0;
}

int filter_deinit(void) {
    if (FILTER_INITED_FLAG == g_filter.inited) {
        g_filter.inited = 0;
        pthread_cancel(g_filter.thrid_id);
    }
    return 0;
}
