#ifndef _UTILS_MSG_H_
#define _UTILS_MSG_H_

typedef struct {
    uint64_t timestamp;
    char *msg;
} msg_info_t, *msg_info_pt;



int msg_init(void);

int msg_set(const char *msg, uint32_t len);

int msg_delete(uint64_t _id);

int msg_get(char *msg_buf, uint32_t msg_buf_len, uint32_t *msg_len);


#endif /* _UTILS_MSG_H_ */
