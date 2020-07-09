#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iotx_utils_internal.h"
#include "iot_import.h"
#include "utils_base64.h"
#include "db/db.h"
#include "msg/utils_msg.h"


#define MSG_MAX_LEN             (4096)
//#define MSG_DEBUG


#define MSG_TABLE_NAME          "msg_t"
#define MSG_COL_NAME_MSG        "msg"
#define MSG_COL_NAME_TIMESTAMP  "timestamp"
#define MSG_COL_TYPE_MSG        (TYPE_STRING)
#define MSG_COL_TYPE_TIMESTAMP  (TYPE_INTEGER)

#define SQL_GET_ALL_FMT         "SELECT __id, " MSG_COL_NAME_MSG"," MSG_COL_NAME_TIMESTAMP " FROM " MSG_TABLE_NAME
#define SQL_GET_ALL_BUF_LEN     (sizeof(SQL_GET_ALL_FMT) + 32)

//message manage structure
struct msg_mng_info_st {
    void *db_conn;                       //DB connection
};


//message structure
struct msg_st {
    uint64_t timestamp;      //timestamp of this message
    char *msg_buf;           //buffer for storing message
    uint32_t msg_buf_len;    //buffer lenght in byte
    uint32_t msg_len;        //actual length of this message in byte
};

static struct msg_mng_info_st msg_mng_info;

static int get_callback(void *usr_data, int count, char **data, char **columns)
{
     struct msg_st *pmsg = (struct msg_st *)usr_data;
#ifdef MSG_DEBUG
    int idx;
    for (idx = 0; idx < count; idx++) {
         utils_info("The data in column \"%s\" is: %s", columns[idx], data[idx]);
     }
#endif

    if (0 != strcmp(columns[0], "__id")) {
        utils_err("get message error");
    }

    if (0 == strcmp(columns[1], MSG_COL_NAME_MSG)) {
        if (NULL != pmsg->msg_buf) {
            utils_base64decode((uint8_t *)data[0], strlen(data[1]), pmsg->msg_buf_len, (uint8_t *)pmsg->msg_buf, &pmsg->msg_len);
        }
    }  else {
        utils_err("get message content failed");
    }

    if (0 == strcmp(columns[2], MSG_COL_NAME_TIMESTAMP)) {
        pmsg->timestamp = strtoul(data[2], NULL, 10);
    } else {
        utils_err("get message timestamp failed");
    }

#ifdef MSG_DEBUG
    utils_info("select result, msg_buf = %s\n msg_len=%d\n timestamp=%d\n", pmsg->msg_buf, pmsg->msg_len, pmsg->timestamp);
#endif
    msg_delete(strtoul(data[0], NULL, 10));

    return 0;
}

//get epoch time in second
static uint64_t get_epoch_time_s(void)
{
    return time(NULL);
}


//Initialize message manage module
//return: 0, success; -1, failed
int msg_init(void)
{
    int ret = 1;
    column col[] = {
        {MSG_COL_NAME_TIMESTAMP, MSG_COL_TYPE_TIMESTAMP, 12, 0, 1},
        {MSG_COL_NAME_MSG, MSG_COL_TYPE_MSG, MSG_MAX_LEN, 0, 1}
    };

    memset(&msg_mng_info, 0, sizeof(struct msg_mng_info_st));

    msg_mng_info.db_conn = db_init("127.0.0.1", "5432", "msg_db", "LinkWAN", "LinkWAN123");

    ret = db_create_table(msg_mng_info.db_conn, MSG_TABLE_NAME, 0, col, sizeof(col)/sizeof(column));
    if(ret != 0) {
        utils_err("create table failed");
        goto do_exit;
    }

    return ret;

do_exit:
    utils_debug("Initialize message manage module failed");

    memset(&msg_mng_info, 0, sizeof(struct msg_mng_info_st));
    return ret;
}


//insert the message specified by @msg
//return: 0, success; -1, failed
int msg_set(const char *msg, uint32_t len)
{
#define SQL_SET_FMT_1   "INSERT INTO " MSG_TABLE_NAME \
                        "( " MSG_COL_NAME_TIMESTAMP"," MSG_COL_NAME_MSG " )" \
                        "VALUES( '%"PRIu64"', '"
#define SQL_SET_FMT_2   "' );"
#define SQL_SET_FMT_LEN (sizeof(SQL_SET_FMT_1) + sizeof(SQL_SET_FMT_2))

    int ret = 0;
    char *buf_sql;
    size_t len_sql, offset;
    uint32_t len_base64_result;

    len_sql = len * 2 + SQL_SET_FMT_LEN + 64;

    if (NULL == (buf_sql = HAL_Malloc(len_sql))) {
        utils_err("malloc failed");
        return -1;
    }

    memset(buf_sql, 0, len_sql);
    offset = sprintf(buf_sql, SQL_SET_FMT_1, get_epoch_time_s());

    utils_base64encode((uint8_t *)msg, len, len_sql - offset, (uint8_t *)buf_sql + offset, &len_base64_result);
    offset += len_base64_result;
    memcpy(buf_sql + offset, SQL_SET_FMT_2, sizeof(SQL_SET_FMT_2));
#ifdef MSG_DEBUG
    utils_info("msg_set: sql = %s", buf_sql);
#endif

    ret = db_exec_sql(msg_mng_info.db_conn, buf_sql, NULL, NULL);
    if (0 != ret) {
        utils_err("insert data failed");
    }

    HAL_Free(buf_sql);

    return ret;
}

//delete the message specified by @_id
//return: 0, success; -1, failed
int msg_delete(uint64_t _id)
{
#define SQL_DEL_FMT     "DELETE FROM " MSG_TABLE_NAME " WHERE __id =%"PRIu64";"
#define SQL_BUF_LEN     (sizeof(SQL_DEL_FMT) + 32)

    int ret;
    char sql[SQL_BUF_LEN];

    ret = snprintf(sql, SQL_BUF_LEN, SQL_DEL_FMT, _id);
    if (ret < 0) {
        utils_err("snprintf failed");
        return -1;
    }

#ifdef MSG_DEBUG
    utils_info("msg_delete: sql = %s", sql);
#endif
    ret = db_exec_sql(msg_mng_info.db_conn, sql, NULL, NULL);
    if (0 != ret) {
        utils_err("execute sql failed");
        return -1;
    }

#ifdef MSG_DEBUG
    utils_info("delete sql complete, %s", sql);
#endif

    return 0;

#undef SQL_BUF_LEN
#undef SQL_DEL_FMT
}

//get message
//@msg_buf, buffer for storing message
//@msg_buf_len, buffer length of @msg_buf in byte
//@msg_len, output the actual length the message in byte
//return: 0, success; -1, failed
int msg_get(char *msg_buf, uint32_t msg_buf_len, uint32_t *msg_len)
{
#define SQL_GET_WITH_ID         SQL_GET_ALL_FMT " order by __id ASC limit 1;"
#define SQL_GET_WITH_ID_BUF_LEN (sizeof(SQL_GET_WITH_ID) + 32)

    int ret;
    char sql[SQL_GET_WITH_ID_BUF_LEN];
    struct msg_st msg;

    memset(&msg, 0, sizeof(struct msg_st));
    msg.msg_buf = msg_buf;
    msg.msg_buf_len = msg_buf_len;

    ret = snprintf(sql, SQL_GET_WITH_ID_BUF_LEN, SQL_GET_WITH_ID);
    if (ret < 0) {
        utils_err("snprintf failed");
        return -1;
    }
    ret = db_exec_sql(msg_mng_info.db_conn,
                sql,
                get_callback,
                &msg);
    if(msg.msg_len > 0) {
        utils_debug("get from DB, msg(len=%d) = %s", msg.msg_len, msg.msg_buf);
    } else {
        utils_info("DB EMPTY!!! all msg has been sent");
        return -1;
    }
    if (0 != ret) {
        utils_err("execute sql failed");
        return -1;
    }

    *msg_len = msg.msg_len;
    return 0;

#undef SQL_GET_WITH_MSG_ID
#undef SQL_GET_WITH_MSG_ID_BUF_LEN
}

