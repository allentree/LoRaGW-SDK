#include <string.h>
#include "log.h"
#include "db.h"

#define IP_LEN              64
#define MODULE_NAME_LEN     64
#define DB_NAME_LEN         128
#define DB_USER_NAME_LEN    128
#define DB_PASSWD_LEN       128
#define DB_PORT_LEN         10

#define DEFAULT_HOST        "127.0.0.1"
#define DEFAULT_PORT        "5432"
#define DEFAULT_DB_NAME     "iiot_gateway"
#define DEFAULT_USER_NAME   "iiot"
#define DEFAULT_PASSWD      "iiot"
#define TABLE_NAME_LOG      "iiot_log"
#define TAG_LOG_DB          "log_db"
#define DEFAULT_LOG_DB_ROWS (100*1024)

static char g_host[IP_LEN] = DEFAULT_HOST;
static char g_port[DB_PORT_LEN] = DEFAULT_PORT;
static char g_db_name[DB_NAME_LEN] = DEFAULT_DB_NAME;
static char g_usr_name[DB_NAME_LEN] = DEFAULT_USER_NAME;
static char g_db_pwd[DB_NAME_LEN] = DEFAULT_PASSWD;
static char g_tab_name[MODULE_NAME_LEN] = TABLE_NAME_LOG;
static void *g_db_conn = NULL;

static column g_tab_log[] = {
    {"module_name", TYPE_STRING, 64, 0, 0},
    {"tag", TYPE_STRING, 64, 0, 0},
    {"level", TYPE_STRING, 5, 0, 0},
    {"file_name", TYPE_STRING, 64, 0, 0},
    {"func_name", TYPE_STRING, 32, 0, 0},
    {"line", TYPE_INTEGER, 16, 0, 0},
    {"content", TYPE_STRING, 512, 0, 0},
    {"time", TYPE_INTEGER, 64, 0, 0}
};

#define DB_LOG_TABLE_COL (sizeof(g_tab_log)/sizeof(column))

#define set_db_var(val,global_val,default_val,len_val) do { \
        if(NULL != val) \
            snprintf(global_val,len_val,"%s",val); \
        else \
            snprintf(global_val,len_val,"%s",default_val); \
    }while(0)

void log_db_destroy()
{
    if (g_db_conn) {
        db_destroy(g_db_conn);
        g_db_conn = NULL;
    }
}

uint8_t log_db_init(cchar *host, cchar *port, cchar *db_name,
                    cchar *user_name, cchar *pwd, int cnt, cchar *tab)
{
    int ret = 0;

    log_db_destroy();

    set_db_var(host, g_host, DEFAULT_HOST, IP_LEN);
    set_db_var(port, g_port, DEFAULT_PORT, DB_PORT_LEN);
    set_db_var(db_name, g_db_name, DEFAULT_DB_NAME, DB_NAME_LEN);
    set_db_var(user_name, g_usr_name, DEFAULT_USER_NAME, DB_USER_NAME_LEN);
    set_db_var(pwd, g_db_pwd, DEFAULT_PASSWD, DB_PASSWD_LEN);
    set_db_var(tab, g_tab_name, TABLE_NAME_LOG, MODULE_NAME_LEN);

    g_db_conn = db_init(g_host, g_port, g_db_name, g_usr_name, g_db_pwd);
    if (!g_db_conn) {
        printf("failed to init db module\n");
        return -1;
    }

    ret = db_create_table(g_db_conn, g_tab_name
                          , cnt <= 0 ? DEFAULT_LOG_DB_ROWS : cnt
                          , g_tab_log, DB_LOG_TABLE_COL);
    if (ret != 0) {
        printf("failed to create table\n");
        return -1;
    }

    //TODO:
    printf("log db init ok\n");
    return 0;
}

static char *int2str(char *buf, int len, int v)
{
    if (!buf) {
        return NULL;
    }
    memset(buf, 0, len);
    snprintf(buf, len, "%d", v);

    return buf;
}

void log_db_print(cchar *m, cchar *t, cchar *lvl, cchar *f, cchar *func,
                  int l, cchar *log, long timestamp)
{
    char line[33] = {0};
    char ts[65] = {0};
    int ret = 0;

    if (!g_db_conn) {
        return;
    }

    col_item item[DB_LOG_TABLE_COL] = {
        {g_tab_log[0].name, g_tab_log[0].type, m},
        {g_tab_log[1].name, g_tab_log[1].type, t},
        {g_tab_log[2].name, g_tab_log[2].type, lvl},
        {g_tab_log[3].name, g_tab_log[3].type, f},
        {g_tab_log[4].name, g_tab_log[4].type, func},
        {g_tab_log[5].name, g_tab_log[5].type, int2str(line, sizeof(line), l)},
        {g_tab_log[6].name, g_tab_log[6].type, log},
        {g_tab_log[7].name, g_tab_log[7].type, int2str(ts, sizeof(ts), timestamp)}
    };

    ret = db_add_item(g_db_conn, g_tab_name, item, DB_LOG_TABLE_COL);
    if (ret != 0) {
        printf("failed to add items to db, err code: %d\n", ret);
    }
}


