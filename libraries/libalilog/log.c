#include <stdarg.h>
#include <time.h>
#include "log.h"

#define MODULE_NAME_LEN 64
#define MAX_MSG_LEN     512*10

#ifndef LOG_STORAGE_FILE
#define LOG_STORAGE_FILE
#endif

//func:line content
#define LOG_FMT_BRF_MIN "%s:%d "

//<tag> file-func:line content
#define LOG_FMT_BRF     "<%s> %s-%s:%d "

//date [module] level <tag> file-func:line content
#define LOG_FMT_VRB     "%s [%s] %s <%s> %s-%s:%d "

char             g_mode_name[MODULE_NAME_LEN] = "LOG";
static LOG_STORE_TYPE   g_store_type;
static LOG_MODE         g_out_mode = LOG_MOD_VERBOSE;
static uint8_t          g_log_lvl = LOG_LEVEL_DEBUG;
static const char       *g_log_desc[] = {"DBG", "INF",
                                         "WRN", "ERR",
                                         "FTL" };
#ifdef LOG_STORAGE_FILE
extern void log_file_destroy();
extern void log_file_print(int lvl, const char *str);
#endif

#ifdef LOG_STORAGE_DB
extern void log_db_print(cchar *m, cchar *t, cchar *lvl, cchar *f, cchar *func,
                         int l, cchar *log, long timestamp);
extern void log_db_destroy();
#endif

void log_set_level(LOG_LEVEL level)
{
    g_log_lvl = level;
}

static char *get_timestamp(char *buf, int len, time_t cur_time)
{
    struct tm tm_time;

    localtime_r(&cur_time, &tm_time);

    snprintf(buf, len, "%d-%d-%d %d:%d:%d",
             1900 + tm_time.tm_year, 1 + tm_time.tm_mon,
             tm_time.tm_mday, tm_time.tm_hour,
             tm_time.tm_min, tm_time.tm_sec);
    return buf;
}

#define color_len_fin strlen(COL_DEF)
#define color_len_start strlen(COL_RED)
void log_print(LOG_LEVEL lvl, cchar *color, cchar *t, cchar *f, cchar *func, int l, cchar *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char buf[MAX_MSG_LEN] = {0};
    char *tmp = NULL;
    int len = 0;
    char buf_date[20] = {0};
    time_t cur_time = time(NULL);

    t = !t ? "\b" : t;
    func = !func ? "\b" : func;

    if (f) {
        f = strrchr(f, '/');
        if (f) {
            f = f + 1;
        }
    }
    f = !f ? "\b" : f;

    //add color support
    if (color) {
        snprintf(buf, MAX_MSG_LEN, color);
    }

    if (g_out_mode == LOG_MOD_VERBOSE)
        snprintf(buf + strlen(buf), MAX_MSG_LEN - strlen(buf), LOG_FMT_VRB,
                 get_timestamp(buf_date, 20, cur_time), g_mode_name,
                 g_log_desc[lvl], t, f, func, l);
    else if (g_out_mode == LOG_MOD_BRIEF) {
        snprintf(buf + strlen(buf), MAX_MSG_LEN - strlen(buf), LOG_FMT_BRF, t, f, func, l);
    } else if (g_out_mode == LOG_MOD_BRIEF_MIN) {
        snprintf(buf + strlen(buf), MAX_MSG_LEN - strlen(buf), LOG_FMT_BRF_MIN, func, l);
    }

    len = MAX_MSG_LEN - strlen(buf) - color_len_fin - 5;
    len = len <= 0 ? 0 : len;
    tmp = buf + strlen(buf);
    if (vsnprintf(tmp, len, fmt, ap) > len) {
        strcat(buf, "...\n");
    }
    if (buf[strlen(buf) - 1] != '\n') {
        strcat(buf, "\n");
    }

    if (color) {
        strcat(buf, COL_DEF);
    }

    if (lvl >= g_log_lvl) {
        fprintf(stderr, "%s", buf);
    }
    //we should cut the last color string before save to flash.
    if (color) {
        buf[strlen(buf) - color_len_fin] = '\0';
    }

#ifdef LOG_STORAGE_FILE
    if (g_store_type >= LOG_FILE && lvl >= g_log_lvl) {
        log_file_print(lvl, buf + (color ? color_len_start : 0));
    }
#endif

#ifdef LOG_STORAGE_DB
    if (g_store_type >= LOG_DB && lvl >= g_log_lvl) {
        log_db_print(g_mode_name, t, g_log_desc[lvl], f, func, l, tmp, cur_time);
    }
#endif

    va_end(ap);
}

uint8_t log_init(cchar *name, LOG_STORE_TYPE type, LOG_LEVEL lvl, LOG_MODE mode)
{
    int ret = 0;
    char file_path[MAX_MSG_LEN] = {0};
    if (!name) {
        printf("log init error: name should not be NULL\n");
        return -1;
    }

    if(type < LOG_STDOUT || type > LOG_FILE_DB || 
            lvl < LOG_LEVEL_DEBUG || lvl > LOG_LEVEL_FATAL || 
            mode < LOG_MOD_BRIEF_MIN || mode > LOG_MOD_VERBOSE){
        printf("log init error: param is invalid.\n");
        return -2; 
    }

    memset(g_mode_name, 0, MODULE_NAME_LEN);
    snprintf(g_mode_name, MODULE_NAME_LEN, "%s", name);
    g_log_lvl = lvl;
    g_store_type = type;
    g_out_mode = mode;

    //snprintf(file_path, sizeof(file_path), "%s/%s", DEFAULT_LOG_PATH_PREFIX, name);
    snprintf(file_path, sizeof(file_path), "%s", name);
#ifdef LOG_STORAGE_FILE
    if (g_store_type >= LOG_FILE) {
        ret = log_file_init(file_path, -1, -1);
    }
#endif
#ifdef LOG_STORAGE_DB
    if (g_store_type >= LOG_DB) {
        ret = log_db_init(NULL, NULL, NULL, NULL, NULL, -1, g_mode_name);
    }
#endif
    printf("log init: module: %s, type: %d, level: %d\n", name, type, lvl);
    return ret;
}

void log_destroy()
{
#ifdef LOG_STORAGE_FILE
    if (g_store_type >= LOG_FILE) {
        log_file_destroy();
    }
#endif

#ifdef LOG_STORAGE_DB
    if (g_store_type >= LOG_DB) {
        log_db_destroy();
    }
#endif

    printf("log destroy.\n");
}

