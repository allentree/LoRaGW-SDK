#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "md5.h"

#define TAG_OSS "oss"

#if defined(ENABLE_OSS_UPLOAD)
#include <curl/curl.h>
#define LOG_OSS_TESTKEY          ""
#define LOG_OSS_SERVER_URL       ""

static char *g_oss_file = NULL;
static char *g_oss_path = NULL;
static char *g_oss_token = NULL;
extern char *g_dir_name;
#endif

#if defined(ENABLE_OSS_UPLOAD)
static int log_get_oss_file(char *modname)
{
    struct stat rstat;
    char file_src[128] = {0};
    char file_dst[128] = {0};
    char cmd[256] = {0};

    snprintf(file_src, sizeof(file_src), "%s/%s.INFO", modname, modname);
    snprintf(file_dst, sizeof(file_dst), "%s.html", modname);

    if (0 != stat(file_src, &rstat)) {
        log_e(TAG_OSS,"filelog:%s, no exist\n", file_src);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "cp -L -rf %s %s", file_src, file_dst);
    system(cmd);

    g_oss_file = (char *)malloc(128);
    if(!g_oss_file) {
        log_e(TAG_OSS,"malloc error\n");
        return -1;
    }

    memset(g_oss_file, 0, 128);
    strcpy(g_oss_file, file_dst);

    return 0;
}

static int log_get_oss_token(char *modname, cchar *deviceid)
{
    time_t ttime;
    struct tm *tmlocal;
    char key_md5[33] = {0};
    char path_md5[33] = {0};
    char buf[128]= {0};

    ttime = time(NULL);
    tmlocal = localtime(&ttime);
    strftime(buf, 64, "%Y%m%d_%H%M%S", tmlocal);  

    g_oss_path = (char *)malloc(128);
    if(!g_oss_path) {
        log_e(TAG_OSS,"malloc error\n");
        return -1;
    }
    memset(g_oss_path, 0x0, 128);
    if (NULL != deviceid) {
        snprintf(g_oss_path, 128, "loragw/%s_%s_%s", modname, deviceid, buf);
    } else {
        snprintf(g_oss_path, 128, "loragw/%s_%s_%s", modname, modname, buf);
    }
    log_d(TAG_OSS,"path: %s\n", g_oss_path);

    md5_hash(g_oss_path, strlen(g_oss_path), path_md5);
    log_d(TAG_OSS,"path_md5: %s\n", path_md5);

    md5_hash(LOG_OSS_TESTKEY, strlen(LOG_OSS_TESTKEY), key_md5);
    //log_d(TAG_OSS,"key_md5: %s\n", key_md5);

    memset(buf, 0x0, sizeof(buf));
    snprintf(buf, sizeof(buf), "alink://%s%s", path_md5, key_md5);
    //log_d(TAG_OSS,"context: %s\n", buf);

    g_oss_token = (char *)malloc(33);
    if(!g_oss_token) {
        log_e(TAG_OSS,"malloc error\n");
        return -1;
    }
    memset(g_oss_token, 0x0, 33);
    md5_hash(buf, strlen(buf), g_oss_token);
    //log_i(TAG_OSS,"token: %s\n", g_oss_token);

    return 0;
}
#endif

void log_file_oss_destroy()
{
#if defined(ENABLE_OSS_UPLOAD)
    if(g_oss_file)
        free(g_oss_file); 

    if(g_oss_path)
        free(g_oss_path);

    if(g_oss_token)
        free(g_oss_token);
#endif
}

extern char g_mode_name[64];
uint8_t log_file_upload(cchar *moddir, cchar *deviceid)
{
#if defined(ENABLE_OSS_UPLOAD)
    CURL *curl = NULL;
    CURLcode res = CURLE_OK;
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    char modname[128]= {0};
    char *p = NULL;
    int ret = 0;

    if (NULL != moddir ) {
        strncpy(modname, moddir, sizeof(modname) - 1 );
    } else {
        strncpy(modname, g_dir_name, sizeof(modname) - 1);
    }
    p = strrchr(modname, '/');
    if (p) {
        *p = 0;
    }

    ret = log_get_oss_file(modname);
    if (0 != ret) {
        log_e(TAG_OSS,"get oss file failed");
        return -1;
    }

    ret = log_get_oss_token(modname, deviceid);
    if (0 != ret) {
        log_e(TAG_OSS,"get oss token failed");
        return -1;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "path",
                 CURLFORM_COPYCONTENTS, g_oss_path,
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "token",
                 CURLFORM_COPYCONTENTS, g_oss_token,
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "file",
                 CURLFORM_FILE, g_oss_file,
                 CURLFORM_END);

    curl = curl_easy_init();
    if (curl) {
        /* what URL that receives this POST */
        curl_easy_setopt(curl, CURLOPT_URL, LOG_OSS_SERVER_URL);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK) {
            log_e(TAG_OSS,"curl_easy_perform() failed: %s", curl_easy_strerror(res));
        }

        /* always cleanup */
        curl_easy_cleanup(curl);

        /* then cleanup the formpost chain */
        curl_formfree(formpost);
    }
    
    return res;
#else
    log_i(TAG_OSS, "disable log oss upload\n");
    return 0;
#endif
}




