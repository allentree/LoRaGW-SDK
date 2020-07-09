/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/time.h>
#include "sst.h"
#include "sst_dbg.h"
#include "sst_wrapper.h"

#define MAX_PATH_LEN 512

#define SST_SHA256 0x01
#define SST_SHA256_LEN 32
#define _SST_INIT_INTEG_MAGIC(_m) do {                \
                                    (_m)[0] = 'I';  \
                                    (_m)[1] = 'n';  \
                                    (_m)[2] = 'T';  \
                                    (_m)[3] = 'g';  \
                                } while (0)

#define _SST_INTEG_MAGIC_VALID(_m) (('I' == (_m)[0]) &&    \
                                    ('n' == (_m)[1]) &&     \
                                    ('T' == (_m)[2]) &&     \
                                    ('g' == (_m)[3]))

typedef struct sst_integ_t {
    uint8_t magic[4];
    uint32_t version;
    uint8_t rsvd[4];
    uint32_t hash_type;
    uint8_t  hash[32];
} __sst_integ_t;

static uint32_t _sst_trans_errno(int32_t err)
{
    uint32_t ret;

    switch (err) {
        case 0:
            ret = SST_SUCCESS;
            break;
        case EACCES:
            /* full through */
        case EPERM:
            ret = SST_ERROR_ACCESS_DENIED;
            break;
        case EEXIST:
            ret = SST_ERROR_ACCESS_CONFLICT;
            break;
        case ENOENT:
            ret = SST_ERROR_ITEM_NOT_FOUND;
            break;
        case ENOSPC:
            ret = SST_ERROR_STORAGE_NO_SPACE;
            break;
        case EROFS:
            ret = SST_ERROR_ACCESS_DENIED;
            break;
        case EBADF:
            /* full through */
        case EISDIR:
            ret = SST_ERROR_BAD_PARAMETERS;
            break;
        case ENOMEM:
            ret = SST_ERROR_OUT_OF_MEMORY;
            break;
        case EINVAL:
            ret = SST_ERROR_BAD_PARAMETERS;
            break;
        case EIO:
            ret = SST_ERROR_STORAGE_NOT_AVAILABLE;
            break;
        case EBUSY:
            ret = SST_ERROR_BUSY;
            break;
        case EOVERFLOW:
            ret = SST_ERROR_OVERFLOW;
            break;
        case ENAMETOOLONG:
            ret = SST_ERROR_BAD_PARAMETERS;
            break;
        default:
            ret = SST_ERROR_GENERIC;
    }

    return ret;
}

static uint32_t _sst_set_file_name(char *name, char *postfix_name)
{
    uint32_t idx = strlen(name);
    uint8_t file_name[MAX_PATH_LEN + 6] = {0};
    uint32_t file_n_len = 0;

    while (--idx) {
        if ('/' == name[idx]) {
            file_n_len = strlen((char*)&name[idx + 1]);
            if(file_n_len > MAX_PATH_LEN){
                return SST_ERROR_BAD_PARAMETERS;
            }
            file_name[0] = '.';
            strcpy((char*)&file_name[1], &name[idx + 1]);
            strcat((char*)file_name, postfix_name);
            name[idx + 1] = '\0';
            strcat(name, (char*)file_name);
            break;
        }
    }

    if(idx == 0) {
        file_name[0] = '.';
        strcpy((char*)&file_name[1], name);
        strcat((char*)file_name, postfix_name);
        strcpy(name, (char*)file_name);
    }

    return SST_SUCCESS;
}

static uint32_t _sst_get_name(const char *path, char *name)
{
    uint32_t idx = strlen(path);
    char *buf = NULL;

    while (--idx) {
        if ('/' == path[idx]) {
            buf = (char *)(&path[idx + 1]);
            if (strlen(buf) + 1 > MAX_PATH_LEN) {
                SST_ERR("too long obj name\n");
                return SST_ERROR_OVERFLOW;
            }
            strcpy((char*)name, buf);
            break;
        }
    }
    if(idx == 0){
        sst_strcpy((char*)name, path);
    }

    return SST_SUCCESS;
}

uint32_t _sst_set_real_name(const char *in_name, char *out_name)
{
    uint32_t ret = 0;
    char name[MAX_PATH_LEN] = { 0 };
    char obj_name[MAX_PATH_LEN];
    uint32_t in_len = strlen(in_name);
    uint32_t name_len = 0;
    uint32_t path_len = 0;

    ret = _sst_get_name(in_name, name);
    if (ret) {
        SST_ERR("get name failed 0x%x\n", ret);
        return ret;
    }

    name_len = strlen(name);
    path_len = in_len - name_len;
    memcpy(out_name, in_name, path_len);
    sst_imp_set_obj_name(name, obj_name);
    name_len = strlen(obj_name);
    if (path_len + name_len + 1 > MAX_PATH_LEN) {
        SST_ERR("name is overflow\n");
        return SST_ERROR_BAD_PARAMETERS;
    }

    sst_memcpy(out_name + path_len, obj_name, name_len);

    return SST_SUCCESS;
}

static uint32_t _sst_fs_store_data(const char *name,
                                     void *file_data,
                                     uint32_t file_len,
                                     uint32_t flag)
{
    int fd = -1;
    uint32_t ret = 0;
    uint32_t flags = 0;
    uint32_t s = 0;
    int32_t res = 0;

    if(flag){
        flags = O_RDWR | O_CREAT;
    } else {
        flags = O_EXCL | O_RDWR | O_CREAT;
    }

    fd = open(name, flags, S_IRUSR | S_IWUSR | S_IROTH | S_IRGRP);
    if (-1 == fd) {
        ret = _sst_trans_errno(errno);
        SST_ERR("failed to open file, %s %d\n", name, errno);
        return ret;
    }

    if (-1 == ftruncate(fd, 0)) {
        ret = _sst_trans_errno(errno);
        SST_ERR("failed to truncate file, %s %d\n", name, errno);
        goto _err;
    }

    if (-1 == lseek(fd, 0, SEEK_SET)) {
        ret = _sst_trans_errno(errno);
        SST_ERR("failed to seek to 0, %s %d\n",
                name, errno);
        goto _err;
    }

    do {
        res = write(fd, file_data + s, file_len - s);
        if (-1 == res) {
            ret = _sst_trans_errno(errno);
            SST_ERR("write failed 0x%x\n", ret);
            goto _err;
        }
        s += res;
    } while (s < file_len);

    if(s != file_len){
        SST_ERR("write file len is not right\n");
        ret = SST_ERROR_GENERIC;
    }

_err:
    close(fd);
    return ret;
}

static uint32_t _sst_itg_store(const char *name, void *file_data, uint32_t file_len)
{
    uint32_t ret = 0;
    char integ_name[MAX_PATH_LEN + 6] = {0}; //for '.' ".itg"
    char *integ_postfix = ".itg";
    __sst_integ_t sst_itg = {0};


    _SST_INIT_INTEG_MAGIC(sst_itg.magic);
    sst_itg.version = SST_VERSION;
    sst_itg.hash_type = SST_SHA256;

    ret = sst_imp_hash_data(file_data, file_len, sst_itg.hash);
    if(ret != SST_SUCCESS){
        SST_ERR("hash file fail\n");
        return ret;
    }

    strcpy(integ_name, name);
    _sst_set_file_name(integ_name, integ_postfix);

    ret = _sst_fs_store_data(integ_name, (void*)&sst_itg, sizeof(__sst_integ_t), 1);
    if(ret != SST_SUCCESS){
        SST_ERR("store itg file fail\n");
        return ret;
    }

    return ret;
}

static uint32_t _sst_fs_get_data(const char *name, void **pp_data, uint32_t *p_file_len)
{
    int fd = -1;
    uint32_t ret = 0;
    uint32_t file_len = 0;
    int32_t  res = 0, s = 0;
    uint8_t *file_data = NULL;
    uint8_t buff[512] = {0};

    fd = open(name, O_RDONLY, S_IRUSR | S_IROTH | S_IRGRP);
    if (-1 == fd) {
        ret = _sst_trans_errno(errno);
        SST_ERR("failed to open file, %s %d\n", name, errno);
        return ret;
    }

    file_len = lseek(fd, 0, SEEK_END);
    if (file_len == -1){
        ret = _sst_trans_errno(errno);
        SST_ERR("failed to seek to end, %s %d\n",name, errno);
        goto _err;
    }

    res = lseek(fd, 0, SEEK_SET);
    if (res == -1){
        ret = _sst_trans_errno(errno);
        SST_ERR("failed to seek to start, %s %d\n",name, errno);
        goto _err;
    }

    if (file_len == 0) {
        SST_ERR("wrong file len\n");
        *pp_data = NULL;
        ret = SST_ERROR_GENERIC;
        goto _err;
    }

    file_data = sst_malloc(file_len);
    if(!file_data){
        SST_ERR("fs malloc error\n");
        *pp_data = NULL;
        ret = SST_ERROR_OUT_OF_MEMORY;
        goto _err;
    }
    sst_memset(file_data, 0, file_len);
    *pp_data = file_data;

    do {
        res = read(fd, buff, sizeof(buff));
        if (-1 == res) {
            ret = _sst_trans_errno(errno);
            SST_ERR("read: failed to read %s %d\n", name, errno);
            goto _err;
        }
        sst_memcpy(file_data, buff, res);
        s += res;
        file_data += res;
    } while(res > 0);

    if(s != file_len){
        ret = SST_ERROR_GENERIC;
        SST_ERR("read: failed to read %s %d\n", name, errno);
        goto _err;
    }

_err:
    close(fd);
    *p_file_len = file_len;

    return ret;
}

static uint32_t _sst_check_iteg_and_recovery(const char *name, void *p_data, uint32_t file_len)
{
    uint32_t ret = SST_SUCCESS;
    uint8_t hash[32] = {0};
    char *bk_postfix = ".bak";
    char bk_name[MAX_PATH_LEN + 6] = {0}; //for '.'".bak"
    void *p_sst_bk = NULL;
    void *p_sst_itg = NULL;
    uint32_t bk_file_len = 0;
    char integ_name[MAX_PATH_LEN + 6] = {0}; //for '.'".itg"
    char integ_postfix[] = ".itg";
    __sst_integ_t *p_sst_itg_t = 0;


    ret = sst_imp_hash_data(p_data, file_len, hash);
    if(ret != SST_SUCCESS){
        SST_ERR("hash file fail\n");
        return ret;
    }

    strcpy(integ_name, name);
    _sst_set_file_name(integ_name, integ_postfix);

    ret = _sst_fs_get_data(integ_name, &p_sst_itg, &bk_file_len);
    if(ret != SST_SUCCESS){
        SST_ERR("get bk file fail\n");
        goto clean1;
    }
    p_sst_itg_t = (__sst_integ_t *)p_sst_itg;
    if(0 == sst_memcmp(hash, p_sst_itg_t->hash, 32)){
        ret = SST_SUCCESS;
        SST_INF("the file is Okay\n");
        goto clean1;
    }

    strcpy(bk_name, name);
    _sst_set_file_name(bk_name, bk_postfix);

    ret = _sst_fs_get_data(bk_name, &p_sst_bk, &bk_file_len);
    if(ret != SST_SUCCESS){
        SST_ERR("get bk file fail\n");
        goto clean2;
    }

    sst_memset(hash, 0, 32);
    ret = sst_imp_hash_data(p_sst_bk, bk_file_len, hash);
    if(ret != SST_SUCCESS){
        SST_ERR("hash file fail\n");
        goto clean2;
    }
    if(0 != sst_memcmp(hash, p_sst_itg_t->hash, 32)){
        SST_ERR("bk file also currupt\n");
        ret = SST_ERROR_OBJ_CORRUPT;
        goto clean2;
    }
    _sst_fs_store_data(name, p_sst_bk, bk_file_len, 1);
    if(ret != SST_SUCCESS){
        SST_ERR("recover file fail\n");
        goto clean2;
    }
    ret = SST_ERROR_OBJ_RECOVER;

clean2:
    if(p_sst_bk) {
        sst_free(p_sst_bk);
        p_sst_bk = NULL;
    }

clean1:
    if(p_sst_itg) {
        sst_free(p_sst_itg);
        p_sst_itg = NULL;
    }

    return ret;
}

uint64_t sst_current_raw_time(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (uint64_t)(tv.tv_sec*1000 + tv.tv_usec/1000);
}

uint32_t sst_store_obj(const char *name, void *file_data, uint32_t file_len, uint32_t flag)
{
    uint32_t ret = 0;
    char *bk_postfix = ".bak";
    char bk_name[MAX_PATH_LEN + 6] = {0}; //for '.'".bak"
    uint32_t name_len = 0;
    char real_name[MAX_PATH_LEN] = {0};

    ret = _sst_set_real_name(name, real_name);
    if (ret) {
        SST_ERR("set real name failed 0x%x\n", ret);
        return ret;
    }

    name_len = strlen(real_name);
    if(name_len >= MAX_PATH_LEN) {
        SST_ERR("fs file real_name is too long:[%s]\n", (char*)name);
        return SST_ERROR_BAD_PARAMETERS;
    }

    /* store backup file*/
    strcpy((char*)bk_name, (char*)real_name);
    _sst_set_file_name(bk_name, bk_postfix);
    ret = _sst_fs_store_data(bk_name, file_data, file_len, 1);
    if(ret != SST_SUCCESS){
        SST_ERR("store bk data file fail 0x%x\n", ret);
        return ret;
    }

    /* store itg file*/
    ret = _sst_itg_store(real_name, file_data, file_len);
    if(ret != SST_SUCCESS){
        SST_ERR("store itg file fail\n");
        return ret;
    }

    /* store original file*/
    ret = _sst_fs_store_data(real_name, file_data, file_len, flag);
    if(ret != SST_SUCCESS){
        SST_ERR("store data file fail\n");
        return ret;
    }

    return ret;
}

uint32_t sst_get_obj(const char *name, void **pp_data, uint32_t *p_file_len)
{
    uint32_t ret = 0;
    char real_name[MAX_PATH_LEN] = {0};

    ret = _sst_set_real_name(name, real_name);
    if (ret) {
        SST_ERR("set real name failed 0x%x\n", ret);
        return ret;
    }

    /* preload the file */
    ret = _sst_fs_get_data(real_name, pp_data, p_file_len);
    if(ret != SST_SUCCESS){
        SST_ERR("read: failed to read %s\n", real_name);
        return ret;
    }

    /* check iteg  */
    ret = _sst_check_iteg_and_recovery(real_name, *pp_data, *p_file_len);
    if(ret == SST_ERROR_OBJ_RECOVER){
        SST_INF("read the recover file %s\n", real_name);
        if (*pp_data) {
            sst_free(*pp_data);
            *pp_data = NULL;
        }
        ret = _sst_fs_get_data(real_name, pp_data, p_file_len);
        if(ret != SST_SUCCESS){
            SST_ERR("read: failed to read %s\n", name);
        }
    }

    return ret;
}

uint32_t sst_delete_obj(const char *name)
{
    uint32_t ret = 0;
    char real_name[MAX_PATH_LEN] = {0};
    char bk_name[MAX_PATH_LEN + 6] = {0}; //for '.'".bak"
    char itg_name[MAX_PATH_LEN + 6] = {0}; //for '.'".itg"

    ret = _sst_set_real_name(name, real_name);
    if (ret) {
        SST_ERR("set real name failed 0x%x\n", ret);
        return ret;
    }

    //delete original file
    if (unlink(real_name)) {
        ret = _sst_trans_errno(errno);
        SST_ERR("unlink origin file failed %x\n", ret);
        return ret;
    }

    //for integrity check
    //delete itg file
    strcpy(itg_name, real_name);
    _sst_set_file_name(itg_name, ".itg");
    if (unlink(itg_name)) {
        ret = _sst_trans_errno(errno);
        SST_ERR("unlink integrity file failed %x\n", ret);
        return ret;
    }

    //delete bak file
    strcpy(bk_name, real_name);
    _sst_set_file_name(bk_name, ".bak");
    if (unlink(bk_name)) {
        ret = _sst_trans_errno(errno);
        SST_ERR("unlink backup faile failed %x\n", ret);
        return ret;
    }

    return SST_SUCCESS;
}

#if CONFIG_SST_MIGRATION
static char mig_file_path[512];

static uint32_t _sst_set_migration_file_name(char *mig_path, char* obj_name)
{
    uint32_t len = strlen(mig_file_path);

    //6 for / .mig \0
    if (len + strlen(obj_name) + 6 > MAX_PATH_LEN) {
        SST_ERR("too long mig path\n");
        return SST_ERROR_OVERFLOW;
    }

    strcpy(mig_path, mig_file_path);

    if(mig_path[len - 1] != '/')
        mig_path[len] = '/';
    mig_path[len + 1] = '\0';
    strcat((char*)mig_path, (char*)obj_name);
    strcat((char*)mig_path, ".mig");

    return SST_SUCCESS;
}

void sst_set_mig_obj_path(const char *path)
{
    sst_memset(mig_file_path, 0, sizeof(mig_file_path));
    sst_strncpy((char*)mig_file_path, path, 512);
}

uint32_t sst_get_mig_obj(const char *name,
                                    uint8_t *key,
                                    uint32_t *key_len)
{
    void *p_sst = NULL;
    uint32_t ret = 0;
    uint32_t file_len = 0;
    uint32_t data_len = 0;
    uint8_t* data = NULL;
    uint8_t* mig_data = NULL;
    uint32_t mig_data_len = 0;
    char item_name[MAX_PATH_LEN] = {0};
    char mig_path[MAX_PATH_LEN + 5] = { 0 };
    uint32_t type = SST_TYPE_NONE;

    /* read file get original data*/
    if(!name || !key_len || (!key && *key_len)) {
        SST_ERR("get sst file bad param!\n");
        return SST_ERROR_BAD_PARAMETERS;
    }

    if (*key_len < SST_MIGRATION_KEY_LEN) {
        SST_ERR("short key len %d : %d\n", *key_len, SST_MIGRATION_KEY_LEN);
        *key_len = SST_MIGRATION_KEY_LEN;
        return SST_ERROR_SHORT_BUFFER;
    }

    ret = sst_get_obj(name, &p_sst, &file_len);
    if (SST_SUCCESS != ret) {
        SST_ERR("get sst file error 0x%x\n", ret);
        goto _err;
    }

    data_len = sst_imp_get_data_len(p_sst);
    if (data_len == 0) {
        SST_ERR("get data_len failed 0x%x\n", ret);
        goto _err;
    }

    data = sst_malloc(data_len);
    if(NULL == data) {
        SST_ERR("get file malloc error!\n");
        ret = SST_ERROR_OUT_OF_MEMORY;
        goto _err;
    }

    ret = sst_imp_get_obj_data(p_sst, file_len, data, &data_len, &type);
    if(ret) {
        SST_ERR("get obj data failed 0x%x\n", ret);
        goto _err;
    }

    /* enc the data with mig key */
    mig_data_len = sizeof(sst_mig_head) + data_len;
    mig_data = sst_malloc(mig_data_len);
    if(NULL == mig_data){
        ret = SST_ERROR_OUT_OF_MEMORY;
        goto _err;
    }
    sst_memset(mig_data, 0, mig_data_len);

    ret = sst_imp_enc_mig_data(type, data, data_len, key, mig_data);
    if(SST_SUCCESS != ret){
        SST_ERR("enc sst mig file error!\n");
        goto _err;
    }
    *key_len = 16;

    ret = _sst_get_name(name, item_name);
    if (ret) {
        SST_ERR("get obj name failed");
        goto _err;
    }
    ret = _sst_set_migration_file_name(mig_path, item_name);
    if (ret) {
        SST_ERR("get obj name failed");
        goto _err;
    }

    ret = _sst_fs_store_data(mig_path, mig_data, mig_data_len, 1);
    if(SST_SUCCESS != ret){
        SST_ERR("enc sst mig file error!\n");
        goto _err;
    }

_err:
    if(data){
        sst_memset(data, 0, data_len);
        sst_free(data);
    }
    if(p_sst){
        sst_memset(p_sst, 0, file_len);
        sst_free(p_sst);
    }

    if(mig_data){
        sst_memset(mig_data, 0, mig_data_len);
        sst_free(mig_data);
    }
    return ret;
}

uint32_t sst_store_mig_obj(const char *name, uint8_t *key, uint32_t key_len)
{
    uint32_t ret = 0;
    char item_name[512] = {0};
    char mig_path[MAX_PATH_LEN] = { 0 };
    void *p_sst_mig = NULL;
    void *p_sst = NULL;
    uint32_t sst_mig_len = 0;
    uint8_t *p_data = NULL;
    uint32_t obj_len = 0;
    uint32_t data_len = 0;
    uint32_t type = SST_TYPE_NONE;

    if(!name || key_len < SST_MIGRATION_KEY_LEN) {
        SST_ERR("create sst bad param!\n");
        return SST_ERROR_BAD_PARAMETERS;
    }
    //get item name
    ret = _sst_get_name(name, item_name);
    if (ret) {
        SST_ERR("get obj name failed ret 0x%x\n", ret);
        return ret;
    }
    ret = _sst_set_migration_file_name(mig_path, item_name);
    if (ret) {
        SST_ERR("get obj name failed ret 0x%x\n", ret);
        return ret;
    }

    ret = _sst_fs_get_data(mig_path, &p_sst_mig, &sst_mig_len);
    if(ret != SST_SUCCESS){
        SST_ERR("sst get mig file error!\n");
        goto clean;
    }

    /* dec migration data */
    ret = sst_imp_dec_mig_data(&type, p_sst_mig, key, &p_data, &data_len);
    if(SST_SUCCESS != ret){
        SST_ERR("enc sst mig file error!\n");
        goto clean1;
    }
    /* store mig data to sst data file */
    ret = sst_imp_create_obj(p_data, data_len, type, &p_sst, &obj_len);
    if(SST_SUCCESS != ret) {
        SST_ERR("create obj failed 0x%x\n", ret);
        goto clean2;
    }

    SST_INF("store sst file len[%d]\n", (int)obj_len);
    ret = sst_store_obj(name, p_sst, obj_len, 1);
    if( SST_SUCCESS != ret){
        SST_ERR("store sst file error!\n");
        goto clean2;
    }

clean2:
    sst_imp_destroy_obj(p_sst);
clean1:
    if(p_data){
        sst_memset(p_data, 0, data_len);
        sst_free(p_data);
    }
clean:
    if(p_sst_mig){
        sst_memset(p_sst_mig, 0, sst_mig_len);
        sst_free(p_sst_mig);
    }

    return ret;
}
#endif /* CONFIG_SST_MIGRATOIN */

#if CONFIG_DATA_MIGRATION
uint32_t sst_migration_enc_data(const char *name,
                                uint8_t *data_in,
                                uint32_t data_size,
                                uint8_t *key,
                                uint32_t *key_len)
{
    uint8_t* mig_data = NULL;
    uint32_t mig_data_len = 0;
    char mig_name[MAX_PATH_LEN + 5] = {0}; //for .mig and \0
    uint32_t ret = 0;
    uint32_t name_len = 0;

    if(NULL == name || NULL == data_in || NULL == key_len){
        SST_ERR("bad param!\n");
        return SST_ERROR_BAD_PARAMETERS;
    }

    if((NULL == key) && (0 != *key_len)){
        SST_ERR("bad key param!\n");
        return SST_ERROR_BAD_PARAMETERS;
    }

    name_len = strlen((char*)name);
    if(name_len >= MAX_PATH_LEN){
        SST_ERR("fs file name is too long:[%s]\n", (char*)name);
        return SST_ERROR_BAD_PARAMETERS;
    }

    if(*key_len < SST_MIGRATION_KEY_LEN) {
        *key_len = SST_MIGRATION_KEY_LEN;
        return SST_ERROR_SHORT_BUFFER;
    }

    /* enc the data with mig key */
    mig_data_len = sizeof(sst_mig_head) + data_size;
    mig_data = sst_malloc(mig_data_len);
    if(NULL == mig_data){
        return SST_ERROR_OUT_OF_MEMORY;
    }
    sst_memset(mig_data, 0, mig_data_len);

    ret = sst_imp_enc_mig_data(SST_TYPE_USERDATA, data_in, data_size, key, mig_data);
    if(SST_SUCCESS != ret){
        SST_ERR("enc sst mig file error!\n");
        goto _err;
    }
    *key_len = 16;

    strcpy((char*)mig_name, (char*)name);
    strcat((char*)mig_name, ".mig");

    ret = _sst_fs_store_data(mig_name, mig_data, mig_data_len, 1);
    if(SST_SUCCESS != ret){
        SST_ERR("enc sst mig file error!\n");
        goto _err;
    }

_err:
    if(mig_data){
        sst_memset(mig_data, 0, mig_data_len);
        sst_free(mig_data);
    }
    return ret;
}

uint32_t sst_migration_dec_data(const char *name, uint8_t *data_out,
                                  uint32_t *data_size, uint8_t *key, uint32_t key_len)
{
    uint32_t ret = 0;
    char mig_name[MAX_PATH_LEN + 5] = {0}; //for ".mig"
    void *p_mig_data = NULL;
    uint32_t sst_mig_len = 0;
    uint32_t type = SST_TYPE_NONE;
    uint8_t *p_data = NULL;
    uint32_t org_data_len = 0;
    uint32_t name_len = 0;

    if(NULL == name || NULL == data_size || NULL == key){
        SST_ERR("bad param!\n");
        return SST_ERROR_BAD_PARAMETERS;
    }

    if((NULL == data_out) && (0 !=*data_size)){
        SST_ERR("bad data buffer param!\n");
        return SST_ERROR_BAD_PARAMETERS;
    }

    if (key_len < SST_MIGRATION_KEY_LEN) {
        SST_ERR("short key len %d\n", key_len);
        return SST_ERROR_BAD_PARAMETERS;
    }

    name_len = strlen((char*)name);
    if(name_len >= MAX_PATH_LEN){
        SST_ERR("fs file name is too long:[%s]\n", (char*)name);
        return SST_ERROR_BAD_PARAMETERS;
    }

    strcpy((char*)mig_name, (char*)name);
    strcat((char*)mig_name, ".mig");

    ret = _sst_fs_get_data(mig_name, &p_mig_data, &sst_mig_len);
    if(ret != SST_SUCCESS){
        SST_ERR("sst get mig file error!\n");
        goto _err;
    }

    /* dec migration data */
    ret = sst_imp_dec_mig_data(&type, p_mig_data, key, &p_data, &org_data_len);
    if(SST_SUCCESS != ret){
        SST_ERR("enc sst mig file error!\n");
        goto _err;
    }
    if(org_data_len > *data_size){
        SST_ERR("enc sst buffer is too short!\n");
        *data_size = org_data_len;
        ret = SST_ERROR_SHORT_BUFFER;
        goto _err;
    }
    sst_memcpy(data_out, p_data, org_data_len);
    *data_size = org_data_len;
_err:
    if(p_data){
        sst_memset(p_data, 0, org_data_len);
        sst_free(p_data);
    }

    if(p_mig_data){
        sst_memset(p_mig_data, 0, sst_mig_len);
        sst_free(p_mig_data);
    }
    return ret;
}
#endif

