#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "ali_crypto.h"
#include "tfs_log.h"

#define TAG "tfs"

int check_file_sig(const char *file, const char *file_sig) {
    FILE *fp_file;
    FILE *fp_file_sig;
    unsigned char *buf = NULL;
    unsigned char *content = NULL;
    unsigned long file_size = -1;
    struct stat statbuff;
    int i, n = 0;
    uint8_t hash_dst[SHA256_HASH_SIZE];
    uint8_t stored_hash[SHA256_HASH_SIZE];
    int ret = -1;

    if (access(file, 0) != 0) {
        log_e(TAG, "%s does not exist.\n", file);
        return -1;
    }
    if (access(file_sig, 0) != 0) {
        log_e(TAG, "%s does not exist.\n", file_sig);
        return -1;
    }

    if (stat(file_sig, &statbuff) < 0) {
        log_e(TAG, "get file %s size fail.\n", file_sig);
        return -1;
    }
    if (statbuff.st_size != SHA256_HASH_SIZE) {
        log_e(TAG, "get file %s size wrong.\n", file_sig);
        return -1;
    }

    if (stat(file, &statbuff) < 0) {
        log_e(TAG, "get file %s size fail.\n", file);
        return -1;
    }
    file_size = statbuff.st_size;

    fp_file = fopen(file, "r");
    if (NULL == fp_file) {
        log_e(TAG, "cannot open %s\n", file);
        return -1;
    }

    do {
        content = (unsigned char *)malloc(file_size);
        if (NULL == content) {
            log_e(TAG, "content malloc fail.\n");
            break;
        }

        buf = (unsigned char *)malloc(1024);
        if (NULL == buf) {
            log_e(TAG, "buf malloc fail.\n");
            break;
        }

        // read file content
        for(;;) {
            i = fread(buf, 1, 1024, fp_file);
            if (i <= 0) {
                break;
            }
            if (n + i > file_size) {
                break;
            }
            memcpy(content + n, buf, i);
            n += i;
        }

        if (n != file_size) {
            log_e(TAG, "read file fail.\n");
            break;
        }

        ali_crypto_result alicrypto_ret = ali_hash_digest(SHA256, content, file_size, hash_dst);
        if (ALI_CRYPTO_SUCCESS != alicrypto_ret) {
            log_e(TAG, "hash fail.\n");
            break;
        }

        fp_file_sig = fopen(file_sig, "r");
        if (NULL == fp_file_sig) {
            log_e(TAG, "cannot open %s\n", file_sig);
            break;
        }

        i = fread(stored_hash, 1, SHA256_HASH_SIZE, fp_file_sig);
        if (i <= 0) {
            log_e(TAG, "read sig file %s error.\n", file_sig);
            fclose(fp_file_sig);
            break;
        }
        fclose(fp_file_sig);
        if (memcmp(hash_dst, stored_hash, SHA256_HASH_SIZE) != 0) {
            log_e(TAG, "check sig fail.\n");
            break;
        }
        ret = 0;
    } while(0);

    if (NULL != buf) {
        free(buf);
    }
    if (NULL != content) {
        free(content);
    }
    fclose(fp_file);
    return ret;
}

int check_file_same(const char *file1, const char *file2) {
    FILE *fp_file1;
    FILE *fp_file2;
    struct stat statbuff1, statbuff2;
    int n1, n2 = 0;
    uint8_t buf1[256];
    uint8_t buf2[256];
    int ret = 0;

    if (access(file1, 0) != 0 || access(file2, 0) != 0 ) {
        log_e(TAG, "ERR: %s or %s does not exist.\n", file1, file2);
        return -1;
    }

    if (stat(file1, &statbuff1) != 0 || stat(file2, &statbuff2) != 0) {
        log_e(TAG, "ERR: get file %s or %s size fail.\n", file1, file2);
        return -1;
    }

    if (statbuff1.st_size != statbuff2.st_size) {
        log_e(TAG, "ERR: size differ.\n");
        return -1;
    }

    fp_file1 = fopen(file1, "rb");
    if (NULL == fp_file1) {
        log_e(TAG, "ERR: cannot open %s\n", file1);
        return -1;
    }
    fp_file2 = fopen(file2, "rb");
    if (NULL == fp_file2) {
        log_e(TAG, "ERR: cannot open %s\n", file2);
        fclose(fp_file1);
        return -1;
    }

    while(!feof(fp_file1) && !feof(fp_file2)) {
        n1 = fread(buf1, 1, 256, fp_file1);
        n2 = fread(buf2, 1, 256, fp_file2);
        if (n1 <= 0 || n2 <= 0 || n1 != n2) {
            log_e(TAG, "read file fail.\n");
            ret = -1;
            break;
        } else {
            if (memcmp(buf1, buf2, n1) != 0) {
                log_e(TAG, "file %s and file %s differ.\n", file1, file2);
                ret = -1;
                break;
            }
        }
    }

    fclose(fp_file1);
    fclose(fp_file2);

    if (ret == 0) {
        log_d(TAG, "file and backup file are same.\n");
    }
    return ret;
}

char *get_sec_sys_name() {
    const char *letters = "abcdefghijklmnopqrstuvwxyz./_";
    static char name[100];
    int number[] = {27, 20, 18, 17, 27, 26, 18, 4, 2, 20, 17, 8, 19, 24, 27, 26, 3, 4, 21, 28, 10, 4, 24};
    memset(name, 0, 100);
    int i = 0;
    for (i = 0; i < sizeof(number)/sizeof(int); i ++) {
        strncpy(name + strlen(name), letters + number[i], 1);
    }

    return name;
}

char *get_sec_sys_sig_name() {
    const char *letters = "abcdefghijklmnopqrstuvwxyz./_";
    static char name[100];
    int number[] = {27, 20, 18, 17, 27, 26, 18, 4, 2, 20, 17, 8, 19, 24, 27, 26, 3, 4, 21, 28, 10, 4, 24, 28, 18, 8, 6};
    memset(name, 0, 100);
    int i = 0;
    for (i = 0; i < sizeof(number)/sizeof(int); i ++) {
        strncpy(name + strlen(name), letters + number[i], 1);
    }

    return name;
}

char *get_sec_sys_bak_name() {
    const char *letters = "abcdefghijklmnopqrstuvwxyz./_";
    static char name[100];
    int number[] = {27, 4, 19, 2, 27, 26, 18, 4, 2, 27, 26, 18, 4, 2, 28, 1, 0, 10};
    memset(name, 0, 100);
    int i = 0;
    for (i = 0; i < sizeof(number)/sizeof(int); i ++) {
        strncpy(name + strlen(name), letters + number[i], 1);
    }

    return name;
}

char *get_sec_sys_bak_sig_name() {
    const char *letters = "abcdefghijklmnopqrstuvwxyz./_";
    static char name[100];
    int number[] = {27, 4, 19, 2, 27, 26, 18, 4, 2, 27, 26, 18, 4, 2, 28, 1, 0, 10, 28, 18, 8, 6};
    memset(name, 0, 100);
    int i = 0;
    for (i = 0; i < sizeof(number)/sizeof(int); i ++) {
         strncpy(name + strlen(name), letters + number[i], 1);
    }

    return name;
}

int copy_file(const char *file1, const char *file2) {
    FILE *fp1 = NULL;
    FILE *fp2 = NULL;
    int c = 0;
    char buf[1024];
    char path[FILENAME_MAX];
    char *pos = NULL;

    memset(buf, 0, 1024);
    memset(path, 0, FILENAME_MAX);

    pos = strrchr(file2, '/');
    if (NULL == pos) {
        log_e(TAG, "get %s path fail.\n", file2);
        return -1;
    }

    strncpy(path, file2, pos - file2);
    if (access(path, 0) != 0 && mkdir(path, 0755) != 0) {
        log_e(TAG, "create %s fail.\n", path);
        return -1;
    }

    if ((fp2 = fopen(file2, "wb")) == NULL) {
       log_e(TAG, "open %s fail\n", file2);
       return -1;
    }

    if ((fp1 = fopen(file1, "rb")) == NULL) {
        log_e(TAG, "open %s fail\n", file1);
        fclose(fp2);
        return -1;
    }

    while((c = fread(buf, 1, 1024, fp1)) > 0) {
       fwrite(buf, 1, c, fp2);
    }

    fclose(fp1);
    fclose(fp2);
    return 0;
}

