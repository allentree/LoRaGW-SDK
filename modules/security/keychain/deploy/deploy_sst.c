#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sst.h"
#include "km.h"
#include "utils.h"
#include "ali_crypto.h"

static int32_t _sec_sst_init() {
    uint32_t sst_ret = 0;

    printf("km_init\n");
    sst_ret = km_init();
    if(0 != sst_ret){
        printf("km init fail, error code: [%x]\n", sst_ret);
        return -1;
    }

    printf("sec_sst_init\n");
    // sst init
    sst_ret = sst_init();
    if (SST_SUCCESS != sst_ret) {
        printf("sst_init fail, error code: [%x]\n", sst_ret);
        return -1;
    }

    //check if storeage folder has already exist just for linkage now
    if (!access("/var/.sst", F_OK) == 0) {
        if (mkdir("/var/.sst", S_IRWXU | S_IRWXG | S_IRWXG)) {
            printf("create storage folder failed\n");
            return -1;
        }
        if (chmod("/var/.sst", S_IRWXU | S_IRWXG | S_IRWXO)) {
            printf("chmod failed\n");
            return -1;
        }
    }

    return 0;
}

#if NO_RSVD_PART_SUPPORT
// remove all security service system files
static int remove_km_file() {
    if ((access(get_sec_sys_name(), 0) == 0 && remove(get_sec_sys_name()) != 0)
        || (access(get_sec_sys_bak_name(), 0) == 0 && remove(get_sec_sys_bak_name()) != 0)
        || (access(get_sec_sys_sig_name(), 0) == 0 && remove(get_sec_sys_sig_name()) != 0)
        || (access(get_sec_sys_bak_sig_name(), 0) == 0 && remove(get_sec_sys_bak_sig_name()) != 0)) {
        return -1;
    }
    return 0;
}

// create security service system file's signature
int create_sig(const char *file, const char *sig) {
    FILE *fp_file;
    FILE *fp_file_sig;
    unsigned char *buf = NULL;
    unsigned long file_size = -1;
    struct stat statbuff;
    int i, n = 0;
    uint8_t hash_dst[SHA256_HASH_SIZE];
    int ret = -1;

    if (access(file, 0) != 0) {
        printf("%s does not exist.\n", file);
        return -1;
    }

    if (stat(file, &statbuff) < 0) {
        printf("get file %s size fail.\n", file);
        return -1;
    }
    file_size = statbuff.st_size;

    fp_file = fopen(file, "rb");
    if (NULL == fp_file) {
        printf("cannot open %s\n", file);
        return -1;
    }

    do {
        buf = (unsigned char *)malloc(file_size);
        if (NULL == buf) {
            printf("buf malloc fail.\n");
            break;
        }
        // read file content
        while(!feof(fp_file)) {
            i = fread(buf + n, 1, 1024, fp_file);
            if (i <= 0) {
                break;
            }
            n += i;
        }

        if (n != file_size) {
            printf("read file fail.\n");
            break;
        }

        ali_crypto_result alicrypto_ret = ali_hash_digest(SHA256, buf, file_size, hash_dst);
        if (ALI_CRYPTO_SUCCESS != alicrypto_ret) {
            printf("hash fail.\n");
            break;
        }

        fp_file_sig = fopen(sig, "wb");
        if (NULL == fp_file_sig) {
            printf("cannot open %s\n", sig);
            break;
        }

        if (fwrite(hash_dst, 1, SHA256_HASH_SIZE, fp_file_sig) != SHA256_HASH_SIZE) {
            printf("write sig file %s fail.\n", sig);
            fclose(fp_file_sig);
            break;
        }
        fclose(fp_file_sig);
        ret = 0;
    } while(0);

    if (NULL != buf) {
        free(buf);
    }
    fclose(fp_file);
    return ret;
}
#endif /* NO_RSVD_PART_SUPPORT */

int main(int argc, char **argv) {
    int ret = 0;
#if NO_RSVD_PART_SUPPORT
    char *km_file;
    char *km_bak_file;
    char *km_sig_file;
    char *km_bak_sig_file;
    int check_ret1, check_ret2;
    int need_deploy = 0;
#endif /* NO_RSVD_PART_SUPPORT */

    if (argc < 1 || argc > 2 || (argc == 2 && (strcmp(argv[1], "-f") != 0))) {
        printf("deploy_sst: invalid option\n"
               "Usage: deploy_sst [OPTION]\n"
               "Deploy security storage's system related information.\n"
               "\n"
               "-f	force to update security storage's system related information\n");
        return -1;
    } else if (argc == 2 && (strcmp(argv[1], "-f") == 0)) {
        printf("force to update sys file.\n");
#if NO_RSVD_PART_SUPPORT
        need_deploy = 1;
#endif /* NO_RSVD_PART_SUPPORT */
    }

#if NO_RSVD_PART_SUPPORT
    km_file = get_sec_sys_name();
    km_bak_file = get_sec_sys_bak_name();
    km_sig_file = get_sec_sys_sig_name();
    km_bak_sig_file = get_sec_sys_bak_sig_name();

    if (need_deploy == 0) {
        check_ret1 = check_file_sig(km_file, km_sig_file);
        check_ret2 = check_file_sig(km_bak_file, km_bak_sig_file);
        if (check_ret1 == 0 && check_ret2 == 0) {
            if (check_file_same(km_sig_file, km_bak_sig_file) == 0) {
                printf("security storage system file has already deployed, if you want to deploy it again, please rerun program with parameter '-f'\n");
            } else {
                printf("sys file is modified, use backup file to overwrite it.\n");
                if (copy_file(km_bak_file, km_file) != 0 || copy_file(km_bak_sig_file, km_sig_file) != 0) {
                    printf("bak to sys fail.\n");
                    ret = -1;
               }
            }
        } else if (check_ret1 == 0) {
            printf("backup file is modified, back sys file up again.\n");
            if (copy_file(km_file, km_bak_file) != 0 || copy_file(km_sig_file, km_bak_sig_file) != 0) {
                printf("sys to bak fail.\n");
                ret = -1;
           }
        } else if (check_ret2 == 0) {
            printf("sys file is modified, use backup file to overwrite it.\n");
            if (copy_file(km_bak_file, km_file) != 0 || copy_file(km_bak_sig_file, km_sig_file) != 0) {
                printf("bak to sys fail.\n");
                ret = -1;
            }
        } else {
            printf("sys files are not deployed, or sys file and backup file are all modified, recreate sys file and backup it.\n");
            need_deploy = 1;
        }
    }

    if (need_deploy == 1) {
        do {
            if(remove_km_file() != 0) {
                printf("remove old file fail, please check you permission.\n");
                ret = -1;
                break;
            }
            ret = _sec_sst_init();
            if (ret != 0) {
                printf("_sec_sst_init fail\n");
                break;
            }
            if (create_sig(km_file, km_sig_file) != 0 || copy_file(km_file, km_bak_file) != 0 || copy_file(km_sig_file, km_bak_sig_file) != 0) {
                printf("create sig and backup fail.\n");
                ret = -1;
                break;
            }
        } while(0);
    }
#else
    ret = _sec_sst_init();
    if (ret) {
        printf("for rsvd part _sec_sst_init_fail\n");
    }

#endif /* NO_RSVD_PART_SUPPORT */

    if (ret != 0) {
        printf("deploy fail.\n");
    } else {
        printf("deploy success.\n");
    }
    return ret;
}
