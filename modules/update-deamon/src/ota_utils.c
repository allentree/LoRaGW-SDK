
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ota_utils.h"
#include "update_global.h"
#include "ecdsa_operation.h"

#include "cJSON.h"
//cjson file defines
#define CJSON_OBJ_FILE_LIST "file-list"

#define OTA_BACKUP_POSTFIX ".backup"
#define OTA_DELETE_POSTFIX ".delete"

char *state_string[OTA_STATE_MAX] = 
{
    OAT_STATE_FILE_IDLE,
    OAT_STATE_FILE_DL,
    OAT_STATE_FILE_VERIFING,
    OAT_STATE_FILE_WRITTING,
    OAT_STATE_FILE_CHECKING,
    OAT_STATE_FILE_DONE,
};

extern update_global_st g_update; 

static cJSON *ota_load_json(const char *file_path);

static int ota_shell_scripts_create(const char * path);
static int ota_shell_scripts_add2tail(const char * path, const char * string);

static int parse_ota_info_file_node(ota_package_st * package, const cJSON *file_info);

int ota_exe_cmd(const char *cmd, char *result, int max_len)
{
    FILE *ptr;
    char buf[4096];
    int total_sz = 0;

    if(!cmd || !result || 0 >= max_len) {
        return -1;
    }
    if(max_len > 4096)
        max_len = 4096;

    if ((ptr = popen(cmd, "r")) != NULL) {
        

        while (fgets(buf, sizeof(buf), ptr) != NULL) {

            total_sz += strlen(buf);

            if (total_sz >= max_len) {
                break;
            }

            strncat(result, buf, strlen(buf));
        }

        pclose(ptr);
        ptr = NULL;
    } else {
        //log_err("popen %s error", cmd);
        return -1;
    }

    return 0;
}

int get_ota_state(oat_state_et * state)
{
    char tmp[64] = {0};
    pthread_mutex_lock(&g_update.lock);
    sprintf(tmp, "/%s", OAT_STATE_FILE_IDLE);
    if(access(tmp, F_OK) == 0) {
        *state = OTA_STATE_IDLE;
        pthread_mutex_unlock(&g_update.lock);
        return 0;
    }

    sprintf(tmp, "/%s", OAT_STATE_FILE_DL);
    if(access(tmp, F_OK) == 0) {
        *state = OTA_STATE_DOWNLOADING;
        pthread_mutex_unlock(&g_update.lock);
        return 0;
    }

    sprintf(tmp, "/%s", OAT_STATE_FILE_VERIFING);
    if(access(tmp, F_OK) == 0) {
        *state = OTA_STATE_VERIFIING;
        pthread_mutex_unlock(&g_update.lock);
        return 0;
    }

    sprintf(tmp, "/%s", OAT_STATE_FILE_WRITTING);
    if(access(tmp, F_OK) == 0) {
        *state = OTA_STATE_WRITTING;
        pthread_mutex_unlock(&g_update.lock);
        return 0;
    }

    sprintf(tmp, "/%s", OAT_STATE_FILE_CHECKING);
    if(access(tmp, F_OK) == 0) {
        *state = OTA_STATE_CHECKING;
        pthread_mutex_unlock(&g_update.lock);
        return 0;
    }


    sprintf(tmp, "/%s", OAT_STATE_FILE_DONE);
    if(access(tmp, F_OK) == 0) {
        *state = OTA_STATE_DONE;
        pthread_mutex_unlock(&g_update.lock);
        return 0;
    }
    pthread_mutex_unlock(&g_update.lock);
    return -1;
}
int set_ota_state(oat_state_et state)
{
    char tmp[64] = {0};
    int fd = -1;
    
    if(state >= OTA_STATE_MAX) {
        return -1;
    }
    char cmd_ret[1024];
    pthread_mutex_lock(&g_update.lock);
    if(ota_exe_cmd("rm -f /.update_*", cmd_ret, 1024) < 0) {
        log_err("call system cmd : rm -f /.update_* , failed!!!");
        pthread_mutex_unlock(&g_update.lock);
        return -1;
    }
    else {
        log_info("exe cmd success ret %s!!!", cmd_ret);
    }
    sprintf(tmp, "touch /%s", state_string[state]);
    cmd_ret[0] = '\0';

    if(ota_exe_cmd(tmp, cmd_ret, 1024) < 0) {
        log_err("call system cmd : %s , failed!!!", tmp);
        pthread_mutex_unlock(&g_update.lock);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", tmp, cmd_ret);
    }

    sprintf(tmp, "/%s", state_string[state]);
    if(OTA_STATE_CHECKING == state || OTA_STATE_WRITTING == state || OTA_STATE_DONE == state) {
        fd = open(tmp, O_RDWR|O_TRUNC );
        if(fd < 0) {
            log_err("create state file error! ");
            pthread_mutex_unlock(&g_update.lock);
            return -1;
        }
        if(write(fd, OTA_STORE_DIR, strlen(OTA_STORE_DIR) + 1) < 0) {
            log_err("write OTA path to %s  error! ", OTA_STORE_DIR);
            close(fd);
            pthread_mutex_unlock(&g_update.lock);
            return -1;
        }
        close(fd);
    }
    g_update.ota_state = state;
    pthread_mutex_unlock(&g_update.lock);
    return 0;
}
int parse_ota_info_file_node(ota_package_st * package, const cJSON *file_info) 
{
    if(!package || !file_info)
        return -1;
    int type = -1; // 0 : file; 1 : exec
#define OTA_FILE_TYPE_NORMAL 0
#define OTA_FILE_TYPE_EXEC 1    
    int oper = -1; // 0: new, 1: delete, 2 : modify 
#define OTA_FILE_OPR_NEW 0
#define OTA_FILE_OPR_DEL 1  
#define OTA_FILE_OPR_MOD 2

    char src_path[FILENAME_MAX + 1] ;
    char dest_path[FILENAME_MAX + 1] ;
    char tmp[FILENAME_MAX*2];

    const cJSON *file_name = cJSON_GetObjectItem(file_info, "name");
    //const cJSON *file_path = cJSON_GetObjectItem(file_info, "path");
    const cJSON *file_type = cJSON_GetObjectItem(file_info, "type");
    //const cJSON *file_opr = cJSON_GetObjectItem(file_info, "operation");

    if(!file_name || !file_type) {
        log_err("failed to get file name and type!!!");
        return -1;
    }
    sprintf(src_path, "%s%s", OTA_STORE_DIR, file_name->valuestring);

    if(strcmp(file_type->valuestring, "file") == 0) {
        type = OTA_FILE_TYPE_NORMAL;
    }
    else if(strcmp(file_type->valuestring, "exec") == 0) {
        type = OTA_FILE_TYPE_EXEC;
    }
    else {
        log_err("%s have a invalid type %s !!!",file_name->valuestring, file_type->valuestring);
        return -1;
    }

    if(type == OTA_FILE_TYPE_NORMAL) {

        const cJSON *file_path = cJSON_GetObjectItem(file_info, "path");
        if(!file_path) {
            log_err("%s have not assign the path!!!",file_name->valuestring );
            return -1;
        }
        sprintf(dest_path, "%s/%s", file_path->valuestring, file_name->valuestring);
        const cJSON *file_opr = cJSON_GetObjectItem(file_info, "operation");
        if(!file_opr) {
            log_err("%s have not assign the operation!!!",file_name->valuestring);
            return -1;
        }
        if(strcmp(file_opr->valuestring, "new") == 0) {
            oper = OTA_FILE_OPR_NEW;
        }
        else if(strcmp(file_opr->valuestring, "delete") == 0) {
            oper = OTA_FILE_OPR_DEL;
        }
        else if(strcmp(file_opr->valuestring, "modify") == 0) {
            oper = OTA_FILE_OPR_MOD;
        }
        else {
            log_err("%s have a invalid opreation %s !!!",file_name->valuestring, file_opr->valuestring);
            return -1;
        }
        //check the operations
        switch(oper) {
            case OTA_FILE_OPR_NEW:
            if(access(dest_path, F_OK) == 0) {
                log_warn("%s have a error opreation %s, change operation to modify",file_name->valuestring, file_opr->valuestring);
                oper = OTA_FILE_OPR_MOD;
            }
            break;
            case OTA_FILE_OPR_MOD:
            if(access(dest_path, F_OK) < 0) {
                log_warn("%s have a error opreation %s ,change operation to new",file_name->valuestring, file_opr->valuestring);
                oper = OTA_FILE_OPR_NEW;
            }
            break;
            case OTA_FILE_OPR_DEL:
            if(access(dest_path, F_OK) < 0) {
                log_warn("%s have a error opreation %s, delete a file that is not exist!!!",file_name->valuestring, file_opr->valuestring);
                oper = -1;
            }
            break;

        }
        if(oper < OTA_FILE_OPR_NEW) {
            return -1;
        }
        if(oper == OTA_FILE_OPR_NEW || oper == OTA_FILE_OPR_MOD ) {
            //check the src file 
            if(access(src_path, F_OK) < 0) {
                log_err("error:srouce file %s is not exsit!!!", src_path);
                return -1;
            }
        }
        
        //每次对文件更新都进行检查，防止对文件进行修改的时候，产生意外掉电
        switch(oper) {
            case OTA_FILE_OPR_NEW:
                //first : make sure the dir is OK 
                sprintf(tmp, "mkdir -p %s\n", file_path->valuestring);
                if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_update );
                    return -1;
                }
                //set up update shell -> cp the src path to dest path: considering the file is dir
                sprintf(tmp, "if [ ! -e %s ]; then\ncp -rf %s %s\nfi\n",dest_path, src_path, dest_path);
                //sprintf(tmp, "cp -rf %s %s\n", src_path, dest_path);
                if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_update );
                    return -1;
                }
                //set up rollback shell -> rm the dest path: considering the file is dir
                sprintf(tmp, "rm -rf %s\n", dest_path);
                if(ota_shell_scripts_add2tail(package->ota_rollback, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_rollback );
                    return -1;
                }
                //do not need to setup update_done.sh
            break;
            case OTA_FILE_OPR_MOD:
                //set up update shell -> backup the dest path : considering the file is dir
                sprintf(tmp, "if [ ! -e %s%s ]; then\nmv -f %s %s%s\nfi\n", dest_path, OTA_BACKUP_POSTFIX, dest_path, dest_path, OTA_BACKUP_POSTFIX);
                if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_update );
                    return -1;
                }

                sprintf(tmp, "if [ ! -e %s ]; then\ncp -rf %s %s\nfi\n", dest_path, src_path, dest_path);
                if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_update );
                    return -1;
                }

                //set up rollback shell -> rm the dest path: considering the file is dir
                sprintf(tmp, "if [ -e %s%s ]; then\nrm -rf %s\nfi\n",dest_path, OTA_BACKUP_POSTFIX, dest_path);
                if(ota_shell_scripts_add2tail(package->ota_rollback, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_rollback );
                    return -1;
                }

                sprintf(tmp, "if [ -e %s%s ]; then\nmv -f %s%s %s\nfi\n", dest_path, OTA_BACKUP_POSTFIX, dest_path, OTA_BACKUP_POSTFIX, dest_path);
                if(ota_shell_scripts_add2tail(package->ota_rollback, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_rollback );
                    return -1;
                }

                //setup update done shell
                sprintf(tmp, "rm -rf %s%s\n", dest_path, OTA_BACKUP_POSTFIX);
                if(ota_shell_scripts_add2tail(package->ota_update_done, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_update_done );
                    return -1;
                }
            break;
            case OTA_FILE_OPR_DEL:
                //set up update shell -> backup the dest path : considering the file is dir
                sprintf(tmp, "if [ ! -e %s%s ]; then\nmv -f %s %s%s\nfi\n", dest_path, OTA_DELETE_POSTFIX, dest_path, dest_path, OTA_DELETE_POSTFIX);
                if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_update );
                    return -1;
                }

                //set up rollback shell -> recovery the dest path: considering the file is dir
                sprintf(tmp, "if [ -e %s%s ]; then\nmv -f %s%s %s\nfi\n", dest_path, OTA_DELETE_POSTFIX, dest_path, OTA_DELETE_POSTFIX, dest_path);
                if(ota_shell_scripts_add2tail(package->ota_rollback, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_rollback );
                    return -1;
                }

                //setup update done shell
                sprintf(tmp, "rm -rf %s%s\n", dest_path, OTA_DELETE_POSTFIX);
                if(ota_shell_scripts_add2tail(package->ota_update_done, tmp) < 0) {
                    log_err("write %s to %s failed", tmp , package->ota_update_done );
                    return -1;
                }

            break;

        }


    }
    else { /*the file is shell which need to be exec*/
        //我们不限制shell操作，但是厂商需要提供一个可以对应的回滚shell脚本，否则很难去根据厂商的脚本去解析生成一个rollback脚本
        //这个脚本一定不能进行reboot操作
        
        const cJSON *file_rollback = cJSON_GetObjectItem(file_info, "rollback");
        if(!file_rollback) {
            log_err("get rollback shell failed!!!",file_name->valuestring);
            return -1;
        }
        sprintf(dest_path, "%s%s", OTA_STORE_DIR, file_rollback->valuestring);

        if(access(src_path, F_OK) < 0) {
            log_err("error: exec shell %s is not exist!!!", src_path);
            return -1;
        }

        if(access(dest_path, F_OK) < 0) {
            log_err("error: rollback shell %s is not exist!!!", dest_path);
            return -1;
        }

        //cd the store dir & ./shell
        sprintf(tmp, "cd %s\n", OTA_STORE_DIR);
        if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
            log_err("write %s to %s failed", tmp , package->ota_update );
            return -1;
        }
        sprintf(tmp, "chmod 755 %s\n", file_name->valuestring);
        if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
            log_err("write %s to %s failed", tmp , package->ota_update );
            return -1;
        }
        sprintf(tmp, "./%s\n", file_name->valuestring);
        if(ota_shell_scripts_add2tail(package->ota_update, tmp) < 0) {
            log_err("write %s to %s failed", tmp , package->ota_update );
            return -1;
        }

        sprintf(tmp, "cd %s\n", OTA_STORE_DIR);
        if(ota_shell_scripts_add2tail(package->ota_rollback, tmp) < 0) {
            log_err("write %s to %s failed", tmp , package->ota_rollback );
            return -1;
        }
        sprintf(tmp, "chmod 755 %s\n", file_rollback->valuestring);
        if(ota_shell_scripts_add2tail(package->ota_rollback, tmp) < 0) {
            log_err("write %s to %s failed", tmp , package->ota_rollback );
            return -1;
        }
        sprintf(tmp, "./%s\n", file_rollback->valuestring);
        if(ota_shell_scripts_add2tail(package->ota_rollback, tmp) < 0) {
            log_err("write %s to %s failed", tmp , package->ota_rollback );
            return -1;
        }
    }

    return 0;

}

int parse_ota_files_from_jcson(ota_package_st * package)
{
    cJSON *root = NULL;
    if(!package || !package->ota_info_path )
        return -1;

    root = ota_load_json(package->ota_info_path);
    if(root == NULL) {
        log_err("failed to get the config's json-root!!");
        return -1;
    }
    const cJSON *ota_files = cJSON_GetObjectItem(root, CJSON_OBJ_FILE_LIST);
    if(!ota_files) {
        log_err("failed to get the file-list!!");
        cJSON_Delete(root);
        return -1;
    }
    int list_count = cJSON_GetArraySize(ota_files);
    if (list_count <= 0) {
        log_err("there is no files in config !!!");
        cJSON_Delete(root);
        return -1;
    }
    log_info("there is %d files in ota packages!", list_count);
    int i;
    for (i = 0; i < list_count; ++i) {
        const cJSON *file_info = cJSON_GetArrayItem(ota_files, i);
        if(file_info == NULL) {
            continue;
        }
        
        if(parse_ota_info_file_node(package, file_info) < 0) {
            log_err("parse ota file info failed!!! please check the jscon and files!");
            cJSON_Delete(root);
            return -1;
        }

    }
    cJSON_Delete(root);
    return 0;
}
int get_realpath_by_exec_dir(char* real_dir, const char* offset_to_exec)
{
    char abs_gateway_root[FILENAME_MAX + 1] = "../";

    if (NULL == real_dir)
        return -1;

   
    char rel_gateway_root[FILENAME_MAX + 1];
    int len = readlink("/proc/self/exe", rel_gateway_root, FILENAME_MAX);
    if (len <= 0)
        return -1;
    rel_gateway_root[len] = '\0';
	
    char* path_end = strrchr(rel_gateway_root, '/');
	if(NULL == path_end)
		return -1;
	
	path_end++;
    *path_end = '\0';
	/*
    strcat(rel_gateway_root, "/../");
    */
    if(!offset_to_exec || strlen(offset_to_exec) == 0)
    {
	    strcpy(real_dir, rel_gateway_root);
	    return 0;
    }
    else
    {
		strcat(rel_gateway_root, offset_to_exec);
    }
    char* real_path = realpath(rel_gateway_root, abs_gateway_root);
    if (NULL == real_path) {
        strcpy(real_dir, rel_gateway_root);
        return -1;
    }
  
    strcpy(real_dir, abs_gateway_root);

    return 0;
}



int unpackage_ota_package(ota_package_st * package)
{
    char cmd[FILENAME_MAX + 1] = {0};
    char filePath[FILENAME_MAX + 1] = {0};
    char cmd_ret[1024] = { 0 };
    //int ret = 0;
    if(!package)
        return -1;
    
    sprintf(cmd, "mkdir -p %s", OTA_STORE_DIR);

    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }

    //rm all file in OTA_STORE_DIR 
    sprintf(cmd, "rm -rf %s*" , OTA_STORE_DIR);
    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }

    sprintf(cmd, "tar zxf %s -C %s", package->ota_file_path , OTA_STORE_DIR);

    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }

    sprintf(filePath, "%s%s" , OTA_STORE_DIR, OTA_PACKAGE_NAME);

    if(access(filePath, F_OK) < 0) {
        log_err("ota packages %s  not exit in OTA packages!!!", OTA_PACKAGE_NAME);
        return -1;
    }
    package->package_path = strdup(filePath);

    sprintf(filePath, "%s%s" , OTA_STORE_DIR, OTA_PACKAGE_SIGN_NAME);

    if(access(filePath, F_OK|R_OK) < 0) {
        log_err("ota files's sign %s not exit in OTA packages", OTA_PACKAGE_SIGN_NAME);
        return -1;
    }
    package->sign_path = strdup(filePath);

    return 0;
}
int ota_shell_scripts_add2tail(const char * path, const char * string)
{
    if(!path || !string)
        return -1;
    FILE *fp = NULL; 

    fp = fopen(path, "a");
    if (!fp) {
        log_err("open %s failed!!!", path);
        return -1;
    }
    if( 1 != fwrite(string, strlen(string), 1, fp) ) {
        log_err("write %s faild!!!", path);
        fclose(fp);
        fp = NULL;
        return -1;
    }
    fclose(fp);
    fp = NULL;
    return 0;
}
int ota_shell_scripts_create(const char * path) 
{
    if(!path || strlen(path) == 0)
        return -1;
    //char cmd[128] = {0};

    FILE *fp = NULL; 

    fp = fopen(path, "w");
    if (!fp) {
        log_err("open %s failed!!!", path);
        return -1;
    }
    if(access("/bin/sh", F_OK) == 0) {
        if( 1 != fwrite("#!/bin/sh\n", strlen("#!/bin/sh\n"), 1 , fp )) {
            log_err("write to %s failed!!!", path);
            fclose(fp);
            fp =NULL;
            return -1;
        }
    }
    else if(access("/bin/bash", F_OK) == 0) {
        if( 1 != fwrite("#!/bin/bash\n", strlen("#!/bin/bash\n"), 1 , fp )) {
            log_err("write to %s failed!!!", path);
            fclose(fp);
            fp =NULL;
            return -1;
        }
    }
    else {
        log_err("not support current shell!!!");
        fclose(fp);
        fp =NULL;
        return -1;
    }
    
    
    fclose(fp);
    fp =NULL;
    
    return 0;
}

int check_ota_package_files(ota_package_st * package)
{
    int ret = 0;
    char cmd[FILENAME_MAX + 1] = {0};
    char cmd_ret[1024] = { 0 };

    if (!package) {
        return -1;
    }
    if(!package->package_path || !package->sign_path || !strlen(g_update.public_key_path)) {
        log_err("files not valid while check the signature!");
        g_update.sign_valid = 0;
        return -1;
    }
    ret = ESDSA_verify_sign_with_publicKey(g_update.public_key_path, package->package_path, package->sign_path);
    if(ret != ESDSA_NO_ERROR) {
        log_err("check the signature failed!!! error code %d !", ret);
        g_update.sign_valid = 0;
        return -1;
    }

    g_update.sign_valid = 1;

    log_info("check the signature successful!!!\n");

    //tar the ota packages
    sprintf(cmd, "tar zxf %s -C %s", package->package_path, OTA_STORE_DIR);
    
    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }

    sprintf(cmd, "%s%s", OTA_STORE_DIR, OTA_UPDATE_SHELL);
    //OTA_UPDATE_SHELL should not be in the packages
    if(access(cmd, F_OK) >= 0) {
        log_err("%s should not exit in OTA packages", OTA_UPDATE_SHELL);
        g_update.sh_valid = 0;
        return -1;
    }
    package->ota_update = strdup(cmd);
//create the shell
    ret = ota_shell_scripts_create(package->ota_update);
    if(ret < 0) {
        log_err("failed to create %s", OTA_UPDATE_SHELL);
        return -1;
    }
//chmod the shell
    sprintf(cmd, "chmod 755 %s%s", OTA_STORE_DIR, OTA_UPDATE_SHELL);

    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }

    sprintf(cmd, "%s%s", OTA_STORE_DIR, OTA_UPDATE_ROLLBACK_SHELL);
    //OTA_UPDATE_ROLLBACK_SHELL should not in the packages
    if(access(cmd, F_OK) == 0) {
        log_err("%s shoud not exit in OTA packages" , OTA_UPDATE_ROLLBACK_SHELL);
        g_update.sh_valid = 0;
        return -1;
    }
    package->ota_rollback = strdup(cmd);
    //create the shell
    ret = ota_shell_scripts_create(package->ota_rollback);
    if(ret < 0) {
        log_err("failed to create %s", OTA_UPDATE_ROLLBACK_SHELL);
        return -1;
    }
    //chmod the shell
    sprintf(cmd, "chmod 755 %s%s", OTA_STORE_DIR, OTA_UPDATE_ROLLBACK_SHELL);

    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }

    sprintf(cmd, "%s%s", OTA_STORE_DIR, OTA_UPDATE_DONE_SHELL);
    //OTA_UPDATE_DONE_SHELL should ont in the packages
    if(access(cmd, F_OK) == 0) {
        log_err("%s shoud not exit in OTA packages", OTA_UPDATE_DONE_SHELL);
        g_update.sh_valid = 0;
        return -1;
    }
    package->ota_update_done = strdup(cmd);
    //create the shell
    ret = ota_shell_scripts_create(package->ota_update_done);
    if(ret < 0) {
        log_err("failed to create %s", OTA_UPDATE_DONE_SHELL);
        return -1;
    }

    sprintf(cmd, "chmod 755 %s%s", OTA_STORE_DIR, OTA_UPDATE_DONE_SHELL);
    //chmod the shell
    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }

    sprintf(cmd, "%s%s", OTA_STORE_DIR, OTA_UPDATE_INFO);
    //the update.jcson must be there
    if(access(cmd, F_OK | R_OK) < 0) {
        log_err("%s not exit in OTA packages",OTA_UPDATE_INFO);
        g_update.sh_valid = 0;
        return -1;
    }
    package->ota_info_path = strdup(cmd);

    g_update.sh_valid = 1;

    return 0;
}

int check_ota_dependment(ota_package_st * package)
{
    cJSON *root = NULL;
    if(!package) {
        return -1;
    }
    if(!package->ota_info_path) {
        log_err("Error : do not get the package configs!!!");
        return -1;
    }

    root = ota_load_json(package->ota_info_path);
    if(root == NULL) {
        log_err("failed to get the config's json-root!!");
        return -1;
    }
    const cJSON *ota_config = cJSON_GetObjectItem(root, "ota-info");
    if(!ota_config) {
        log_err("failed to get the config's ota-info!!");
        cJSON_Delete(root);
        return -1;
    }
    const cJSON *manufacturer =  cJSON_GetObjectItem(ota_config, "manufacturer");
    if(!manufacturer) {
        log_err("failed to get the config's manufacturer info!!");
        cJSON_Delete(root);
        //cJSON_Delete(ota_config);
        return -1;
    }
    const cJSON *hw_ver =  cJSON_GetObjectItem(ota_config, "hw_version");
    if(!hw_ver) {
        log_err("failed to get the config's hw_version info!!");
        cJSON_Delete(root);
        //cJSON_Delete(ota_config);
        //cJSON_Delete(manufacturer);
        return -1;
    }
    const cJSON *sw_ver =  cJSON_GetObjectItem(ota_config, "sw_version");
    if(!sw_ver) {
        log_err("failed to get the config's sw_version info!!");
        cJSON_Delete(root);
        //cJSON_Delete(ota_config);
        //cJSON_Delete(manufacturer);
        //cJSON_Delete(hw_ver);
        return -1;
    }

    const cJSON *ota_ver =  cJSON_GetObjectItem(ota_config, "current_version");
    if(!ota_ver) {
        log_err("failed to get the config's current ota version info!!");
        cJSON_Delete(root);
       // cJSON_Delete(ota_config);
        //cJSON_Delete(manufacturer);
        //cJSON_Delete(hw_ver);
        //cJSON_Delete(sw_ver);
        return -1;
    }

    const cJSON *dp_ver =  cJSON_GetObjectItem(ota_config, "depend_version");
    if(!dp_ver) {
        log_err("failed to get the config's depend_version info!!");
        cJSON_Delete(root);
       // cJSON_Delete(ota_config);
        //cJSON_Delete(manufacturer);
        //cJSON_Delete(hw_ver);
        //cJSON_Delete(sw_ver);
        return -1;
    }

    g_update.ota_info.manufacturer = strdup(manufacturer->valuestring);
    g_update.ota_info.hw_version = strdup(hw_ver->valuestring);
    g_update.ota_info.sw_version = strdup(sw_ver->valuestring);
    g_update.ota_info.current_ver = strdup(ota_ver->valuestring);
    g_update.ota_info.depend_version = strdup(dp_ver->valuestring);

    cJSON_Delete(root);
    
    //check version
    if(strcmp(g_update.ota_info.manufacturer, g_update.dev_info.manufacturer) != 0) {
        log_err("ota package's manufacturer error!!! %s != %s!",g_update.ota_info.manufacturer, g_update.dev_info.manufacturer);
        g_update.ver_valid = 0;
        return -1;
    }
    if(!strstr(g_update.ota_info.hw_version, g_update.dev_info.hw_version)) {
        log_err("ota packages not support current hareware version %s !", g_update.dev_info.hw_version);
        g_update.ver_valid = 0;
        return -1;
    }
    
    if(!strstr(g_update.ota_info.depend_version, g_update.cur_ota_ver)) {
        log_err("ota packages not support current software version %s !", g_update.cur_ota_ver);
        g_update.ver_valid = 0;
        return -1;
    }
    g_update.ver_valid = 1;
    log_info("ota package dependment check is done!!! update version %s!", g_update.ota_info.current_ver);

    return 0;
}
int call_ota_update(ota_package_st * package)
{
    char cmd[FILENAME_MAX + 1] = { 0 };
    char cmd_ret[1024] = { 0 };
    if(!package || !package->ota_update) {
        log_err("update.sh is not exit!!!");
        return -1;
    }
    sprintf(cmd, "%s", package->ota_update);
    log_info("call update shell %s !!!\n", cmd);
    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }
    return 0;
}
int call_ota_rollback(ota_package_st * package)
{
    char cmd[FILENAME_MAX + 1] = { 0 };
    char cmd_ret[1024] = { 0 };
    if(!package || !package->ota_rollback) {
        log_err("update.sh is not exit!!!");
        return -1;
    }
    sprintf(cmd, "%s", package->ota_rollback);

    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }
    return 0;
}
int call_ota_update_done(ota_package_st * package)
{
    char cmd[FILENAME_MAX + 1] = { 0 };
    char cmd_ret[1024] = { 0 };
    if(!package || !package->ota_update_done) {
        log_err("update.sh is not exit!!!");
        return -1;
    }
    sprintf(cmd, "%s", package->ota_update_done);

    cmd_ret[0] = '\0';
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }
    return 0;
}

cJSON *ota_load_json(const char *file_path)
{
    cJSON *root = NULL;

    FILE *fh_json = fopen(file_path, "r");
    if (fh_json) {
        fseek(fh_json, 0, SEEK_END);
        ssize_t file_size = ftell(fh_json);
        if (file_size <= 0) {
            fclose(fh_json);
            return NULL;
        }

        char *buff = (char *) malloc(file_size);
        if (NULL == buff) {
            fclose(fh_json);
            return NULL;
        }
        fseek(fh_json,0L,SEEK_SET); 
        if (1 == fread(buff, file_size, 1, fh_json)) {
            root = cJSON_Parse(buff);
        }
        free(buff);
        fclose(fh_json);
    }

    return root;
}

int load_ota_state_after_reboot(oat_state_et state)
{
    int ret = 0;
    char filePath[FILENAME_MAX + 1] = { 0 };
    char ota_store[FILENAME_MAX + 1] = { 0 };
    int fd = -1;
    switch(state) {
        case OTA_STATE_DOWNLOADING:
        //在下载过程中，造成异常重启，将状态置为IDLE，重新上报状态，然后下载
        ret = set_ota_state(OTA_STATE_IDLE);
        break;
        case OTA_STATE_VERIFIING:
        //在下OTA验证过程中，造成异常重启，判断OTA包存在，重新进行验证
        ret = get_realpath_by_exec_dir(filePath, NULL);
        if(ret < 0 ) {
            log_err("failed to get project root!!!\n");
            exit(-1);
        }
        strcat(filePath , "ota.tar.gz");
        g_update.ota_package.ota_file_path = strdup(filePath);
        if(access(g_update.ota_package.ota_file_path, F_OK) < 0) {
            free((void*)g_update.ota_package.ota_file_path);
            g_update.ota_package.ota_file_path = NULL;
            ret = set_ota_state(OTA_STATE_IDLE);
        }
        break;
        //如果在writing的过程中重启了，进行异常恢复
        case OTA_STATE_WRITTING:
        case OTA_STATE_CHECKING:
        case OTA_STATE_DONE:
        //在下OTA通过验证，在写入文件系统过程中发生了掉电或者重启：恢复三个脚本 && 当前OTA版本信息
        ret = get_realpath_by_exec_dir(filePath, NULL);
        if(ret < 0 ) {
            log_err("failed to get project root!!!\n");
            exit(-1);
        }
        strcat(filePath , "ota.tar.gz");
        g_update.ota_package.ota_file_path = strdup(filePath);
        if(access(g_update.ota_package.ota_file_path, F_OK) < 0) {
            free((void *)g_update.ota_package.ota_file_path);
            g_update.ota_package.ota_file_path = NULL;
            ret = set_ota_state(OTA_STATE_IDLE);
            break;
        }
        
        sprintf(filePath, "/%s", state_string[state]);
        fd = open(filePath, O_RDWR );
        if(fd < 0) {
            log_err("open state file:%s error! ", filePath);
            ret = set_ota_state(OTA_STATE_IDLE);
            break;
        }
        lseek(fd, 0 , SEEK_SET);

        if(read(fd, ota_store, FILENAME_MAX) < 0) {
            log_warn("read OTA path from state file:%s falied! using default one!", filePath);
            sprintf(ota_store, "%s", OTA_STORE_DIR);
        }
        close(fd);
        
        sprintf(filePath, "%s%s", ota_store, OTA_UPDATE_SHELL);
        if(access(filePath, F_OK) < 0) {
            log_err("update.sh not exit in OTA packages %s,", filePath);
            free((void *)g_update.ota_package.ota_file_path);
            g_update.ota_package.ota_file_path = NULL;
            ret = set_ota_state(OTA_STATE_IDLE);
            break;
        }
        g_update.ota_package.ota_update = strdup(filePath);

        sprintf(filePath, "%s%s", ota_store, OTA_UPDATE_ROLLBACK_SHELL);

        if(access(filePath, F_OK) < 0) {
            log_err("update_rollback.sh not exit in OTA packages");
            free((void *)g_update.ota_package.ota_file_path);
            g_update.ota_package.ota_file_path = NULL;
            free((void *)g_update.ota_package.ota_update);
            g_update.ota_package.ota_update = NULL;
            ret = set_ota_state(OTA_STATE_IDLE);
            break;
        }
        g_update.ota_package.ota_rollback = strdup(filePath);

        sprintf(filePath, "%s%s", ota_store, OTA_UPDATE_DONE_SHELL);
        if(access(filePath, F_OK) < 0) {
            log_err("update_done.sh not exit in OTA packages");
            free((void *)g_update.ota_package.ota_file_path);
            g_update.ota_package.ota_file_path = NULL;
            free((void *)g_update.ota_package.ota_update);
            g_update.ota_package.ota_update = NULL;
            free((void *)g_update.ota_package.ota_rollback);
            g_update.ota_package.ota_rollback = NULL;
            ret = set_ota_state(OTA_STATE_IDLE);
            break;
        }
        g_update.ota_package.ota_update_done = strdup(filePath);

        sprintf(filePath, "%s%s", ota_store, OTA_UPDATE_INFO);

        if(access(filePath, F_OK | R_OK) < 0) {
            log_err("update info json not exit in OTA packages");
            free((void *)g_update.ota_package.ota_file_path);
            g_update.ota_package.ota_file_path = NULL;
            free((void *)g_update.ota_package.ota_update);
            g_update.ota_package.ota_update = NULL;
            free((void *)g_update.ota_package.ota_rollback);
            g_update.ota_package.ota_rollback = NULL;
            free((void *)g_update.ota_package.ota_update_done);
            g_update.ota_package.ota_update_done = NULL;
            ret = set_ota_state(OTA_STATE_IDLE);
            break;
        }
        g_update.ota_package.ota_info_path = strdup(filePath);
 
        g_update.is_ota_file_checked = 1;
        g_update.sign_valid = 1;
        g_update.sh_valid = 1;

        ret = check_ota_dependment(&g_update.ota_package);
        if(ret < 0)
        {
            log_err("check_ota_dependment failed!!!\n");
        }
        break;
        default :
            ret = set_ota_state(OTA_STATE_IDLE);
        break;
    }
    return ret;
}