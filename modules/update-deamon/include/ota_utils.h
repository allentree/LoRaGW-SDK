#ifndef _OTA_UTILS_H
#define _OTA_UTILS_H
#include "update_global.h"
#include <stdio.h>

int get_ota_state(oat_state_et * state);
int set_ota_state(oat_state_et state);

int unpackage_ota_package(ota_package_st * package);
int check_ota_package_files(ota_package_st * package);

int check_ota_dependment(ota_package_st * package);

int call_ota_update(ota_package_st * package);
int call_ota_rollback(ota_package_st * package);
int call_ota_update_done(ota_package_st * package);

int get_realpath_by_exec_dir(char* real_dir, const char* offset_to_exec);

int load_ota_state_after_reboot(oat_state_et state);

int parse_ota_files_from_jcson(ota_package_st * package);

int ota_exe_cmd(const char *cmd, char *result, int max_len);
#endif