#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "utils.h"

int main() {
    int32_t ret = 0;
    char *km_sig_file;
    char *km_bak_sig_file;

    km_sig_file = get_sec_sys_sig_name();
    km_bak_sig_file = get_sec_sys_bak_sig_name();

    if (check_file_same(km_sig_file, km_bak_sig_file) == 0) {
        printf("check file same ok\n");
    }

    return ret;
}
