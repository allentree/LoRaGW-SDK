#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "utils.h"

int main() {
    printf("wrong file2 name.\n");
    if (copy_file("file1", "file2") != 0) {
        printf("test ok!\n");
    } else {
        printf("test fail!\n");
    }

    printf("mkdir fail.\n");
    if (copy_file("file1", "/usr/test/file2") != 0) {
        printf("test ok!\n");
    } else {
        printf("test fail!\n");
    }

    printf("create file fail.\n");
    if (copy_file("file1", "/usr/file2") != 0) {
        printf("test ok!\n");
    } else {
        printf("test fail!\n");
    }

    printf("open file fail.\n");
    if (copy_file("file1", "~/file2") != 0) {
        printf("test ok!\n");
    } else {
        printf("test fail!\n");
    }
    
    remove("~/file2");
    
    return 0;
}
