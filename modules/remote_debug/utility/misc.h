#ifndef __MISC_H__
#define __MISC_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
//#include <error.h>
#include <signal.h>

#define MAX_VAL(v1,v2)  ((v1) > (v2) ? (v1) : (v2))

int get_dev_ip(char *buf, int size);

void dump_hex(char *p , int len);

#endif

