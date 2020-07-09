/*
 * Copyright (c) 2014-2015 Alibaba Group. All rights reserved.
 *
 * Alibaba Group retains all right, title and interest (including all
 * intellectual property rights) in and to this computer program, which is
 * protected by applicable intellectual property laws.  Unless you have
 * obtained a separate written license from Alibaba Group., you are not
 * authorized to utilize all or a part of this computer program for any
 * purpose (including reproduction, distribution, modification, and
 * compilation into object code), and you must immediately destroy or
 * return to Alibaba Group all copies of this computer program.  If you
 * are licensed by Alibaba Group, your rights to utilize this computer
 * program are limited by the terms of that license.  To obtain a license,
 * please contact Alibaba Group.
 *
 * This computer program contains trade secrets owned by Alibaba Group.
 * and, unless unauthorized by Alibaba Group in writing, you agree to
 * maintain the confidentiality of this computer program and related
 * information and to not disclose this computer program and related
 * information to any other person or entity.
 *
 * THIS COMPUTER PROGRAM IS PROVIDED AS IS WITHOUT ANY WARRANTIES, AND
 * Alibaba Group EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
 * INCLUDING THE WARRANTIES OF MERCHANTIBILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, TITLE, AND NONINFRINGEMENT.
 */
#ifndef _ABP_NODES_H_
#define _ABP_NODES_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "misc/utils_httpc.h"

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

#define ENABLE_ABP_NODES

#define ABP_NODES_NUM_MAX      2048

#define ABP_MSGID_UP           0x85
#define ABP_MSGID_DOWN         0x86

typedef struct {
    const char *url;
    httpclient_t http;
    httpclient_data_t http_data;
} file_http_t, *file_http_pt;

typedef struct {
    uint64_t devaddr;
    uint64_t deveui;
    uint32_t fcntup;
    uint32_t nfcntdown;
    uint32_t afcntdown;
    uint32_t conffcnt;
    char mode[9];
    char version[9];
    char nwkskey[129];
    char appskey[129];
} abp_node_t, *abp_node_pt;

typedef struct {
    uint32_t num;
    abp_node_t nodes[ABP_NODES_NUM_MAX];
} abp_list_t, *abp_list_pt;


int abp_key_init(void);
int abp_redis_init(void);
int abp_file_conf(const char *msg_buf, uint16_t msg_len);
int abp_file_download (void);
int abp_send_msg_ack(char *error_str);

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif

#endif

