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

#include "sysconfig.h"
#include "mqtt_global.h"

#define CONFIG_MAGIC_STR        "ota.ver"

typedef struct device_config {
    char magic[16];
    char ota_version[96];
} device_config_t;

//device_config_t main_config;

#ifndef IOTX_CONFIG_PATH

#ifdef ENABLE_ADVANCED_OTA
#define IOTX_CONFIG_PATH         "/"
#else
#define IOTX_CONFIG_PATH         "./"
#endif

#endif

#ifndef GATEWAY_BASE_VERSION 
#define GATEWAY_BASE_VERSION "2.4.0"
#endif

#define IOTX_CONFIG_FILE_NAME    ".sysconfig.db"

device_config_t main_config;

static int init = 0;


static int config_write(void);
static int config_read(void);
static void config_dump(void);
static int config_update(void);
static int config_reset(void);

int config_write(void)
{
    FILE *fp;
    char filepath[128] = {0};
    char value[128] = {0};

    snprintf(filepath, sizeof(filepath), "%s%s", IOTX_CONFIG_PATH, IOTX_CONFIG_FILE_NAME);
    fp = fopen(filepath, "w");
    if (!fp)
        return -1;

    snprintf(value, sizeof(value), "%s:%s", main_config.magic, main_config.ota_version); 
    fputs(value, fp);

    fclose(fp);

    return 0;
}

int config_read(void)
{
    FILE *fp;
    char filepath[128] = {0};
    int ret = 0;

    snprintf(filepath, sizeof(filepath), "%s%s", IOTX_CONFIG_PATH, IOTX_CONFIG_FILE_NAME);
    fp = fopen(filepath, "r");
    if (!fp)
        return -1;

    memset(&main_config, 0x0, sizeof(main_config));
    ret = fscanf(fp, "%[^:]:%[^:]", main_config.magic, main_config.ota_version);
    if (-1 == ret) {
        log_err("read end\n");
    }
    log_info("magic:%s, ver:%s, ret:%d\n", main_config.magic, main_config.ota_version, ret);

    fclose(fp);

    return ret;
}

void config_dump(void)
{
	log_info("~~~~~dump sys config~~~~~\n");
	log_info("magic: %s\n", main_config.magic);
	log_info("OTA version: %s\n", main_config.ota_version);
	log_info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

int ota_config_init(void)
{
	int ret = 0;

	if (!init) {
		memset(&main_config, 0, sizeof(main_config));
		if ((-1 != config_read()) && !strncmp(main_config.magic, CONFIG_MAGIC_STR, strlen(CONFIG_MAGIC_STR)) 
    		&& (strlen(main_config.ota_version) > 0)) {
			log_info("config init ok\n");
		} else {
			log_err("config init fail, reset...\n");
			ret = config_reset();
		}

		config_dump();
		init = 0xff;
	}

	return ret;
}

void ota_config_exit(void)
{
	init = 0;
}

int config_update(void)
{
	return config_write();
}

int config_reset(void)
{
	memset(&main_config, 0, sizeof(main_config));

	strcpy(main_config.magic, CONFIG_MAGIC_STR);
	strcpy(main_config.ota_version, GATEWAY_BASE_VERSION);
	return config_update();
}

char *config_get_ota_version(void)
{
	if (!init)
		ota_config_init();
	return main_config.ota_version;
}

int config_set_ota_version(char *buffer)
{
    if (!buffer)
        return -1;

	if (!init)
		ota_config_init();

	memset(main_config.ota_version, 0, sizeof(main_config.ota_version));
	strncpy(main_config.ota_version, buffer, sizeof(main_config.ota_version) - 1);

	return config_update();
}


