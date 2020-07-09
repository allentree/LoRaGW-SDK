/*
 * Copyright (c) 2014-2017 Alibaba Group. All rights reserved.
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
#include <stdlib.h>     /* qsort_r */
#include <stdio.h>      /* printf, fprintf, snprintf, fopen, fputs */
#include <string.h>     /* memset, memcpy */
#include "gwiotapi.h"
#include "parson.h"
#include "aes.h"


#define GW_AUTH_KEY_FILE        "auth_key.json"
#define GW_DEV_INFO_FILE        "dev_info.json"
#define GW_GLOBAL_CONF_FILE     "global_conf.json"
#define GW_LOCAL_CONF_FILE      "local_conf.json"

static int aes_decrypt_key(char *in, char *out)
{
    char input[512] = {0};
    /* 此为默认加解密key，请厂商自己更换，厂商适配时key初始化建议不要直接使用key字符串来定义，避免key被反编译获取到 */
    char key[32] = "IWf8d2vXAfuyORMJ";
    struct AES_ctx ctx;
    int i = 0;
    int size = 0;

    if ((in == NULL) || (out == NULL) || (strlen(in) <= 0)) {
        printf("param is invalid");
        return -1;
    }

    if ((strlen(in) % 16) != 0) {
        printf("input data is invalid");
        return -1;
    }

    //printf("key: %s\n", key);

    size = strlen(in) / 2;
    memset(input, 0, sizeof(input));
    for (i = 0; i < strlen(in); i = i + 2) {
        sscanf(in + i, "%02hhx", &input[i/2]);
    }

    //printf("size: %d, in: %s\n", size, in);

    #if 0
    printf("size: %d, input data: ", size);
    for(i = 0; i < size; i++)
    {
        printf("%02x", input[i]);
    }
    printf("\n");
    #endif

    AES_init_ctx(&ctx, (uint8_t *)key);
    for(i = 0; i < size / 16; i++) {
        AES_ECB_decrypt(&ctx, (uint8_t *)(input + 16 * i));
    }

    #if 0
    printf("size: %d, out data: ", size);
    for(i = 0; i < size; i++)
    {
        printf("%02x", input[i]);
    }
    printf("\n");
    #endif

    memcpy(out, input, size);
    //printf("decrypt, size: %d, out: %s\n", size, out);

    return 0;
}

/**
 * @brief get authenticate info of gateway.
*
* @param[out] authinfo is a pointer to the #gw_auth_info_t.
* @return  0 success, -1 failed.
* @see None.
 * @note None.
 */
int aliot_gw_get_auth_info(aliot_gw_auth_info_t *authinfo)
{
    const char conf_obj_name[] = "auth_key";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    const char *str = NULL;
    char out[512] = {0};

    root_val = json_parse_file_with_comments(GW_AUTH_KEY_FILE);
    if (root_val == NULL) {
        printf("%s not a valid JSON file\n", GW_AUTH_KEY_FILE);
        return -1;
    }

    conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
    if (conf_obj == NULL) {
        printf("not contain a JSON object named %s\n", conf_obj_name);
        json_value_free(root_val);
        return -1;
    }

    memset(authinfo, 0x0, sizeof(aliot_gw_auth_info_t));
    str = json_object_get_string(conf_obj, "product_key");
    if (str != NULL) {
        memset(out, 0x0, sizeof(out));
        aes_decrypt_key((char *)str, out);
        strncpy(authinfo->product_key, out, STR_PRODUCT_KEY_LEN);
        //printf("product_key: %s\n", authinfo->product_key);
    }

    str = json_object_get_string(conf_obj, "device_name");
    if (str != NULL) {
        memset(out, 0x0, sizeof(out));
        aes_decrypt_key((char *)str, out);
        strncpy(authinfo->device_name, out, STR_DEVICE_NAME_LEN);
        //printf("device_name: %s\n", authinfo->device_name);
    }

    str = json_object_get_string(conf_obj, "device_secret");
    if (str != NULL) {
        memset(out, 0x0, sizeof(out));
        aes_decrypt_key((char *)str, out);
        strncpy(authinfo->device_secret, out, STR_DEVICE_SECRET_LEN);
        //printf("device_secret: %s\n", authinfo->device_secret);
    }
    
    strncpy(authinfo->device_id, authinfo->device_name, STR_DEVICE_ID_LEN);
    //printf("device_id: %s\n", authinfo->device_id);

    json_value_free(root_val);
    return 0;
}

/**
 * @brief get device info of gateway.
*
* @param[out] devinfo is a pointer to the #gw_device_info_t.
* @return  0 success, -1 failed.
* @see None.
 * @note None.
 */
int aliot_gw_get_device_info(aliot_gw_device_info_t *devinfo)
{
    const char conf_obj_name[] = "gateway_conf";
    const char info_obj_name[] = "dev_info";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    const char *str = NULL;

    root_val = json_parse_file_with_comments(GW_LOCAL_CONF_FILE);
    if (root_val == NULL) {
        printf("%s not a valid JSON file\n", GW_LOCAL_CONF_FILE);
        return -1;
    }

    conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
    if (conf_obj == NULL) {
        printf("not contain a JSON object named %s\n", conf_obj_name);
        json_value_free(root_val);
        return -1;
    }

    memset(devinfo, 0x0, sizeof(aliot_gw_device_info_t));
    str = json_object_get_string(conf_obj, "gateway_ID");
    if (str != NULL) {
        strncpy(devinfo->gateway_eui, str, STR_GWEUI_LEN);
        //printf("gateway_eui: %s\n", devinfo->gateway_eui);
    }

    json_value_free(root_val);

    root_val = json_parse_file_with_comments(GW_DEV_INFO_FILE);
    if (root_val == NULL) {
        printf("%s not a valid JSON file\n", GW_DEV_INFO_FILE);
        return -1;
    }

    conf_obj = json_object_get_object(json_value_get_object(root_val), info_obj_name);
    if (conf_obj == NULL) {
        printf("not contain a JSON object named %s\n", info_obj_name);
        json_value_free(root_val);
        return -1;
    }

    str = json_object_get_string(conf_obj, "gw_model");
    if (str != NULL) {
        strncpy(devinfo->model, str, STR_MODEL_LEN);
        //printf("model: %s\n", devinfo->model);
    }

    str = json_object_get_string(conf_obj, "gw_manuf");
    if (str != NULL) {
        strncpy(devinfo->manufacturer, str, STR_NAME_LEN);
        //printf("manufacturer: %s\n", devinfo->manufacturer);
    }

    str = json_object_get_string(conf_obj, "hw_ver");
    if (str != NULL) {
        strncpy(devinfo->hw_version, str, STR_NAME_LEN);
        //printf("hw_version: %s\n", devinfo->hw_version);
    }

    str = json_object_get_string(conf_obj, "sw_ver");
    if (str != NULL) {
        strncpy(devinfo->sw_version, str, STR_NAME_LEN);
        //printf("sw_version: %s\n", devinfo->sw_version);
    }

    json_value_free(root_val);
    return 0;

}

/**
 * @brief get udp uplink port for receive GWMP message.
*
* @param[] None.
* @return udp uplink port.
* @see None.
 * @note None.
 */
uint16_t aliot_gw_get_udp_port_up(void)
{
    const char conf_obj_name[] = "gateway_conf";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    JSON_Value *val = NULL;
    uint16_t udp_port_up = 8888;

    root_val = json_parse_file_with_comments(GW_GLOBAL_CONF_FILE);
    if (root_val != NULL) {
        conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
        if (conf_obj != NULL) {
            val = json_object_get_value(conf_obj, "serv_port_up");
            if (val != NULL) {
                udp_port_up = (uint16_t)json_value_get_number(val);
                //printf("serv_port_up: %d\n", udp_port_up);
            }
        }
        json_value_free(root_val);
    }

    //printf("udp_port_up: %d\n", udp_port_up);
    return udp_port_up;
}

/**
 * @brief get udp downlink port for send GWMP message.
*
* @param[] None.
* @return udp downlink port.
* @see None.
 * @note None.
 */
uint16_t aliot_gw_get_udp_port_down(void)
{
    const char conf_obj_name[] = "gateway_conf";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    JSON_Value *val = NULL;
    uint16_t udp_port_down = 9999;

    root_val = json_parse_file_with_comments(GW_GLOBAL_CONF_FILE);
    if (root_val != NULL) {
        conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
        if (conf_obj != NULL) {
            val = json_object_get_value(conf_obj, "serv_port_down");
            if (val != NULL) {
                udp_port_down = (uint16_t)json_value_get_number(val);
                //printf("serv_port_down: %d\n", udp_port_down);
            }
        }
        json_value_free(root_val);
    }

    //printf("udp_port_down: %d\n", udp_port_down);
    return udp_port_down;
}

/**
 * @brief update gateway config data.
*
* @param[in] buffer is the gateway config data buffer.
* @param[in] length is the gateway config data len.
* @return  0 success, -1 failed.
* @see None.
 * @note None.
 */
int aliot_gw_update_global_conf(uint8_t *buffer, uint32_t length)
{
    const char conf_obj_name[] = "gateway_conf";
    const char rf_obj_name[] = "SX1301_conf";
    JSON_Value *root_val = NULL;
    JSON_Object *conf_obj = NULL;
    FILE *fp = NULL;
    uint32_t written_len = 0;

    if ((NULL == buffer) || (0 == length)) {
        printf("param invalid\n");
        return -1;
    }

    root_val = json_parse_string_with_comments((const char *)buffer);
    if (root_val == NULL) {
        printf("invalid JSON file");
        return -1;
    }

    conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
    if (conf_obj == NULL) {
        printf("not contain a JSON object named %s\n", conf_obj_name);
        json_value_free(root_val);
        return -1;
    }

    conf_obj = json_object_get_object(json_value_get_object(root_val), rf_obj_name);
    if (conf_obj == NULL) {
        printf("not contain a JSON object named %s\n", rf_obj_name);
        json_value_free(root_val);
        return -1;
    }

    fp = fopen(GW_GLOBAL_CONF_FILE, "wb");
    if (NULL == fp) {
        printf("fopen %s failed\n", GW_GLOBAL_CONF_FILE);
        json_value_free(root_val);
        return -1;
    }

    written_len = fwrite(buffer, 1, length, fp);
    if (written_len != length) {
        printf("fwrite failed, %d != %d\n", written_len, length);
        fclose(fp);
        json_value_free(root_val);
        return -1;
    }

    fclose(fp);
    fp = NULL;

    return 0;
}

/**
 * @brief get gateway config data.
*
* @param[out] buffer is for return the gateway config data.
* @param[in] buf_size is buffer max size.
* @return  the gateway config data length success, 0 failed.
* @see None.
* @note None.
*/
uint32_t aliot_gw_get_global_conf(uint8_t *buffer, uint32_t buf_size)
{
    FILE *fp = NULL;
    uint32_t file_len = 0;

    if ((NULL == buffer) || (0 == buf_size)) {
        printf("param invalid\n");
        return 0;
    }

    fp = fopen(GW_GLOBAL_CONF_FILE, "rb");
    if (NULL == fp) {
        printf("fopen %s failed\n", GW_GLOBAL_CONF_FILE);
        return 0;
    }

    file_len = fread(buffer, 1, buf_size, fp); 
    if (0 == file_len) {
        printf("fread global_conf.json failed\n");
        fclose(fp);
        return 0;
    }

    fclose(fp);
    fp = NULL;

    return file_len;
}

/**
 * @brief reset gateway.
*
* @param[] None.
* @return  0 success, -1 failed.
* @see None.
 * @note None.
 */
int aliot_gw_reset(void)
{
	system("reboot");
    return 0;
}
#ifndef ENABLE_ADVANCED_OTA
static FILE *ota_fp = NULL;

/**
 * @brief Initialize a OTA upgrade.
 *
 * @param None
 * @return 0, success; -1, failure.
 * @see None.
 * @note None.
 */
int aliot_platform_ota_start(const char *md5)
{
    ota_fp = fopen("/tmp/lora_ota.tar.gz", "wb");
    if (NULL == ota_fp) {
        printf("fopen OTA file failed\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Write OTA data.
 *
 * @param [in] buffer: @n A pointer to a buffer to save data.
 * @param [in] length: @n The length, in bytes, of the data pointed to by the buffer parameter.
 * @return 0, success; -1, failure.
 * @see None.
 * @note None.
 */
int aliot_platform_ota_write(char *buffer, uint32_t length)
{
    uint32_t written_len = 0;

    if (NULL == ota_fp) {
        printf("OTA file not fopen\n");
        return -1;
    }

    written_len = fwrite(buffer, 1, length, ota_fp);

    if (written_len != length) {
        printf("fwrite failed, %d != %d\n", written_len, length);
        return -1;
    }
    return 0;
}

/**
 * @brief indicate OTA complete.
 *
 * @param [in] stat: 0, normal termination; -1, abnormal termination (error occur).
 * @return 0: suuccess; -1: failure.
 * @see None.
 * @note None.
 */
int aliot_platform_ota_finalize(int stat)
{
    if (ota_fp != NULL) {
        fclose(ota_fp);
        ota_fp = NULL;
    }

    if (0 == stat) {
        printf("tar lora_ota.tar.gz and run ota.sh\n");

        system("rm /tmp/lora_ota/* -rf");
        system("mkdir -p /tmp/lora_ota");
        system("chmod 755 /tmp/lora_ota");
        system("tar zxf /tmp/lora_ota.tar.gz -C /tmp/lora_ota");
        system("chmod 755 /tmp/lora_ota/ota.sh");
        system("/tmp/lora_ota/ota.sh");
    }

    return 0;
}
#endif
/**
* @brief enable/disable ssh service.
*
* @param [in] enable: 1, enable ssh service; 0, disable ssh service.
* @return 0: suuccess; -1: failure.
* @see None.
* @note None.
*/
/*this example code is base on dropbear */
int aliot_platform_ssh_enable(int enable)
{
    if(enable > 1 || enable < 0) {
        return -1;
    }
    if(enable) {
        system("/usr/sbin/dropbear &");
    }
    else {
        system("killall dropbear");
    }
    return 0;
}

/**
* @brief enable/disable UART console.
*
* @param [in] enable: 1, enable UART console; 0, disable UART console.
* @return 0: suuccess; -1: failure.
* @see None.
* @note None.
*/
#include <termios.h>
#include <fcntl.h>
/*you can replace with your uart device*/
#define TTY_DEV "/dev/ttymxc0"
int aliot_platform_uart_enable(int enable)
{
    int fd = -1;
    int ret = -1;
    if(enable > 1 || enable < 0) {
        return -1;
    }
    fd = open(TTY_DEV, O_RDWR);
    if(fd < 0 ) {
        printf("open %s error!\n", TTY_DEV);
        return -1;
    }
    if(enable) {
        ret = tcflow(fd, TCOON);
        if( ret < 0) {
            printf("set %s on failed!!!\n", TTY_DEV);
        }
    }
    else {
        ret = tcflow(fd, TCOOFF);
        if( ret < 0) {
            printf("set %s off failed!!!\n", TTY_DEV);
        }
    }
    close(fd);

    return (ret < 0)? -1 : 0;
}

