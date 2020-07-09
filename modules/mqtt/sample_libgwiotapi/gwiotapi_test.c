#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "gwiotapi.h"

#define BUF_LEN_MAX              (8 * 1024)

int main(int argc, char **argv)
{
    uint16_t udp_port = 0;
    int ret = -1;
    uint32_t len = 0;
    aliot_gw_auth_info_t auth_info;
    aliot_gw_device_info_t dev_info;
    uint8_t buffer[BUF_LEN_MAX];

    memset(&auth_info, 0x0, sizeof(aliot_gw_auth_info_t));
    ret = aliot_gw_get_auth_info(&auth_info);
    if (ret == 0) {
        printf("get product_key: %s\n", auth_info.product_key);
        printf("get device_name: %s\n", auth_info.device_name);
        printf("get device_id: %s\n", auth_info.device_id);
        printf("get device_secret: %s\n", auth_info.device_secret);
        printf("aliot_gw_get_auth_info - TEST OK\n");
    } else {
        printf("aliot_gw_get_auth_info - TEST FAIL\n");
    }

    memset(&dev_info, 0x0, sizeof(aliot_gw_device_info_t));
    ret = aliot_gw_get_device_info(&dev_info);
    if (ret == 0) {
        printf("get gateway_eui: %s\n", dev_info.gateway_eui);
        printf("get model: %s\n", dev_info.model);
        printf("get manufacturer: %s\n", dev_info.manufacturer);
        printf("get hw_version: %s\n", dev_info.hw_version);
        printf("get sw_version: %s\n", dev_info.sw_version);
        printf("aliot_gw_get_device_info - TEST OK\n");
    } else {
        printf("aliot_gw_get_device_info - TEST FAIL\n");
    }

    udp_port = aliot_gw_get_udp_port_up();
    if (udp_port > 0) {
        printf("get upd_port_up: %d\n", udp_port);
        printf("aliot_gw_get_udp_port_up - TEST OK\n");
    } else {
        printf("aliot_gw_get_udp_port_up - TEST FAIL\n");
    }

    udp_port = aliot_gw_get_udp_port_down();
    if (udp_port > 0) {
        printf("get upd_port_down: %d\n", udp_port);
        printf("aliot_gw_get_udp_port_down - TEST OK\n");
    } else {
        printf("aliot_gw_get_udp_port_down - TEST FAIL\n");
    }

    memset(buffer, 0x0, BUF_LEN_MAX);
    len = aliot_gw_get_global_conf(buffer, BUF_LEN_MAX - 1);
    if (len > 0) {
        printf("get global_conf.json, len: %d\n", len);
        printf("%s\n", buffer);
        printf("aliot_gw_get_global_conf - TEST OK\n");
    } else {
        printf("aliot_gw_get_global_conf - TEST FAIL\n");
    }

    ret = aliot_gw_update_global_conf(buffer, len);
    if (ret == 0) {
        printf("aliot_gw_update_global_conf - TEST OK\n");
    } else {
        printf("aliot_gw_update_global_conf - TEST FAIL\n");
    }

    #if 0
    ret = aliot_gw_reset();
    if (ret == 0) {
        printf("aliot_gw_reset - TEST OK\n");
    } else {
        printf("aliot_gw_reset - TEST FAIL\n");
    }
    #endif

    #if 0
    ret = aliot_platform_ota_start(NULL);
    if (ret == 0) {
        printf("aliot_platform_ota_start - TEST OK\n");
    } else {
        printf("aliot_platform_ota_start - TEST FAIL\n");
    }

    ret = aliot_platform_ota_write((char *)buffer, len);
    if (ret == 0) {
        printf("aliot_platform_ota_write - TEST OK\n");
    } else {
        printf("aliot_platform_ota_write - TEST FAIL\n");
    }

    ret = aliot_platform_ota_finalize(0);
    if (ret == 0) {
        printf("aliot_platform_ota_finalize - TEST OK\n");
    } else {
        printf("aliot_platform_ota_finalize - TEST FAIL\n");
    }
    #endif
	
    ret = aliot_platform_ssh_enable(1);
    if (ret == 0) {
        printf("aliot_platform_ssh_enable - TEST OK\n");
    } else {
        printf("aliot_platform_ssh_enable - TEST FAIL\n");
    }

    ret = aliot_platform_uart_enable(1);
    if (ret == 0) {
        printf("aliot_platform_uart_enable - TEST OK\n");
    } else {
        printf("aliot_platform_uart_enable - TEST FAIL\n");
    }

    return 0;
}

