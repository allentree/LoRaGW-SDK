#ifndef __ALIBABA_LORAWAN_
#define __ALIBABA_LORAWAN_

#include <stdint.h>         /* C99 types */

#ifdef __cplusplus
extern "C"
{
#endif

#define STR_PRODUCT_KEY_LEN   (11)
#define STR_DEVICE_NAME_LEN   (32)
#define STR_DEVICE_ID_LEN     (20)
#define STR_DEVICE_SECRET_LEN (32)
typedef struct {
    char product_key[STR_PRODUCT_KEY_LEN + 1];
    char device_name[STR_DEVICE_NAME_LEN + 1];
    char device_id[STR_DEVICE_ID_LEN + 1];
    char device_secret[STR_DEVICE_SECRET_LEN + 1];
} aliot_gw_auth_info_t;

#define STR_GWEUI_LEN (16)
#define STR_SN_LEN (64)
#define STR_MODEL_LEN (80)
#define STR_NAME_LEN (32)
typedef struct {
    char gateway_eui[STR_GWEUI_LEN + 1];
    char model[STR_MODEL_LEN + 1];
    char manufacturer[STR_NAME_LEN + 1];
    char hw_version[STR_NAME_LEN + 1];
    /* sw_version is the gateway version(format: X.X.X) */
    char sw_version[STR_NAME_LEN + 1];
} aliot_gw_device_info_t;


/**
* @brief get authenticate info of gateway.
*
* @param[out] authinfo is a pointer to the #gw_auth_info_t, the return keys must decrypt.
* @return 0 success, -1 failed.
* @see None.
* @note None.
*/
int aliot_gw_get_auth_info(aliot_gw_auth_info_t *authinfo);

/**
* @brief get device info of gateway.
*
* @param[out] devinfo is a pointer to the #gw_device_info_t.
* @return 0 success, -1 failed.
* @see None.
* @note None.
*/
int aliot_gw_get_device_info(aliot_gw_device_info_t *devinfo);

/**
* @brief get udp uplink port for receive GWMP message.
*
* @param[] None.
* @return udp uplink port.
* @see None.
* @note None.
*/
uint16_t aliot_gw_get_udp_port_up(void);

/**
* @brief get udp downlink port for send GWMP message.
*
* @param[] None.
* @return udp downlink port.
* @see None.
* @note None.
*/
uint16_t aliot_gw_get_udp_port_down(void);

/**
* @brief get gateway config data.
*
* @param[out] buffer is for return the gateway config data.
* @param[in] buf_size is buffer max size.
* @return the gateway config data length success, 0 failed.
* @see None.
* @note None.
*/
uint32_t aliot_gw_get_global_conf(uint8_t* buffer, uint32_t buf_size);

/**
* @brief update gateway config data.
*
* @param[in] buffer is the gateway config data buffer.
* @param[in] length is the gateway config data len.
* @return 0 success, -1 failed.
* @see None.
* @note None.
*/
int aliot_gw_update_global_conf(uint8_t *buffer, uint32_t length);

/**
* @brief reset gateway meaning reboot gateway.
*
* @param[] None.
* @return 0 success, -1 failed.
* @see None.
* @note None.
*/
int aliot_gw_reset(void);

/**
* @brief Initialize a OTA upgrade.
*
* @param None
* @return 0, success; -1, failure.
* @see None.
* @note None.
*/
int aliot_platform_ota_start(const char *md5);

/**
* @brief Write OTA data.
*
* @param [in] buffer: @n A pointer to a buffer to save data.
* @param [in] length: @n The length, in bytes, of the data pointed
to by the buffer parameter.
* @return 0, success; -1, failure.
* @see None.
* @note None.
*/
int aliot_platform_ota_write(char *buffer, uint32_t length);

/**
* @brief indicate OTA complete.
*
* @param [in] stat: 0, normal termination; -1, abnormal termination
(error occur).
* @return 0: suuccess; -1: failure.
* @see None.
* @note None.
*/
int aliot_platform_ota_finalize(int stat);

/**
* @brief enable/disable ssh service.
*
* @param [in] enable: 1, enable ssh service; 0, disable ssh service.
* @return 0: suuccess; -1: failure.
* @see None.
* @note None.
*/
int aliot_platform_ssh_enable(int enable);

/**
* @brief enable/disable UART console.
*
* @param [in] enable: 1, enable UART console; 0, disable UART console.
* @return 0: suuccess; -1: failure.
* @see None.
* @note None.
*/
int aliot_platform_uart_enable(int enable);

#ifdef __cplusplus
}
#endif

#endif

