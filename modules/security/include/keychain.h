#ifndef _KEYCHAIN_H_
#define _KEYCHAIN_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KC_SUCCESS                       0x00000000
#define KC_ERROR_GENERIC                 0xffff0001
#define KC_ERROR_ACCESS_DENIED           0xffff0002
#define KC_ERROR_ITEM_NOT_FOUND          0xffff0003
#define KC_ERROR_BAD_PARAMETERS          0xffff0004
#define KC_ERROR_OUT_OF_MEMORY           0xffff0005
#define KC_ERROR_STORAGE_NO_SPACE        0xffff0006
#define KC_ERROR_STORAGE_NOT_AVAILABLE   0xffff0007
#define KC_ERROR_BUSY                    0xffff0008
#define KC_ERROR_OVERFLOW                0xffff0009
#define KC_ERROR_SHORT_BUFFER            0xffff000A

#define MAX_DOMAIN_NAME_LEN 256

typedef enum _kc_key_type_t {
    KEY_CHAIN_PASSWORD,
    KEY_CHAIN_KEY,
    KEY_CHAIN_CERT,
    KEY_CHAIN_USERDATA,
} kc_key_type_t;

typedef enum _kc_group_perm_t {
    KC_READ = 1,
    KC_WRITE = 2,
} kc_group_perm_t;

uint32_t kc_init();
void kc_destroy();



/**
 * @brief add new item to keychain (global)
 *
 * @param[in] key_name: the item name, the length must be no more than 256 Bytes
 * @param[in] key_sec: the item value
 * @param[in] key_sec_len: the length of itme value
 * @param[in] key_type: the type of item
 * @return: 0~OK, other~ERROR.
 * @note None.
 */
uint32_t kc_add_global_item(const char *key_name, const uint8_t *key_sec, uint32_t key_sec_len, kc_key_type_t key_type);
/**
 * @brief get item from keychain (global)
 *
 * @param[in] key_name: the item name, the length must be no more than 256 Bytes
 * @param[out] key_sec: the item value
 * @param[in_out] key_sec_len: length of itme value
 * @param[out] key_type: the type of item
 * @return: 0~OK, other~ERROR.
 * @note None.
 */
uint32_t kc_get_global_item(const char *key_name, const uint8_t *key_sec, uint32_t *key_sec_len, kc_key_type_t *key_type);

uint32_t kc_delete_global_item(const char *key_name);
/**
 * @brief add new item to keychain (process domain)
 *
 * @param[in] key_name: the item name, the length must be no more than 256 Bytes
 * @param[in] key_sec: the item value
 * @param[in] key_sec_len: the length of itme value
 * @param[in] key_type: the type of item
 * @return: 0~OK, other~ERROR.
 * @note None.
 */
uint32_t kc_add_item(const char *key_name, const uint8_t *key_sec, uint32_t key_sec_len, kc_key_type_t key_type);

/**
 * @brief get item from keychain (process domain)
 *
 * @param[in] key_name: the item name, the length must be no more than 256 Bytes
 * @param[out] key_sec: the item value
 * @param[in_out] key_sec_len: length of itme value
 * @param[out] key_type: the type of item
 * @return: 0~OK, other~ERROR.
 * @note None.
 */
uint32_t kc_get_item(const char *key_name, uint8_t *key_sec, uint32_t *key_sec_len, kc_key_type_t *key_type);

/**
 * @brief update item in keychain
 *
 * @param[in] key_name: the item name, the length must be no more than 256 Bytes
 * @param[in] key_sec: the item value
 * @param[in] key_sec_len: length of itme value
 * @return: 0~OK, other~ERROR.
 * @note None.
 */
uint32_t kc_update_item(const char *key_name, const uint8_t *key_sec, uint32_t key_sec_len);

/**
 * @brief delete item in keychain
 *
 * @param[in] key_name: the item name, the length must be no more than 256 Bytes
 * @return: 0~OK, other~ERROR.
 * @note None.
 */
uint32_t kc_delete_item(const char *key_name);

/*
 * @data migration used to encrypt data and store encrypted data in file
 * @param[in] data: the data to be encrypted
 * @param[in] data_len: the length of the data to be encrypted
 * @param[in] file_path: the file to store the encrypted data
 * @param[out] key: the key which is used to encrypt the data
 * @param[in_out] key_len: the length of the key
 * @return: 0~OK, other~ERROR.
 * */
uint32_t kc_encrypt_data(const uint8_t *data, uint32_t data_len, const char *file_path, uint8_t *key, uint32_t *key_len);
/*
 * @data migration used to decrypt data stored in file
 * @param[in] file_path: the file to store the encrypted data
 * @param[in] key: the key which is used to decrypt the data
 * @param[in] key_len: the length of the key
 * @param[out] data: the decrypted data
 * @param[in_out] data_len: the length of the decrypted data
 * @return: 0~OK, other~ERROR.
 * */
uint32_t kc_decrypt_data(const char *file_path, uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t *data_len);

/*
 * @set the domain name of the process, cannot be changed during the life cycle of a process
 * @param[in] domain_name, the domain name of the process
 * @return: 0~OK, other~ERROR.
 * */
uint32_t kc_set_proc_domain_name(const char *domain_name);

//not support yet
uint32_t kc_create_group(const char *group_name);
uint32_t kc_add_group_number(const char *group_name, const char *proc, kc_group_perm_t flag);
uint32_t kc_remove_group_number(const char *group_name, const char *proc);
uint32_t kc_add_group_item(const char *group_name, const char *key_name,
        const uint8_t *key_sec, uint32_t key_sec_len, kc_key_type_t key_type);
uint32_t kc_get_group_item(const char *group_name, const char *key_name,
        uint8_t *key_sec, uint32_t *key_sec_len, kc_key_type_t *key_type);
//local migration
uint32_t kc_mig_get_file(uint8_t *key, uint32_t *key_len);
uint32_t kc_mig_store_file(uint8_t *key, uint32_t key_len);
//online migration
uint32_t kc_backup();
uint32_t kc_recovery();
uint32_t kc_mig_id(uint32_t *new_id, uint32_t id_len);
uint32_t kc_mig_recovery(uint8_t *orig_id, uint32_t id_len);
#ifdef __cplusplus
}
#endif

#endif /* _KEYCHAIN_H_ */
