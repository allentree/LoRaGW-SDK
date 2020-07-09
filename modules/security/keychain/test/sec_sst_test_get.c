#include <stdio.h>
#include "keychain.h"

/* try to get the item of other process
 * can not get item of other process
 * check if errno is KC_ERROR_ITEM_NOT_FOUND
 */
void main(void)
{
    char *key = "test_key";
    char secret[128];
    uint32_t secret_len = 128;
    uint32_t ret = 0;
    kc_key_type_t key_type = 0;

    if (kc_init()) {
        printf("kc init failed\n");
        return;
    }

    ret = kc_get_global_item(key, secret, &secret_len, &key_type);
    if (ret != KC_ERROR_ITEM_NOT_FOUND) {
        printf("kc test get other process item failed 0x%x\n", ret);
        goto clean;
    }

    printf("test if can get the item of other process success\n");

clean:
    kc_destroy();
}

