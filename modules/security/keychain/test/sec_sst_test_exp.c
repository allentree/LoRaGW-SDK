#include <stdio.h>
#include "keychain.h"

void test_no_int_but_destroy()
{
    kc_destroy();
}

void test_init_one_multi_destroy()
{
    kc_init();
    kc_destroy();
    kc_destroy();
}

int test_no_init()
{
    uint32_t ret = 0;
    char *key = "test_key";
    uint32_t secret_len = 0;
    kc_key_type_t key_type = 0;

    ret = kc_get_item(key, NULL, &secret_len, &key_type);
    if (!ret) {
        printf("kc test get other process item failed 0x%x\n", ret);
        return -1;
    }

    return 0;
}

void main(void)
{
    int ret = 0;

    ret = test_no_init();
    if (ret) {
        printf("test no init failed\n");
        return;
    }
#if 0
    test_no_int_but_destroy();
    printf("test not init but destroy no crash success\n");
#endif

    test_init_one_multi_destroy();
    printf("test init one but multi destroy no crash success\n");
}

