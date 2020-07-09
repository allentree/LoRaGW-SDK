#include "km.h"

#define RSA_GEN_NAME "rsa_gen_key"
#define RSA_GEN_NAME_LEN sizeof(RSA_GEN_NAME)
#define RSA_IM_NAME "rsa_im_key"
#define RSA_IM_NAME_LEN sizeof(RSA_IM_NAME)
#define AES_GEN_NAME "aes_gen_key"
#define AES_GEN_NAME_LEN sizeof(AES_GEN_NAME)
#define AES_IM_NAME "aes_im_key"
#define AES_IM_NAME_LEN sizeof(AES_IM_NAME)
#define HMAC_GEN_NAME "hmac_gen_key"
#define HMAC_GEN_NAME_LEN sizeof(HMAC_GEN_NAME)
#define HMAC_IM_NAME "hmac_im_key"
#define HMAC_IM_NAME_LEN sizeof(HMAC_IM_NAME)

#define km_malloc malloc
#define km_memset memset
#define km_memcpy memcpy

uint32_t test_import(char *name, uint32_t name_len, km_key_type type);
uint32_t test_generate(char *name, uint32_t name_len,
                  km_key_type type, uint32_t key_size);

uint32_t test_delete(char *name, uint32_t name_len);

