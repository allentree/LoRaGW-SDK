#ifndef _KM_TEST_AES_H_
#define _KM_TEST_AES_H_

uint32_t test_cipher_enc_dec(char *name, uint32_t name_len,
                        km_block_mode_type type,
                        km_padding_type padding_type);

uint32_t test_cipher_short(char *name, uint32_t name_len,
                        km_block_mode_type type,
                        km_padding_type padding_type);

uint32_t km_cipher_whole_test(char *name, uint32_t name_len);

uint32_t km_cipher_perf_test(uint32_t test_count);

#endif /* _KM_TEST_AES_H_ */
