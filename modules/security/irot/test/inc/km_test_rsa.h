#ifndef _KM_TEST_RSA_H_
#define _KM_TEST_RSA_H_

uint32_t test_sign_verify(char *name, uint32_t name_len);
uint32_t test_encrypt_decrypt(char *name, uint32_t name_len);
uint32_t km_asym_test();
uint32_t km_rsa_perf_test(uint32_t test_count);

#endif /* _KM_TEST_RSA_H_ */
