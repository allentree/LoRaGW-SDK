#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#define ESDSA_NO_ERROR 0
#define ESDSA_ERR_ALLOC_KEY -1
#define ESDSA_ERR_WRITE_FILE -2
#define ESDSA_ERR_READ_FILE -3
#define ESDSA_ERR_OPEN_FILE -4
#define ESDSA_ERR_SET_KEY_GROUP -5
#define ESDSA_ERR_GEN_KEY -6
#define ESDSA_ERR_NEW_FILE -7
#define ESDSA_ERR_GEN_SHA256 -8
#define ESDSA_ERR_GEN_SIGN -9
#define ESDSA_ERR_PARAMS -10
#define ESDSA_ERR_SIGN_INVALID -11
#define ESDSA_ERR_SIGN_FAILED -12
//#define 
int create_ECDSAKey(const char * output_path, const char * prefix);

int ECDSA_sign_file_with_privateKey(const char * privateKey_path, const char * file_path, const char * output_sign_path);

int ESDSA_verify_sign_with_publicKey(const char * publicKey_path, const char * file_path, const char * output_sign_path);

