#include "ecdsa_operation.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>


#define ECDSA_PUBLIC_KEY_NAME "PublicKey.pem"
#define ECDSA_PRIVATE_KEY_NAME "PrivateKey.pem"

static int _Write_PublicKey2File(const char *Path, EC_KEY *pKey)
{
	int nRet = 0;
	BIO *pBioFile = BIO_new_file(Path, "wb+");
	do {
		if (!pBioFile) {
			printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__); 
			nRet = ESDSA_ERR_NEW_FILE;
			break;
		}

		if (1 != PEM_write_bio_EC_PUBKEY(pBioFile, pKey)) {
			printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__); 
			nRet = ESDSA_ERR_WRITE_FILE;
			break;
		}

		nRet = ESDSA_NO_ERROR;
	} while (0);
	if(pBioFile)
		BIO_free(pBioFile); 
	return nRet;
}

static int _Write_PrivateKey2File(const char *Path, EC_KEY *pKey,EC_GROUP *ec_group)
{
	int nRet = 0;
	BIO *pBioFile = BIO_new_file(Path, "wb+");

	do 
	{
		if (!pBioFile) {
			printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__); 
			nRet = ESDSA_ERR_NEW_FILE;
			break;
		}

		PEM_write_bio_ECPKParameters(pBioFile, ec_group);
		if (1 != PEM_write_bio_ECPrivateKey(pBioFile, pKey,NULL,NULL,0,NULL,NULL)) {
			printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__);
			nRet = ESDSA_ERR_WRITE_FILE; 
			break;
		}
		nRet = ESDSA_NO_ERROR;
	} while (0);
	if(pBioFile)
		BIO_free(pBioFile); 
	return nRet;
}

int create_ECDSAKey(const char * output_path, const char * prefix)
{
	int ret = 0;
	EC_KEY  *ec_key = NULL;;   
	char    *pFileAllPath = NULL;
	EC_GROUP *ec_group;  
	int nPathLen = 0;
	
	char *pPublicKey  = ECDSA_PUBLIC_KEY_NAME;
	char *pPrivateKey = ECDSA_PRIVATE_KEY_NAME;

	ec_key = EC_KEY_new();

	if (!ec_key) { 
		printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__);  
		return ESDSA_ERR_ALLOC_KEY;  
	}   

	ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if (!ec_group) {   
		printf("ECDSA Error%s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__); 
		ret = ESDSA_ERR_ALLOC_KEY;
		goto error1;
	}

	EC_GROUP_set_asn1_flag(ec_group, OPENSSL_EC_NAMED_CURVE);
	EC_GROUP_set_point_conversion_form(ec_group, POINT_CONVERSION_UNCOMPRESSED);

	if(1 != EC_KEY_set_group(ec_key,ec_group)) {   
		printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__);  
		ret = ESDSA_ERR_SET_KEY_GROUP;
		goto error1;
	}

	if (!EC_KEY_generate_key(ec_key)) {
		printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__); 
		ret = ESDSA_ERR_GEN_KEY;
		goto error2;
	}
    if(prefix){
        nPathLen = strlen(output_path) + strlen(pPublicKey) + strlen(pPrivateKey) + strlen(prefix) + 2;
    }
    else {
        nPathLen = strlen(output_path) + strlen(pPublicKey) + strlen(pPrivateKey) + 2;
    }
	pFileAllPath = (char*)malloc(nPathLen);
	if(!pFileAllPath){
		ret = ESDSA_ERR_ALLOC_KEY;
		goto  error2; 
	}
	memset((void*)pFileAllPath,0,nPathLen);
	strcpy(pFileAllPath,output_path);
	if(prefix) {
		strcat(pFileAllPath,prefix);
	}
	strcat(pFileAllPath,pPublicKey);
	ret = _Write_PublicKey2File(pFileAllPath,ec_key);
	if( ret != ESDSA_NO_ERROR ) {
		printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__);
		goto error3;
	}
	memset((void*)pFileAllPath,0,nPathLen);
	strcpy(pFileAllPath,output_path);
	if(prefix) {
		strcat(pFileAllPath,prefix);
	}
	strcat(pFileAllPath,pPrivateKey);
	ret = _Write_PrivateKey2File(pFileAllPath,ec_key,ec_group);
	if( ret != ESDSA_NO_ERROR ) {
		printf("ECDSA Error %s %s,%d\n",__FILE__,__FUNCTION__ ,__LINE__);
		goto error3;
	}
error3:
	if(pFileAllPath) {
		free(pFileAllPath);
		pFileAllPath = NULL;
	}
error2:
	if (ec_group) {
		EC_GROUP_free(ec_group);
		ec_group = NULL;
	}
error1:
	if (ec_key) {
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ret;
}

static int load_file_data(const char * path, char **pbuffer, unsigned int * buffer_size)
{
	FILE * file = NULL;
	int fileSize = -1;
	char * pFileData = NULL;
	int ret = 0;

	if(!path || !pbuffer || !buffer_size) {
		return -1;
	}

	*buffer_size = 0;
	
	file = fopen(path,"rb");
	if(!file) {
		return -1;
	}
	fseek(file,0L,SEEK_END);
	fileSize = ftell(file);
	if(fileSize < 0) {
		fclose(file);
		return -1;
	}
	pFileData = (char*)malloc(fileSize);
	if(!pFileData) {
		fclose(file);
		return -1;
	}

	memset(pFileData,0,fileSize);
	fseek(file,0L,SEEK_SET); 
	ret = fread(pFileData,fileSize,1,file);
	if(ret != 1){
		fclose(file);
		free(pFileData);
		return -1;
	}
	*pbuffer = pFileData;
	*buffer_size = fileSize;
	fclose(file);
	file = NULL;

	return 0;
}

static EC_KEY * ECDSA_load_key_from_file(const char * key_file_path, int key_type)
{
	EC_KEY *ec_key = NULL; 
	BIO *pBioKeyFile = NULL;
	if(!key_file_path) {
		return NULL;
	}
	pBioKeyFile = BIO_new_file(key_file_path, "rb");
	if(!pBioKeyFile) {
		return NULL;
	}
	if(!key_type)
		ec_key = PEM_read_bio_ECPrivateKey(pBioKeyFile, NULL, NULL, NULL);
	else
		ec_key = PEM_read_bio_EC_PUBKEY(pBioKeyFile, NULL, NULL, NULL);
	BIO_free(pBioKeyFile);
	return ec_key;
}

static int ECDSA_gen_sha256(const char * pData, unsigned int dataSize, char* digest)
{
	EVP_MD_CTX md_ctx;
	unsigned int  dgst_len = 0;
	if(!pData || !digest)
		return -1; 
	EVP_MD_CTX_init(&md_ctx);  
	EVP_DigestInit(&md_ctx, EVP_sha256());
	EVP_DigestUpdate(&md_ctx, (const void*)pData,dataSize);  
	EVP_DigestFinal(&md_ctx, (unsigned char*)digest, &dgst_len);
	return dgst_len;
}

int ECDSA_sign_file_with_privateKey(const char * privateKey_path, const char * file_path, const char * output_sign_path)
{
	int ret = ESDSA_NO_ERROR;
	char *pfileData = NULL;
	unsigned int fileSize = 0;
	EC_KEY * privateKey = NULL;

	char digest[32];
	char sign_buffer[1024];
	unsigned int sign_size =0;
	int dgst_len = 0;
	if(!privateKey_path || !file_path || !output_sign_path){
		return ESDSA_ERR_PARAMS;
	}

	FILE * fp = NULL;
	ret = load_file_data(file_path, &pfileData, &fileSize);
	if(ret < 0)
	{
		return ESDSA_ERR_READ_FILE;
	}
	privateKey = ECDSA_load_key_from_file(privateKey_path, 0);
	if(!privateKey) {
	
		ret = ESDSA_ERR_READ_FILE;
		goto error1;
	}

	memset(digest, 0 , sizeof(digest));
	dgst_len = ECDSA_gen_sha256(pfileData, fileSize, &digest[0]);
	if(dgst_len < 0) {
		
		ret = ESDSA_ERR_GEN_SHA256;
		goto error2;
	}
	if (!ECDSA_sign(0,(const unsigned char *)digest, dgst_len,(unsigned char *)sign_buffer, &sign_size,privateKey)) {
		
		ret = ESDSA_ERR_GEN_SIGN;
		goto error2;
	}
	fp = fopen(output_sign_path,"wb");
	if(!fp)
	{
		ret = ESDSA_ERR_WRITE_FILE;
		goto error2;
	}
	ret = fwrite(sign_buffer,sign_size,1,fp);
	if(ret != 1)
	{
		ret = ESDSA_ERR_WRITE_FILE;
		goto error3;
	}
	ret = ESDSA_NO_ERROR;
error3:
	if(fp)
		fclose(fp);	
error2:
	if(privateKey)
		EC_KEY_free(privateKey); 
error1:		
	if(pfileData)
		free(pfileData);
	return ret;
}

int ESDSA_verify_sign_with_publicKey(const char * publicKey_path, const char * file_path, const char * input_sign_path)
{
	int ret = ESDSA_NO_ERROR;
	char *pfileData = NULL;
	unsigned int fileSize = 0;
	char *psignData = NULL;
	unsigned int signSize = 0;

	EC_KEY * publicKey = NULL;

	char digest[32];
	//char sign_buffer[1024];
	//unsigned int sign_size =0;

	int dgst_len = 0;

	if(!publicKey_path || !file_path || !input_sign_path){
		return ESDSA_ERR_PARAMS;
	}

	ret = load_file_data(file_path, &pfileData, &fileSize);
	if(ret < 0)
	{
		return ESDSA_ERR_READ_FILE;
	}
	ret = load_file_data(input_sign_path, &psignData, &signSize);
	if(ret < 0)
	{
		ret = ESDSA_ERR_READ_FILE;
		goto error1;
	}

	publicKey = ECDSA_load_key_from_file(publicKey_path, 1);
	if(!publicKey) {
	
		ret = ESDSA_ERR_READ_FILE;
		goto error2;
	}

	memset(digest, 0 , sizeof(digest));
	dgst_len = ECDSA_gen_sha256(pfileData, fileSize, &digest[0]);
	if(dgst_len < 0) {
		
		ret = ESDSA_ERR_GEN_SHA256;
		goto error3;
	}
	ret = ECDSA_verify(0,(const unsigned char*)digest, dgst_len, (const unsigned char *)psignData, signSize, publicKey);
	if(ret == 0) {
		ret = ESDSA_ERR_SIGN_INVALID;
	}
	else if (ret == 1){
		ret = ESDSA_NO_ERROR;
	}
	else {
		ret = ESDSA_ERR_SIGN_FAILED;
	}

error3:
	if(publicKey)
		EC_KEY_free(publicKey); 
error2:		
	if(psignData)
		free(psignData);		
error1:		
	if(pfileData)
		free(pfileData);
	return ret;
}

