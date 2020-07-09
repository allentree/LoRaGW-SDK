#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include "ecdsa_operation.h"

typedef enum {
    gen_key = 0,
    sign_file ,
    verify_file ,
    opreation_max,
}test_opr_et;
test_opr_et operation = opreation_max;

const char * key_output_path = NULL;
const char * key_prefix = NULL;
const char * origin_file_path = NULL;
const char * key_path = NULL;
const char * sign_output_file = NULL;
const char * sign_input_file = NULL;

static inline void print_help_string(char *name)
{
    fprintf(stderr, "Usage:  %s -g output key path -p prefix -r origin file -s sign file path -v verify file path -k key path !\n ",name);
    fprintf(stderr, "example - generate key :%s -g /home/root/ -p alibaba \n", name);
    fprintf(stderr, "example generate sign :%s -r /home/root/needSignFile -s /home/root/filesign -k /home/root/privateKey \n", name);
    fprintf(stderr, "example verify file :%s -r /home/root/needVerifyFile -v /home/root/filesign -k /home/root/publicKey \n", name);
    exit(0);
}


void show_help(int argc, char **argv)
{
    int opt = 0;
    //static char buf[1024] = {0};
    if(argc > 7){
        print_help_string(argv[0]); 
    }
    while ((opt = getopt(argc, argv, "g:p:r:s:v:k:")) != -1) {
        switch (opt) {
			//log_i(WATCHDOG_UNITTEST_TAG, "opt value %c!\n\r",opt);
            case 'g':
                operation = gen_key;
                key_output_path = strdup(optarg);
				
				break;
            case 'p':
                key_prefix = strdup(optarg);
				
                break;
            case 'r':
                origin_file_path = strdup(optarg);
				break;
			case 's':
                operation = sign_file;
                sign_output_file =  strdup(optarg);
                break;
            case 'v':
                operation = verify_file;
                sign_input_file =  strdup(optarg);
                break;
            case 'k':
                key_path = strdup(optarg);
                break;
            case 'h':	
            default: 
            print_help_string(argv[0]); 
        }
    }

	return;
}



int main(int argc, char** argv)
{

    show_help(argc, argv);
    int ret = -1;
    switch(operation)
    {
        case gen_key:
            if(!key_output_path)
            {
                fprintf(stderr,"have no output path for key'sgeneration!\n");
                print_help_string(argv[0]);
                break;
            }
            ret = create_ECDSAKey(key_output_path, key_prefix);
            if(ret < 0)
            {
                fprintf(stderr,"create sign key error : %d!\n", ret);
            }
            else
            {
                printf("create key successful, output path %s !\n", key_output_path);
            }
        break;
        case sign_file:
            if(!origin_file_path)
            {
                fprintf(stderr,"have no origin_file_path for sign!\n");
                print_help_string(argv[0]);
                break;
            }
            if(!key_path)
            {
                fprintf(stderr,"have no key_path for sign!\n");
                print_help_string(argv[0]);
                break;
            }
            if(!sign_output_file)
            {
                fprintf(stderr,"have no sign_output_file for sign!\n");
                print_help_string(argv[0]);
                break;
            }
            ret = ECDSA_sign_file_with_privateKey(key_path,origin_file_path,sign_output_file);
            if(ret < 0)
            {
                fprintf(stderr,"create file's sign error : %d!\n", ret);
            }
            else
            {
                printf("create file sign successful, output path %s !\n", sign_output_file);
            }
        break;
        case verify_file:
            if(!origin_file_path)
            {
                fprintf(stderr,"have no origin_file_path for sign!\n");
                print_help_string(argv[0]);
                break;
            }
            if(!key_path)
            {
                fprintf(stderr,"have no key_path for sign!\n");
                print_help_string(argv[0]);
                break;
            }
            if(!sign_input_file)
            {
                fprintf(stderr,"have no sign_input_file for sign!\n");
                print_help_string(argv[0]);
                break;
            }
            ret = ESDSA_verify_sign_with_publicKey(key_path,origin_file_path,sign_input_file);
            if(ret < 0)
            {
                fprintf(stderr,"verify file's sign error : %d!\n", ret);
            }
            else
            {
                printf("verify file sign successful, the sign is OK!\n");
            }
        break;
        default:
            print_help_string(argv[0]);
        break;
    }
    if(key_output_path) {
        free((void *)key_output_path);
    }
    if(key_prefix) {
        free((void *)key_prefix);
    }
    if(origin_file_path) {
        free((void *)origin_file_path);
    }
    if(key_path) {
        free((void *)key_path);
    }
    if(sign_output_file) {
        free((void *)sign_output_file);
    }
    if(sign_input_file) {
        free((void *)sign_input_file);
    }

    return 0;
}