#ifndef __PARSE_INI_H__
#define __PARSE_INI_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#define PARSEINI_LIB_VERSION "1.1.0"

#ifdef __GNUC__
#define WEAKATTR    __attribute__((weak))
#define UNUSEDATTR  __attribute__((unused))
#else
#define WEAKATTR
#define UNUSEDATTR
#endif

typedef enum 
{
    False = 0,
    True
} Bool;

Bool parse_start(const char *filename);
void parse_end(void);
int get_one_value(const char *section, const char *key);
char *get_key_string(const char *section, const char *key, char *buf);
Bool get_more_value(const char *section, const char *key, unsigned char *array, int num);
void add_key_string(const char *section, const char *key, const char *string);
void add_one_key(const char *section, const char *key, int value);
void add_more_key(const char *section, const char *key, unsigned char *array, int num);
void del_key(const char *section, const char *key);
void del_section(const char *section);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PARSE_INI_H__ */

