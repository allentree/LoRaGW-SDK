#ifndef UTILS_H
#define UTILS_H

int check_file_sig(const char *file, const char *file_sig);
int check_file_same(const char *file1, const char *file2);
char *get_sec_sys_name();
char *get_sec_sys_sig_name();
char *get_sec_sys_bak_name();
char *get_sec_sys_bak_sig_name();
int copy_file(const char *file1, const char *file2);

#endif // UTILS_H
