#ifndef __DB_H__
#define __DB_H__

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

typedef enum{
    TYPE_STRING,
    TYPE_INTEGER,
    TYPE_DOUBLE,
    TYPE_BOOLEAN,
    TYPE_BINARY 
}SQL_COL_TYPE;

typedef struct{
    const char      *name; 
    SQL_COL_TYPE    type;
    int             len;
    unsigned char   is_key;
    unsigned char   is_not_null;
}column;

typedef struct{
    const char      *name;
    SQL_COL_TYPE    type;
    const char      *val;
}col_item;

#ifndef DB_PATH_PREFIX
#define DB_PATH_PREFIX "./"
#endif

typedef int (*db_exec_cb)(void*,int,char**,char**);

void *db_init(const char *host, const char *port, const char *db, 
                            const char *usr_name, const char *pwd);

int db_create_table(void *conn,const char *name, int max_cnt ,column *col, int col_cnt);

int db_drop_table(void *conn,const char *table_name);

int db_clear_table(void *conn,const char *table_name);

int db_add_item(void *conn,const char *tab_name,col_item *item,int len);

int db_select_table(void *conn,const char *tab_name ,const char **col, 
                    int col_cnt, db_exec_cb cb, void *usr_data);

int db_limit_tab_rows(void *conn, const char *tab, int rows);

int db_destroy(void *conn);

int db_exec_sql(void *conn, const char *sql,
                        db_exec_cb cb, void *usr_data);

char *db_get_err_msg(int err_code, char *err_msg, int len);
#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif

#endif

