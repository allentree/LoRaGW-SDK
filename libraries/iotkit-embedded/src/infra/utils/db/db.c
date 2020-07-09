#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db.h"

extern char *db_auto_increase_primary_key();
extern int db_destroy(void *conn);
extern void *db_open_connection(const char *host,const char *port, 
                const char *db, const char *usr_name,const char *pwd);

extern int db_exec_sql(void *conn,const char *sql,db_exec_cb cb, void *usr_data);
extern char *db_get_err_msg(int err_code, char *err_msg, int len);

void *db_init(const char *host, const char *port, 
                    const char *db, const char *usr_name, 
                    const char *pwd) 
{
    return db_open_connection(host,port,db,usr_name,pwd);
}

static void type_convert(SQL_COL_TYPE type, int len, char *cmd, int cmd_left_len)
{
    switch(type){
        case TYPE_STRING:
            snprintf(cmd, cmd_left_len," varchar(%d) ",len); 
            break;
        case TYPE_INTEGER:
            strncat(cmd," integer", cmd_left_len);
            break;
        case TYPE_DOUBLE:
            strncat(cmd," double precision", cmd_left_len);
            break;
        case TYPE_BOOLEAN:
            strncat(cmd," boolean", cmd_left_len);
            break;
        case TYPE_BINARY:
            strncat(cmd," bytea", cmd_left_len);
            break;
        default: break;
    }
}

static void create_limited_table(void *conn,const char *tab, int limit, char *cmd, int len)
{
    if(!conn || !tab || limit <= 0)
        return;

    //drop table
    memset(cmd,0,len);
    snprintf(cmd,len,"DROP TABLE IF EXISTS \"_%s_limited\"",tab);
    db_exec_sql(conn,cmd,NULL,NULL);

    //create new table
    memset(cmd,0,len);
    snprintf(cmd,len,"CREATE TABLE if not exists \"_%s_limited\" (max_cnt integer, cur_cnt integer)",tab);
    db_exec_sql(conn,cmd,NULL,NULL);

    //add the init values.
    memset(cmd,0,len);
    snprintf(cmd,len,"INSERT INTO \"_%s_limited\" (max_cnt, cur_cnt) VALUES (%d,0)",tab,limit);
    db_exec_sql(conn,cmd,NULL,NULL);
}

static int cb_get_cnt(void* usr_data,int count,char** data ,char** columns)
{
    int *cnt = NULL;

    cnt = usr_data;
   
    if(cnt)
        *cnt = atoi(data[0]); 

    return 0;
}

static int increase_limited_table(void *conn,const char *tab, char *cmd ,int len)
{
    int cur_cnt = 0;

    memset(cmd,0,len);
    //get current count
    snprintf(cmd,len,"SELECT cur_cnt FROM \"_%s_limited\"",tab);
    db_exec_sql(conn,cmd,cb_get_cnt,&cur_cnt);
   
    //get the total count.
    if(cur_cnt <= 0){
        memset(cmd,0,len);
        snprintf(cmd,len,"SELECT count(*) from \"%s\"",tab);
        db_exec_sql(conn,cmd,cb_get_cnt,&cur_cnt);
    }
     
    memset(cmd,0,len);
    snprintf(cmd,len,"UPDATE \"_%s_limited\" set cur_cnt = %d"
                            ,tab,++cur_cnt);
    db_exec_sql(conn,cmd,NULL,NULL);
    return cur_cnt;
}

static void auto_limit_tab_rows(void *conn,const  char *tab, char *cmd ,int len)
{
    int max_cnt = 0; 
    int cur_cnt = 0;
  
    if(!conn || !tab || !cmd)
        return;

    //update the limited table
    cur_cnt = increase_limited_table(conn,tab,cmd,len);
    
    memset(cmd,0,len);
    snprintf(cmd,len,"SELECT max_cnt FROM \"_%s_limited\"",tab);
    db_exec_sql(conn,cmd,cb_get_cnt,&max_cnt);

    if(max_cnt <= 0 || max_cnt > cur_cnt)
        return; 
    
    //delete the un-needed rows
    db_limit_tab_rows(conn,tab,max_cnt/2);
    
    //update the limited table
    memset(cmd,0,len); 
    snprintf(cmd,len,"UPDATE \"_%s_limited\" set cur_cnt=0",tab);
    db_exec_sql(conn,cmd,NULL,NULL);
}

static inline int get_left_len(char *p, int init_len, int reserved_len)
{
    int left_len = 0;

    if(!p)
        return left_len;

    left_len = init_len - strlen(p) - 1 - reserved_len;
    
    return left_len <= 0 ? 0 : left_len;
}

#define DEFAULT_CMD_LENGTH 1024*10
int db_create_table(void *conn,const char *name, int max_cnt, column *col, int col_cnt)
{
    char *cmd = NULL; 
    int i = 0;
    int ret = 0;
    char *key = NULL;
    int index = -1;

    if(!conn || !name || !col)
        return -1;

    cmd = malloc(DEFAULT_CMD_LENGTH); 
    if(!cmd)
        return -1;
  
    key = db_auto_increase_primary_key();
    memset(cmd,0,DEFAULT_CMD_LENGTH);
    snprintf(cmd,get_left_len(cmd,DEFAULT_CMD_LENGTH,3),"CREATE TABLE if not exists \"%s\" (",name);
   
    if(key)
        snprintf(cmd+strlen(cmd),get_left_len(cmd,DEFAULT_CMD_LENGTH,3),"%s,",key); 

    for(i = 0; i < col_cnt; i++) {
        if(col[i].name == NULL)
            break;
        strncat(cmd,col[i].name,get_left_len(cmd,DEFAULT_CMD_LENGTH,3));
        type_convert(col[i].type,col[i].len,cmd+strlen(cmd),get_left_len(cmd,DEFAULT_CMD_LENGTH,3));
        
        if(col[i].is_key)
           index = i; 
        if(col[i].is_not_null)
            strncat(cmd," NOT NULL", get_left_len(cmd,DEFAULT_CMD_LENGTH,3));
        if(i != col_cnt-1)
            strncat(cmd," ,", get_left_len(cmd,DEFAULT_CMD_LENGTH,3));
    }
    if(index != -1)
        snprintf(cmd+strlen(cmd),get_left_len(cmd,DEFAULT_CMD_LENGTH,3),",UNIQUE (%s)",col[index].name);
    strcat(cmd," )"); 
    ret = db_exec_sql(conn,cmd,NULL,NULL);
#ifndef AUTO_CUT
    create_limited_table(conn,name,max_cnt,cmd,DEFAULT_CMD_LENGTH);
#endif
    free(cmd);
    return ret;
}

int db_clear_table(void *conn, const char *table_name)
{
    int ret = 0;
    char cmd[DEFAULT_CMD_LENGTH] = {0}; 
    
    if(!conn || !table_name)
        return -1;

    snprintf(cmd,sizeof(cmd),"DELETE FROM \"%s\"",table_name);

    ret = db_exec_sql(conn,cmd,NULL,NULL);

    memset(cmd,0,sizeof(cmd));
    snprintf(cmd,sizeof(cmd),"UPDATE \"_%s_limited\" set cur_cnt = 0",table_name);
    db_exec_sql(conn,cmd,NULL,NULL);

    return ret;
}

int db_drop_table(void *conn, const char *table_name)
{
    int ret = 0;
    char cmd[DEFAULT_CMD_LENGTH] = {0}; 
    
    if(!conn || !table_name)
        return -1;

    snprintf(cmd,sizeof(cmd),"DROP TABLE IF EXISTS \"%s\"",table_name);
    ret = db_exec_sql(conn,cmd,NULL,NULL);

    memset(cmd,0,sizeof(cmd));
    snprintf(cmd,sizeof(cmd),"DROP TABLE IF EXISTS \"_%s_limited\"",table_name);
    ret = db_exec_sql(conn,cmd,NULL,NULL);

    return ret;
}

static int _append_sql_cmd(const char *target, char *buf,int len)
{
    int i = 0;
    int j = 0;

    if(!target || !buf || len <= 0)
        return 0;
    
    buf[j++] = 39;// 39 == ''', 
    for(i = 0; i < strlen(target); i++){
        if(j >= len-2)
            break;

        if(target[i] == 39 && target[i+1] != 39){
            buf[j++] = 39; 
        }
        buf[j++] = target[i];
    }
    buf[j] = 39;
    
    return j-1;
}


int db_add_item(void *conn,const  char *tab_name,col_item *item,int len)
{
    char *cmd = NULL; 
    int i = 0;
    int ret = 0;
    if(!conn || !tab_name || !item)
        return -1;

    cmd = malloc(DEFAULT_CMD_LENGTH+1); 
    if(!cmd)
        return -1;
   
    memset(cmd,0,DEFAULT_CMD_LENGTH+1);
    snprintf(cmd,DEFAULT_CMD_LENGTH,"INSERT INTO \"%s\" (",tab_name);

    for(i = 0; i < len ; i++){
        if(item[i].name == NULL){
            len = i+1;
            break;
        }
        strncat(cmd,item[i].name,get_left_len(cmd,DEFAULT_CMD_LENGTH,2));
        if(i != len-1)
            strncat(cmd," ,",get_left_len(cmd,DEFAULT_CMD_LENGTH,2));
    }
    strncat(cmd,") VALUES ( ",get_left_len(cmd,DEFAULT_CMD_LENGTH,2));
    for(i = 0; i < len ; i++){
        if(item[i].type == TYPE_INTEGER || 
                item[i].type == TYPE_DOUBLE ){
            snprintf(cmd+strlen(cmd),get_left_len(cmd,DEFAULT_CMD_LENGTH,4),"%s",item[i].val); 
        } else{
            _append_sql_cmd(item[i].val, cmd+strlen(cmd), get_left_len(cmd,DEFAULT_CMD_LENGTH,4));

        } 
        if(i != len-1)
            strncat(cmd, ", ", get_left_len(cmd,DEFAULT_CMD_LENGTH,2));
    }
    strcat(cmd,")");
    ret = db_exec_sql(conn,cmd,NULL,NULL);
#ifndef AUTO_CUT
    auto_limit_tab_rows(conn,tab_name,cmd,DEFAULT_CMD_LENGTH);
#endif
    free(cmd);
    return ret;
}

int db_select_table(void *conn, const char *tab_name ,const char **col, 
                    int col_cnt, db_exec_cb cb, void *usr_data)
{
    char *cmd = NULL; 
    int i = 0;
    int ret = 0;
    int fix_len = 0;

    if(!conn || !tab_name || !col)
        return -1;

    cmd = malloc(DEFAULT_CMD_LENGTH); 
    if(!cmd)
        return -1;
   
    memset(cmd,0,DEFAULT_CMD_LENGTH);

    strcat(cmd,"select ");
    fix_len = strlen(tab_name) + strlen("from") - 5;//...from tab_name;
    for(i = 0; i < col_cnt; i++){
        if(col[i] == NULL)
            break;
        strncat(cmd,col[i],get_left_len(cmd,DEFAULT_CMD_LENGTH,fix_len));
        if(i != col_cnt-1)
            strncat(cmd," ,", get_left_len(cmd,DEFAULT_CMD_LENGTH,fix_len));
    }
    snprintf(cmd+strlen(cmd),get_left_len(cmd,DEFAULT_CMD_LENGTH,0), 
                " from \"%s\"",tab_name);

    ret = db_exec_sql(conn,cmd,cb,usr_data);
    free(cmd);
    return ret;
}

int db_limit_tab_rows(void *conn, const char *tab, int rows)
{
    char *cmd = NULL; 
    int ret = 0;

    if(!conn || !tab || rows <= 0)
        return -1;

    cmd = malloc(DEFAULT_CMD_LENGTH); 
    if(!cmd)
        return -1;
   
    memset(cmd,0,DEFAULT_CMD_LENGTH);

    snprintf(cmd,DEFAULT_CMD_LENGTH, "delete from \"%s\" where __id not in (select __id from \"%s\" order by __id desc limit %d)",
                                tab,tab,rows); 
    ret = db_exec_sql(conn,cmd,NULL,NULL);
    free(cmd);

    return ret;
}

