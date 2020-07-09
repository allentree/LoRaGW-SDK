#include <stdio.h>
#include <unistd.h>

#include "sqlite3/sqlite3.h"
#include "db.h"

char *db_auto_increase_primary_key()
{
    return "__id integer primary key autoincrement";
}

int db_destroy(void *conn)
{
    sqlite3 *p_conn = conn;
    return sqlite3_close(p_conn);
}

void *db_open_connection(const char *host,const char *port, 
                const char *db, const char *usr_name,const char *pwd) 
{
    sqlite3 *p_conn = NULL;
    int ret = 0;
    char db_name[512] = {0};

    snprintf(db_name,sizeof(db_name),"%s/%s",DB_PATH_PREFIX,db);
    ret = sqlite3_open(db_name,&p_conn);
    if(SQLITE_OK != ret)
        printf("error to open sqlite3 database : %s, %s\n",sqlite3_errstr(ret),db_name);
    else{
        printf("open sqlite connection success, db location: %s\n",db_name);

#ifndef SQLITE_SYNC
        db_exec_sql(p_conn,"PRAGMA synchronous=OFF",NULL,NULL);
#endif
    }
    return p_conn;
}

int db_exec_sql(void *conn,const char *sql,db_exec_cb cb, void *usr_data)
{
    int ret = 0;
    sqlite3 *p_conn = conn;
    char *err_msg = NULL;
    char err_buf[128] = {0};
again:
    ret = sqlite3_exec(p_conn,sql,cb,usr_data,&err_msg);
    if(SQLITE_BUSY == ret){
        usleep(1);
        sqlite3_free(err_msg);
        goto again;
    }

    if(SQLITE_OK != ret){
        printf("failed to exec sql,: %s, sql: %s\n",
                err_msg ? err_msg : db_get_err_msg(ret,err_buf,128), sql);
        sqlite3_free(err_msg);
    }
    return ret;
}

char *db_get_err_msg(int err_code, char *err_msg, int len)
{
    if(!err_msg)
        return NULL;

    switch(err_code){
        case SQLITE_ERROR     :  snprintf(err_msg,len,"%s"," Generic error ");break;
        case SQLITE_INTERNAL  :  snprintf(err_msg,len,"%s"," Internal logic error in SQLite ");break;
        case SQLITE_PERM      :  snprintf(err_msg,len,"%s"," Access permission denied ");break;
        case SQLITE_ABORT     :  snprintf(err_msg,len,"%s"," Callback routine requested an abort");break; 
        case SQLITE_BUSY      :  snprintf(err_msg,len,"%s"," The database file is locked ");break;
        case SQLITE_LOCKED    :  snprintf(err_msg,len,"%s"," A table in the database is locked ");break;
        case SQLITE_NOMEM     :  snprintf(err_msg,len,"%s"," A malloc() failed ");break;
        case SQLITE_READONLY  :  snprintf(err_msg,len,"%s"," Attempt to write a readonly database ");break;
        case SQLITE_INTERRUPT :  snprintf(err_msg,len,"%s"," Operation terminated by sqlite3_interrupt()");break;
        case SQLITE_IOERR     :  snprintf(err_msg,len,"%s"," Some kind of disk I/O error occurred ");break;
        case SQLITE_CORRUPT   :  snprintf(err_msg,len,"%s"," The database disk image is malformed ");break;
        case SQLITE_NOTFOUND  :  snprintf(err_msg,len,"%s"," Unknown opcode in sqlite3_file_control() ");break;
        case SQLITE_FULL      :  snprintf(err_msg,len,"%s"," Insertion failed because database is full ");break;
        case SQLITE_CANTOPEN  :  snprintf(err_msg,len,"%s"," Unable to open the database file ");break;
        case SQLITE_PROTOCOL  :  snprintf(err_msg,len,"%s"," Database lock protocol error ");break;
        case SQLITE_EMPTY     :  snprintf(err_msg,len,"%s"," Internal use only ");break;
        case SQLITE_SCHEMA    :  snprintf(err_msg,len,"%s"," The database schema changed");break; 
        case SQLITE_TOOBIG    :  snprintf(err_msg,len,"%s"," String or BLOB exceeds size limit");break;
        case SQLITE_CONSTRAINT:  snprintf(err_msg,len,"%s"," Abort due to constraint violation");break;
        case SQLITE_MISMATCH  :  snprintf(err_msg,len,"%s"," Data type mismatch");break;
        case SQLITE_MISUSE    :  snprintf(err_msg,len,"%s"," Library used incorrectly");break;
        case SQLITE_NOLFS     :  snprintf(err_msg,len,"%s"," Uses OS features not supported on host");break;
        case SQLITE_AUTH      :  snprintf(err_msg,len,"%s"," Authorization denied");break;
        case SQLITE_FORMAT    :  snprintf(err_msg,len,"%s"," Not used");break;
        case SQLITE_RANGE     :  snprintf(err_msg,len,"%s"," 2nd parameter to sqlite3_bind out of range");break;
        case SQLITE_NOTADB    :  snprintf(err_msg,len,"%s"," File opened that is not a database file");break;
        case SQLITE_NOTICE    :  snprintf(err_msg,len,"%s"," Notifications from sqlite3_log()");break;
        case SQLITE_WARNING   :  snprintf(err_msg,len,"%s"," Warnings from sqlite3_log()");break;
        case SQLITE_ROW       :  snprintf(err_msg,len,"%s"," sqlite3_step() has another row ready");break;
        case SQLITE_DONE      :  snprintf(err_msg,len,"%s"," sqlite3_step() has finished executing");break;
        case -1               :  snprintf(err_msg,len,"%s"," Param is not correct.");break;
        default: snprintf(err_msg,len,"%s","unkonw error msg.");break; 
    }

    return err_msg;
}

