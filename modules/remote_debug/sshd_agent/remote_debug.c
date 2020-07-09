#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int open_remote_debug(const char *path)
{
    struct stat st;
    int ret = 0;
    char buf[512] = {0}; 
    if(!path)
        return -1;

    ret = stat(path, &st);    
    
    if(ret == -1){
        printf("failed to stat %s\n", path); 
        return -1;
    }
    
    if(!S_ISREG(st.st_mode)){
        printf("%s is not a file\n", path); 
        return -2;
    }

    system("systemctl start sshd.socket");
    
    sleep(1);

    snprintf(buf, sizeof(buf), "%s &>/dev/null &", path);
    ret = system(buf);    

    return ret;
}

int close_remote_debug()
{
    int ret = 0;
    char buf[256] = {0};
    
    system("systemctl stop sshd.socket");
    
    sleep(1);
    snprintf(buf, sizeof(buf), "kill -2 `cat /tmp/sshd_agent.pid`");  
   
    sleep(1);
    ret = system(buf);

    return ret;
}

#if 1

int main(int argc, char **argv)
{
    int ret = 0;

    printf("open remote debug....\n");
    
    ret = open_remote_debug("/chunk/wenhu.xwh/develop/remote_debug/sshd_agent/sshd_agent");

    if(ret == 0){
        printf("success !!!!!!!!!\n");
    }else{
        printf("failed : %d:%s!!!!!!!\n", ret, strerror(errno)); 
    }

    sleep(9);

    printf("close remote debug....\n");
    
    ret = close_remote_debug("/chunk/wenhu.xwh/develop/remote_debug/sshd_agent/sshd_agent");

    if(ret == 0){
        printf("success !!!!!!!!!\n");
    }else{
        printf("failed !!!!!!!\n"); 
    }

    return 0; 
}


#endif


