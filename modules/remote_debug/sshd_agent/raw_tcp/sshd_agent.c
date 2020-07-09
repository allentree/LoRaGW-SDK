#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "rd_net.h"

#define ERR printf
#define INFO printf

// #define USE_TCP

//这是server的地址和端口
#define LOCAL_IP                 "100.69.166.91"    //服务器单播地址
#define LOCAL_PORT               54322            //服务器的端口
#define WB_LOCAL_PORT            "54322"          //服务器的端口

//这是需要转发的IP地址和端口
//#define REMOTE_IP               "100.69.166.91:22/"
#define REMOTE_IP               "172.17.0.2:22/"

typedef struct {
    struct sockaddr_in  toIP;
    unsigned int              toSock;//提供ssh服务的socket

    struct in_addr fromAddr;//发出请求连接的客户端信息
    unsigned short         fromPort;
    unsigned int         fromSock;//ssh客户端的socket
}link_info;

#define MAX_VAL(v1,v2)  ((v1) > (v2) ? (v1) : (v2))

int GetRemoteSever(char *src,struct sockaddr_in *addrServer)
{
	//log_debug("src    %s\n",src);
	if(!src || !addrServer)
	{
		return -1;
	}

	bzero(addrServer,sizeof(struct sockaddr_in)); 
	addrServer->sin_family = AF_INET;
	
	char *pTemp = src;
	if(strstr(src,"//") != 0)//去掉http://得到后面的地址
	{
		pTemp = strstr(src,"//")+2; 
	}

    if(strchr(pTemp,':') != 0)//如果直接是IP地址
	{
		char IP[16];
		memset(IP,0,sizeof(IP));
		strncpy(IP,pTemp,strchr(pTemp,':')-pTemp);// ip 

		addrServer->sin_addr.s_addr =  inet_addr(IP);
		
		pTemp = strchr(pTemp,':')+1;// 20099/
		if(strchr(pTemp,'/') != 0)
		{
			char PORT[6];
			memset(PORT,0,sizeof(PORT));
			strncpy(PORT,pTemp,strchr(pTemp,'/')-pTemp);//port
			addrServer->sin_port = htons(atoi(PORT));
		}
		pTemp = strchr(pTemp,'/');
	}
	else//如果不是直接给出IP地址，则需要通过DNS获取
	{
		char NET[256];
		memset(NET,0,sizeof(NET));
        if(strchr(pTemp,'/') != NULL){
            strncpy(NET,pTemp,strchr(pTemp,'/')-pTemp);//devimages.apple.com   
        }else{
            strcpy(NET,pTemp);
        }

		struct hostent   *hostTemp;

		while((hostTemp=gethostbyname(NET)) == NULL)//如果dns解析失败的话，那就一直等待解析
		{
	        ERR("gethostbyname   error,   %s\n ",strerror(errno));
			sleep(1);
		}
	
	    addrServer->sin_addr=*((struct in_addr*)hostTemp->h_addr);
		addrServer->sin_port = htons(80);
	}
	return 1;
}

#define LEAD_MSG "M$A$G$I$C$"

int generate_lead_msg(char *buf,int len)
{
    char *msg = "sshd: uuid:12345,sn:abcdefg,ip:192.168.1.139";

    return snprintf(buf,len,"%s-%ld-%s",LEAD_MSG,strlen(msg)+strlen(LEAD_MSG)+1,msg);
}

void *start_agent(void *val)
{
    int sockfd = 0;
    int sockfd_sshd = 0;  
    int retRecv = 0;
    struct sockaddr_in server;
    struct sockaddr_in server_sshd;
    socklen_t len = sizeof(server);
    int opt = 1;
    int ret = 0;
    pthread_t threadId;
    fd_set rfds;
    struct timeval tv;
    char buf[4096] = {0};
    Network_t network;
    ConnectInfo_t connInfo;

    server_sshd.sin_family = PF_INET;
    server_sshd.sin_port = htons(22);
    server_sshd.sin_addr.s_addr = inet_addr("127.0.0.1");

    #ifdef USE_TCP
    sockfd = socket(PF_INET,SOCK_STREAM,0);
    if(sockfd == -1) {
        ERR("create socket  error :  %s\n",strerror(errno));
        return NULL;
    }   
    server.sin_family = PF_INET;
    server.sin_port = htons(LOCAL_PORT);
    server.sin_addr.s_addr = inet_addr(LOCAL_IP);

    if(connect(sockfd,(struct sockaddr *)&server,sizeof(server)) == -1){
        ERR("failed to connect to server %s .\n",strerror(errno));
        return NULL;
    }
    #else
    rd_net_init(&network, RD_NET_WEBSOCKET, LOCAL_IP, WB_LOCAL_PORT, NULL, NULL);
    ret = rd_net_connect(&network);
    if (0 != ret) {
        printf("create connect cloud failed\n");
        return NULL;
    }

    memset(&connInfo, 0x0, sizeof(ConnectInfo_t));
    ret = rd_net_get_conn_info(&network, NULL, &connInfo);
    if (0 == ret) {
        sockfd = connInfo.sockfd;
    }
    #endif

    ret = generate_lead_msg(buf,sizeof(buf));
    printf("sockfd: %d, ret: %d\n",sockfd,ret);
    #ifdef USE_TCP
    ret = send(sockfd,buf,ret+1,0);
    #else
    ret = rd_net_write(&network, NULL, buf, ret+1, 0);
    #endif
    INFO("succeed to connet to the remote server : %s, msg size: %d.\n",buf,ret);

    while (1) {

        FD_ZERO(&rfds);
        if (sockfd > 0)
            FD_SET(sockfd,&rfds);
        if(sockfd_sshd > 0)
            FD_SET(sockfd_sshd,&rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0L;
        
        ret = select(MAX_VAL(sockfd,sockfd_sshd)+1,&rfds,NULL,NULL,&tv);
        
        if(ret <= 0)
            continue;

        if(sockfd_sshd == 0){
            sockfd_sshd = socket(PF_INET,SOCK_STREAM,0);
            if(connect(sockfd_sshd,(struct sockaddr *)&server_sshd,sizeof(server)) == -1){
                ERR("failed to connect to server %s .\n",strerror(errno));
                return NULL;
            }
            printf("server msg is comming ,connecting to sshd : %d. \n",sockfd_sshd);
        }
        if(FD_ISSET(sockfd,&rfds)){
            memset(buf,0,sizeof(buf));
            #ifdef USE_TCP
            ret = recv(sockfd,buf,sizeof(buf),0);
            #else
            ret = rd_net_read(&network, NULL, buf, sizeof(buf), 0);
            #endif
            INFO("client msg comes from server ret %d\n",ret);
            if (ret > 0) {
                ret = send(sockfd_sshd,buf,ret,0);
                printf("resend to sshd: %d\n",ret); 
            }else{
                INFO("server exit\n");
                break;
            }
        }else if(FD_ISSET(sockfd_sshd,&rfds)){
            memset(buf,0,sizeof(buf));
            ret = recv(sockfd_sshd,buf,sizeof(buf),0);
            INFO("client msg comes from sshd ret %d, %x%x%x%x\n",ret,buf[0],buf[1],buf[2],buf[3]);
            if (ret > 0) {
                #ifdef USE_TCP
                ret = write(sockfd,buf,ret);
                #else
                ret = rd_net_write(&network, NULL, buf, ret, 0);
                #endif
                printf("resend to server: %d\n",ret); 
            }else{
                INFO("sshd exit \n");
                close(sockfd);
                close(sockfd_sshd);
                sockfd_sshd = 0;
                break;
            }
        }
    }
}

int main(void)
{
    signal(SIGPIPE,SIG_IGN);
    pthread_t threadId;
    pthread_create(&threadId,NULL,start_agent,NULL);
    
    pthread_join(threadId,NULL);
    
    return 0;
}
