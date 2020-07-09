#include <pthread.h>
#include "sshd_agent.h"
#include "rd_net.h"
#include "json_parser.h"
#include "misc.h"
#include "parser_ini.h"
#include "sha256.h"
#include "hmac-sha256.h"
#ifdef PLATFORM_Lora
#include "gwiotapi.h"
#endif
#include <sys/types.h>
#include <unistd.h>

#ifdef LOG_SUPPORT
#include "log.h"
#else
#define log_e(TAG,fmt,args...) printf(fmt,##args)
#define log_i(TAG,fmt,args...) printf(fmt,##args)
#define log_d(TAG,fmt,args...) printf(fmt,##args)
#define log_w(TAG,fmt,args...) printf(fmt,##args)
#endif

Network_t g_network;
int g_sockfd_sshd = 0;

#define MSG_HEAD_FMT "{\"msg_type\": %d,\"payload_len\": %d,\"msg_id\": %d,\"timestamp\":%ld,\"token\":\"%s\"}\r\n\r\n"
#define MSG_HDSK_FMT "{\"uuid\": \"%s\",\"product_key\": \"%s\",\"device_name\": \"%s\",\"version\":\"%s\",\"IP\":\"%s\",\"MAC\":\"%s\",\"token\":\"%s\", \"service_supported\": \"ssh\",\"signmethod\": \"hmacsha256\", \"sign\": \"%s\"}"

#define CFG_FILE_NAME   "remote_debug.ini"

static char g_cloud_ip[512] = {0};
static char g_cloud_port[64] = {0};
static char g_cert_path[FILENAME_MAX] = {0};
static char g_product_key[128] = {0};
static char g_device_name[128] = {0};
static char g_device_secret[128] = {0};
static int  g_is_tls_on = 0;
static int  g_listen_port = 22;
static int  g_keepalive_time = 30*60;

#define TAG_RDBG    "remote_debug"

void sig_int_handler(int sig);

static char *get_token()
{
    return "this_is_sshd_agent";
}

static char *sda_gen_msg_header(int msg_type, int msg_len)
{
    static char msg[1024] = {0};
    static unsigned int msg_id = 0;

    memset(msg,0,sizeof(msg));
    snprintf(msg,sizeof(msg),MSG_HEAD_FMT,
            msg_type,
            msg_len,
            ++msg_id,
            time(NULL),
            get_token());
    
    return msg;
}

static char *g_uuid = "_uuid";

#define HMAC_SHA256_BYTES 32

static char *calc_sign(char *uuid, char *dn, char *pk)
{
    static char *format = "clientId%sdeviceName%sproductKey%stimestamp%lu";
    static unsigned char msg[1024] = {0};
    uint8_t mac[HMAC_SHA256_BYTES];
    static char ret[1024] = {0};

    memset(msg, 0, sizeof(msg));
    memset(mac, 0, sizeof(mac));
    memset(ret, 0, sizeof(ret));

    snprintf((char *)msg, sizeof(msg), format, uuid, dn, pk, time(NULL));
    hmac_sha256(mac, msg, strlen((char *)msg), (unsigned char *)g_device_secret, strlen((char *)g_device_secret) + 1);
    int j = 0; 
    for (j = 0; j < HMAC_SHA256_BYTES; j++)
        sprintf(ret + strlen(ret), "%02x", mac[j]);
    
    return ret;
}

static char *sda_gen_lead_msg()
{
    static char msg[1024] = {0};
    char ipaddr[256] = {0};

    get_dev_ip(ipaddr, sizeof(ipaddr));

    memset(msg,0,sizeof(msg));
    snprintf(msg, sizeof(msg), MSG_HDSK_FMT, 
            g_uuid, 
            g_product_key,
            g_device_name, 
            "version_", 
            ipaddr, 
            "MAC_", 
            get_token(),
            calc_sign(g_uuid, g_device_name, g_product_key));

    return msg; 
}

static int sda_connect_to_cloud (void)
{
    int ret = 0;
    char *msg_hdsk = NULL;
    char *msg_hdr = NULL;
    char buf[4096] = {0};

    rd_net_init(&g_network, RD_NET_WEBSOCKET, 0, g_cloud_ip, g_cloud_port, NULL,g_is_tls_on , g_cert_path, NULL);

    ret = rd_net_connect(&g_network);
    if (0 != ret) {
        log_e(TAG_RDBG,"net connect failed\n");
        return ret;
    }

    msg_hdsk = sda_gen_lead_msg();
    msg_hdr =  sda_gen_msg_header(2,strlen(msg_hdsk));

    log_i(TAG_RDBG,"handshak msg:%s, len:%d\n", msg_hdsk, (int)strlen(msg_hdsk));
    log_i(TAG_RDBG,"header msg:%s, len:%d\n", msg_hdr, (int)strlen(msg_hdr));

    snprintf(buf,sizeof(buf),"%s%s",msg_hdr,msg_hdsk); 
    ret = rd_net_write(&g_network, NULL, buf, strlen(buf), 0);
    if (ret <= 0) {
        log_e(TAG_RDBG,"write data to cloud failed\n");
        return -1;
    }

    log_i(TAG_RDBG,"send msg handshake, len:%d\n", ret);

    return 0;
}

static int sda_connect_to_sshd (void)
{
    int ret = 0;
    struct sockaddr_in server_sshd;

    memset(&server_sshd, 0 , sizeof(struct sockaddr_in));

    server_sshd.sin_family = PF_INET;
    server_sshd.sin_port = htons(g_listen_port);
    server_sshd.sin_addr.s_addr = inet_addr("127.0.0.1");

    g_sockfd_sshd = socket(PF_INET, SOCK_STREAM, 0);
    if (-1 == g_sockfd_sshd) {
        log_e(TAG_RDBG,"create sshd socket failed, %s\n", strerror(errno));
        return -1;
    }

    ret = connect(g_sockfd_sshd, (struct sockaddr *)&server_sshd, sizeof(server_sshd));
    if (-1 == ret) {
        log_e(TAG_RDBG,"connect to sshd failed, %s\n", strerror(errno));
        return -1;
    }
    printf("connect to local sshd succeed.\n");
    return 0;
}

static int get_payload_len(char *buf, int *len_hdr)
{
    int first = 0;
    int second = 0;
    char *tmp = NULL;
    char *ret = NULL;
    int len = 0;

    if(!buf)
        return 0;

    tmp = strchr(buf,'{');
    if(tmp){
        first = tmp - buf; 
    }

    tmp = strchr(buf, '}');
    if(tmp){
        second = tmp - buf; 
    }

    ret = json_get_value_by_name(buf + first,
                                second - first + 1,
                                "payload_len",
                                &len,
                                NULL);
    if(ret){
        len = atoi(ret);  
        *len_hdr = second - first + sizeof("\r\n\r\n");
    }
    return len;
}

int sda_run_loop (void)
{
    int ret = 0;
    int sockfd = 0;
    char buf[4096] = {0};
    fd_set rfds;
    struct timeval tv;
    ConnectInfo_t connInfo;
    static int payload = 0;
    int len_hdr = 0;
    int tmp = 0;
    char *hdr = NULL;
    static int timeout = 0;
    ret = sda_connect_to_cloud();
    if (0 != ret) {
        log_e(TAG_RDBG,"connect to cloud failed\n");
        goto _exit;
    }

    memset(&connInfo, 0x0, sizeof(ConnectInfo_t));
    ret = rd_net_get_conn_info(&g_network, NULL, &connInfo);
    if (0 != ret) {
        log_e(TAG_RDBG,"get cloud connect info failed\n");
        goto _exit;
    }
    sockfd = connInfo.sockfd;
    log_i(TAG_RDBG,"connect to cloud success, socketfd: %d\n", sockfd);

    while (1) {

        FD_ZERO(&rfds);
        if (sockfd > 0) {
            FD_SET(sockfd, &rfds);
        }
        if (g_sockfd_sshd > 0) {
            FD_SET(g_sockfd_sshd, &rfds);
        }
        tv.tv_sec = 1;
        tv.tv_usec = 0L;

        ret = select(MAX_VAL(sockfd, g_sockfd_sshd) + 1, &rfds, NULL, NULL, &tv);

        if(timeout >= g_keepalive_time*60){
            log_i(TAG_RDBG,"timeout , we will close current session and exit.\n");
            sig_int_handler(SIGINT);
            break;
        }

        if (ret == 0) {
            log_i(TAG_RDBG,"timeout occured: %d\n",++timeout);
            continue;
        }else if(ret < 0){
            log_e(TAG_RDBG,"failed to select: %s\n", strerror(errno));
            break; 
        }
        if (g_sockfd_sshd == 0) {
            ret = sda_connect_to_sshd();
            if (0 != ret) {
                log_e(TAG_RDBG,"connect to sshd failed\n");
            } else {
                log_i(TAG_RDBG,"cloud msg is comming, connect to sshd: %d\n", g_sockfd_sshd);
            }
        }
        if (FD_ISSET(sockfd, &rfds)) {
            memset(buf, 0, sizeof(buf));
            len_hdr = 0;
            ret = rd_net_read(&g_network, NULL, buf, 
                                //payload == 0 ? sizeof(buf) : payload, 0);
                                sizeof(buf), 0);
            tmp  = get_payload_len(buf,&len_hdr);
            payload = (tmp == 0 ? payload : tmp);
            if (ret > 0) {
                timeout = 0;
                int total = ret -len_hdr;
                int n = 0, nwritten = 0;
                
                for (nwritten = 0; nwritten < total; nwritten +=n ) {
                    n = send(g_sockfd_sshd, buf + len_hdr + nwritten, total - nwritten, 0);
                    log_i(TAG_RDBG,"resend to sshd, len: %d, payload: %d\n", n, payload);
                    if (n == -1) {
                        log_i(TAG_RDBG,"resend to sshd FAILED, len: %d, payload: %d\n", n, payload);
                        break;
                    }
                }
            }else if(ret < 0){
                continue;
            }
        } else if(FD_ISSET(g_sockfd_sshd, &rfds)) {
            memset(buf, 0, sizeof(buf));
            ret = recv(g_sockfd_sshd, buf, 1024, 0);
            log_i(TAG_RDBG,"recv msg comes from sshd, len:%d\n", ret);
            if (ret > 0) {
                hdr = sda_gen_msg_header(4,ret);
                memmove(buf+strlen(hdr),buf,ret);
                memmove(buf,hdr,strlen(hdr));
                tmp = rd_net_write(&g_network, NULL, buf, ret + strlen(hdr), 0);
                log_i(TAG_RDBG,"resend to cloud, len:%d\n", tmp);
            } else {
                log_e(TAG_RDBG,"sshd exit\n");
                ret = 0;
                break;
            }
        }
    }

_exit:
    rd_net_destroy(&g_network);
    if (g_sockfd_sshd > 0) {
        close(g_sockfd_sshd);
        g_sockfd_sshd = 0;
    }

    return ret;
}

static void load_default_cfg()
{
    strcpy(g_cloud_port,"8081");
    strcpy(g_cloud_ip,"172.1.1.1");
    g_is_tls_on = 1; 
}
#ifdef PLATFORM_Lora
static int read_lora_authinfo(void)
{
    aliot_gw_auth_info_t auth_info;
    int rc = 0;

    memset(&auth_info, 0x0, sizeof(aliot_gw_auth_info_t));
    rc = aliot_gw_get_auth_info(&auth_info);
    if (0 != rc) {
        log_e(TAG_RDBG,"call gateway get auth info api error, %d!", rc);
        exit(0);
    }

    strncpy(g_device_name, auth_info.device_name, sizeof(g_device_name));
    strncpy(g_product_key, auth_info.product_key, sizeof(g_product_key));
    strncpy(g_device_secret, auth_info.device_secret, sizeof(g_device_secret));
    return 0;

}
#endif
static void read_config()
{
    char buff[FILENAME_MAX] = {0};
    char abs_path[FILENAME_MAX] = {0};
    int read_len = 0;
    char *tmp = NULL;

    read_len = readlink("/proc/self/exe", buff, FILENAME_MAX);
    if(read_len <= 0){
        printf("path read failed\n");
        exit(0);
    }
    tmp = strrchr(buff, '/');
    if(tmp){
        buff[tmp - buff]='\0';
    }
    
    snprintf(abs_path, FILENAME_MAX, "%s/%s", buff, CFG_FILE_NAME);
    snprintf(g_cert_path, FILENAME_MAX, "%s/root.pem", buff);
    if (True == parse_start(abs_path)) {
        get_key_string("remote_debug","cloud_ip",g_cloud_ip);
        get_key_string("remote_debug","cloud_port",g_cloud_port);
#ifdef PLATFORM_Lora
        read_lora_authinfo();

#else
        if(strlen(g_device_name) == 0 
                && strlen(g_product_key) == 0
                && strlen(g_device_secret) == 0){
            get_key_string("remote_debug","device_name",g_device_name);
            get_key_string("remote_debug","product_key",g_product_key);
            get_key_string("remote_debug","device_secret",g_device_secret);
        } 
#endif

        g_is_tls_on = get_one_value("remote_debug","tls_switch");
        g_listen_port = get_one_value("remote_debug","listen_port");
        g_keepalive_time = get_one_value("remote_debug","keepalive_time");
        
        parse_end();
    } else {
        load_default_cfg();
    }
    
    if(g_listen_port == 0)
        g_listen_port = 22;
    if(g_keepalive_time == 0)
        g_keepalive_time = 30;//30 minutes

    log_i(TAG_RDBG,"cloud ip: %s\n",g_cloud_ip);
    log_i(TAG_RDBG,"cloud port: %s\n",g_cloud_port);
    log_i(TAG_RDBG,"cert file path: %s\n",g_cert_path);
    log_i(TAG_RDBG,"tls switch: %d\n",g_is_tls_on);
    log_i(TAG_RDBG,"listen port: %d\n",g_listen_port);
    log_i(TAG_RDBG,"keepalive time: %d minutes\n",g_keepalive_time);
}



#ifdef ENABLE_SSHD_WATCHDOG
extern void *feed_watchdog(void *arg);
extern void cancel_feed_watchdog();
#endif

void sig_int_handler(int sig)
{
    if (sig) {
        log_i(TAG_RDBG, "Caught signal: %s, exiting..., %d\r\n", strsignal(sig), sig);
        if (SIGINT == sig) {
            log_i(TAG_RDBG, "we will exit...\r\n");
#ifdef ENABLE_SSHD_WATCHDOG
            cancel_feed_watchdog();
            sleep(1);
#endif
            exit(0);
        }
    }
}

void generate_pid_file()
{
    char cmd[512] = {0};
    log_i(TAG_RDBG, "current pid:  %d\n",getpid());
    
    snprintf(cmd, sizeof(cmd), "kill -2 `cat /tmp/sshd_agent.pid`");  
    system(cmd); 

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "echo \"%d\" > /tmp/sshd_agent.pid", getpid());
    system(cmd);
}

int main (int argc, char **argv)
{
    int times = 0;
#ifdef LOG_SUPPORT
    log_init("remote_debug",LOG_FILE_DB,LOG_LEVEL_DEBUG,LOG_MOD_VERBOSE);
    log_file_init("remote_debug", 3 , 1);
#endif
  
    struct sigaction sig_int;
    memset(&sig_int, 0, sizeof(struct sigaction));
    sigemptyset(&sig_int.sa_mask);
    sig_int.sa_handler = sig_int_handler;
    sigaction(SIGINT, &sig_int, NULL); 

    printf("./sshd_agent <device_name> <product_key> <secret>to setup pk/dn\n");

    if(argc == 4){
        strncpy(g_device_name, argv[1], sizeof(g_device_name));
        strncpy(g_product_key, argv[2], sizeof(g_product_key));
        strncpy(g_device_secret, argv[3], sizeof(g_device_secret));
       
        int i = 1; 
        for (i = 1; i < argc; i++){
            int j = strlen(argv[i]);  
            for (j = j - 1; j >= 0; j--){
                argv[i][j] = ' ';
            }  
        }  
    }else{
        log_i(TAG_RDBG, "we will read the confile file or NVRom\n"); 
#ifdef PLATFORM_DingDing  
        dingding_read_cloud_uuid(g_product_key, g_device_name, g_device_secret);
        log_i("read pk/dn from dingding nvrom pk: %s, dn: %s\n", g_product_key, g_device_name);
#endif
    }
    read_config();
#ifdef ENABLE_SSHD_WATCHDOG
    pthread_t id = 0;
    int ret = 0;
    ret = pthread_create(&id,NULL,feed_watchdog,NULL);
    if(ret != 0){
        log_e(TAG_RDBG,"faild to start watchdog\n"); 
    }    
#endif
    generate_pid_file();
    while(1) {
        sda_run_loop();
        log_i(TAG_RDBG,"reconnect: try %d times\n", times++);
        sleep(1);
    }
#ifdef LOG_SUPPORT
    log_destroy();
#endif
    return 0;
}

