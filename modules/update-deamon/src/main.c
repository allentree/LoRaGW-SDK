#include <getopt.h>
#include <string.h>
#include <signal.h>

#include "update_global.h"
#include "update_ipc_local.h"
#include "exports/iot_export_ota.h"
#include "ota_utils.h"
#include "sysconfig.h"

#ifdef ENABLE_WATCHDOG
#include "watch_dog_export.h"

#endif

#define SIGNAL_REQUIRE_EXIT_VALID 0x5aa5

#define MAX_DOWNLOAD_WAIT_TIME (60*60)
static int download_time = 0;

int g_signal_require_exit = 0;
update_global_st g_update; 

static int update_state_rollback_to_idle(int report_ver);

void sig_int_handler(int sig)
{
    if (sig) {
        log_err( "Caught signal: %s, exiting...\r\n", strsignal(sig));
        if (SIGINT == sig || SIGTERM == sig) {
            if (SIGNAL_REQUIRE_EXIT_VALID == g_signal_require_exit) {
                exit(0);
            }
            g_signal_require_exit = SIGNAL_REQUIRE_EXIT_VALID;
            if(g_update.ota_state == OTA_STATE_WRITTING) {
                //在写文件系统的状态下，
                //set_ota_state(OTA_STATE_CHECKING);
                log_info("update-deamon is exiting");
                system("sync");
            }
        }
    }
}
//delete all ota files and free the memory
int update_state_rollback_to_idle(int report_ver)
{
    char cmd[FILENAME_MAX + 1] = { 0 };
    char cmd_ret[1024] = { 0 };

    //rm the download ota files
    if(g_update.ota_package.ota_file_path) {
        if(access(g_update.ota_package.ota_file_path, F_OK) == 0) {
            sprintf(cmd, "rm -rf %s" , g_update.ota_package.ota_file_path);
            if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
                log_err("exe cmd %s failed!!!", cmd);
                return -1;
            }
            else {
                log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
            }
        }
        free((void *)g_update.ota_package.ota_file_path);
        g_update.ota_package.ota_file_path = NULL;
    }
    //rm all files in OTA_STORE_DIR
    cmd_ret[0]='\0';
    sprintf(cmd, "rm -rf %s*" , OTA_STORE_DIR);
    if(ota_exe_cmd(cmd, cmd_ret, 1024 ) < 0 ) {
        log_err("exe cmd %s failed!!!", cmd);
        return -1;
    }
    else {
        log_info("exe cmd %s success ret %s!!!", cmd, cmd_ret);
    }
    //free the package path
    if(g_update.ota_package.package_path) {
        free((void *)g_update.ota_package.package_path);
        g_update.ota_package.package_path = NULL;
    }
    //free the all path in ota_package
    if(g_update.ota_package.sign_path) {
        free((void *)g_update.ota_package.sign_path);
        g_update.ota_package.sign_path = NULL;
    }
    if(g_update.ota_package.ota_update) {
        free((void *)g_update.ota_package.ota_update);
        g_update.ota_package.ota_update = NULL;
    }
    if(g_update.ota_package.ota_rollback) {
        free((void *)g_update.ota_package.ota_rollback);
        g_update.ota_package.ota_rollback = NULL;
    }
    if(g_update.ota_package.ota_update_done) {
        free((void *)g_update.ota_package.ota_update_done);
        g_update.ota_package.ota_update_done = NULL;
    }
    if(g_update.ota_package.ota_info_path) {
        free((void *)g_update.ota_package.ota_info_path);
        g_update.ota_package.ota_info_path = NULL;
    }

    //free the ota_info
    if(g_update.ota_info.current_ver) {
        free((void *)g_update.ota_info.current_ver);
        g_update.ota_info.current_ver = NULL;
    }
    if(g_update.ota_info.manufacturer) {
        free((void *)g_update.ota_info.manufacturer);
        g_update.ota_info.manufacturer = NULL;
    }
    if(g_update.ota_info.hw_version) {
        free((void *)g_update.ota_info.hw_version);
        g_update.ota_info.hw_version = NULL;
    }
    if(g_update.ota_info.depend_version) {
        free((void *)g_update.ota_info.depend_version);
        g_update.ota_info.depend_version = NULL;
    }

    //free ota download info 
    if(g_update.ota_download_info.ver) {
        free((void *)g_update.ota_download_info.ver);
        g_update.ota_download_info.ver = NULL;
    }
    if(g_update.ota_download_info.md5) {
        free((void *)g_update.ota_download_info.md5);
        g_update.ota_download_info.md5 = NULL;
    }
    g_update.ota_download_info.fileSize = 0;


    g_update.is_ota_file_checked = 0;
    g_update.sign_valid = 0;
    g_update.sh_valid = 0;
    g_update.ver_valid = 0;
    g_update.enable_multi_rootfs = 0;

    memset(&g_update.ota_check, 0 , sizeof(ota_update_check_st));

    if(report_ver)
        g_update.ver_reported = 0;
    else
        g_update.ver_reported = 1;
    

    set_ota_state(OTA_STATE_IDLE);
    
    return 0;
}

static int call_kill_watchdog() {
    char cmd_ret[1024] = { 0 };
    if(ota_exe_cmd("pkill watch_dog", cmd_ret, 1024) < 0) {
        log_err("call cmd : pkill watch_dog failed!!");
        return -1;
    }
    else {
        log_info("call cmd : pkill watch_dog success , return %s !", cmd_ret);
    }
    return 0;
}
static void update_show_usage(void)
{
    printf(
        "Usage: monitor [OPTIONS]\n\n"
        "  -h, --help                      Show help info\n"
        "  -v, --version                   Display version\n"
    );
}

static struct option arg_options[] = {
    {"version",     no_argument,            0, 'v'},
    {"help",        no_argument,            0, 'h'},
    {0, 0, 0, 0}
};

int main(int argc, const char **argv)
{
    int ret = 0;
    char filePath[FILENAME_MAX + 1];
    //static int running_check = 0;

    if (geteuid() != 0) {
        printf("Please run as root (with sudo). exiting now\r\n");
        exit(-1);
    }

    // 忽略子进程的结束信号
    /*
    struct sigaction sig_sigchld;
    memset(&sig_sigchld, 0, sizeof(struct sigaction));
    sigemptyset(&sig_sigchld.sa_mask);
    sig_sigchld.sa_handler = SIG_IGN;
    sigaction(SIGCHLD, &sig_sigchld, NULL);
*/
    while (1) {
        int c;
        int option_index = 0;
        c = getopt_long(argc, argv, "vh", arg_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                update_show_usage();
                return 0;

            case 'v':
            #define UPDATE_VERSION "1.0.0"
                printf("update-deamon version: %s\n", UPDATE_VERSION);
                return 0;

            default:
                update_show_usage();
                return -1;
        }
    }

    // 响应 SIGINT。
    struct sigaction sig_int;
    memset(&sig_int, 0, sizeof(struct sigaction));
    sigemptyset(&sig_int.sa_mask);
    sig_int.sa_handler = sig_int_handler;
    sigaction(SIGINT, &sig_int, NULL);

    sigaction(SIGTERM, &sig_int, NULL);

    #if defined(ENABLE_REMOTE_LOG)
    log_init(UPDATE_TAG, LOG_FILE, LOG_LEVEL_DEBUG, LOG_MOD_VERBOSE);
    log_file_init(UPDATE_TAG, 5 , 1);
    #endif
    memset(&g_update, 0 , sizeof(g_update));

    #if 0
    if(argc > 1) {
        //todo : for multi rootfs
        //getopt
        exit(1);
    }
    #endif

    g_update.enable_multi_rootfs = 0;
    
    pthread_mutex_init(&g_update.lock, NULL);

    ret = aliot_gw_get_device_info(&g_update.dev_info);
    if(ret < 0) {
        log_err("get device info failed!!!\n");
        log_err("exit!!!\n");
        exit(-1);
    }
    g_update.cur_ota_ver =  config_get_ota_version();
    if(g_update.cur_ota_ver == NULL) {
        log_err("get current ota info failed!!!\n");
        log_err("exit!!!\n");
        exit(-1);
    }
    log_info("device_info :\n gateway_eui: %s \n model: %s \n manufacturer: %s\n hw_version: %s\n sw_version: %s\n current ota version: %s\n", g_update.dev_info.gateway_eui,\
                   g_update.dev_info.model , g_update.dev_info.manufacturer, \
                    g_update.dev_info.hw_version, g_update.dev_info.sw_version, g_update.cur_ota_ver);
    
  
    //public key store 
    ret = get_realpath_by_exec_dir(filePath, OTA_PACKAGE_PUBLIC_KEY_NAME);
    if(ret < 0) {
        log_err("failed to get public key path!");
        exit(-1);
    }
    if(access(filePath, F_OK|R_OK) < 0) {
        log_err("ota public key files not exit in OTA packages");
        exit(-1);
    }
    //g_update.public_key_path = strdup(filePath);
    strcpy(g_update.public_key_path, filePath);
    //todo : check the disk's free space
     /*
    ret = get_realpath_by_exec_dir(filePath, "./ota.tar.gz");
    if(ret < 0 )
    {
        log_err("failed to get project root!!!\n")
        goto error1;
    }
    g_update.ota_package.ota_file_path = strdup(filePath);
*/
    ret = update_dbus_setup();
    if(ret != LORA_IPC_SUCCESS) {
        log_err("setup dbus error!!! exit!!!");
        exit(-1);
    }

    ret = get_ota_state(&g_update.ota_state);
    if(ret < 0)
    {
        log_err("get current ota state failed!!!\n");
        log_info("set current state to IDLE!!!\n");
        set_ota_state(OTA_STATE_IDLE);
    }
    log_info("OTA state is %d !!!", g_update.ota_state);

    if(g_update.ota_state != OTA_STATE_IDLE) {
        log_info("reboot form state %d, recovery the update context!",g_update.ota_state);
        ret = load_ota_state_after_reboot(g_update.ota_state);
        if(ret < 0) {
            log_err("recovery from state %s failed!!! rollback to idle!",g_update.ota_state);
            update_state_rollback_to_idle(1);
        }
    }

#if defined(ENABLE_WATCHDOG)
	struct timespec watchdog_time_keeper;
	clock_gettime(CLOCK_MONOTONIC, &watchdog_time_keeper);
#endif
    while(!g_signal_require_exit)
    {
        #if defined(ENABLE_WATCHDOG)
        if (thread_feeddog_periodically(UPDATE_SYMBOL, "main_thread", 60, 600, &watchdog_time_keeper) < 0) {
			log_err("OTA thread feeddog failed\n");
		}
        #endif
        switch(g_update.ota_state)
        {
            case OTA_STATE_IDLE:
                if(!g_update.ver_reported) {
                    log_info("trying report current software version to server!!!");
                    ret = update_report_ota_ver_to_server(g_update.cur_ota_ver);
                    if(ret != LORA_IPC_SUCCESS) {
                        log_err("report current version failed ret %d !!! retry !", ret);
                        sleep(5); 
                    }
                    else {
                        log_info("report current version %s to server successful!", g_update.cur_ota_ver);
                        g_update.ver_reported = 1;
                        sleep(5);
                    }
                }
                else {
                    sleep(5);
                }
                download_time = 0;
            break;
            case OTA_STATE_DOWNLOADING:
                log_info("downloading ota packages to %s ...", g_update.ota_package.ota_file_path);
                sleep(1);
                if(download_time++ > MAX_DOWNLOAD_WAIT_TIME) {
                    log_err("downloading %s timeout in %d senconds!", g_update.ota_package.ota_file_path, MAX_DOWNLOAD_WAIT_TIME);
                    sleep(1);
                    update_state_rollback_to_idle(1);
                }
            break;

            case OTA_STATE_VERIFIING:
                log_info("verifing ota packages ...");
                ota_report_process_state(50, "ota package downloading done");
                if(!g_update.is_ota_file_checked) {
                    ret = unpackage_ota_package(&g_update.ota_package);
                    if(ret < 0) {
                        log_err("unpackage the ota files failed!!!");
                        ota_report_process_state(IOT_OTAP_CHECK_FALIED, "unpackage the files failed! please check the files");
                        sleep(1);
                        update_state_rollback_to_idle(1);
                        break;
                    }
                    log_info("unpackage the ota files successful, packages : %s, sign : %s, now start check the packages!!");
                    ret = check_ota_package_files(&g_update.ota_package);
                    if(ret < 0) {
                        log_err("check the ota files failed!!!");
                        if(!g_update.sign_valid) {
                             ota_report_process_state(IOT_OTAP_CHECK_FALIED, "the sign check failed!! please check the sign!");
                        }
                        if(!g_update.sh_valid) {
                             ota_report_process_state(IOT_OTAP_CHECK_FALIED, "the update shell check failed!! please check the files!");
                        }
                        sleep(1);
                        update_state_rollback_to_idle(1);
                        break;
                    }
                    ret = check_ota_dependment(&g_update.ota_package);
                    if(ret < 0) {
                        log_err("check ota dependmet error, current version %s , depend version %s!!!", \
                                    g_update.cur_ota_ver, g_update.ota_info.depend_version);
                        ota_report_process_state(IOT_OTAP_CHECK_FALIED, "dependment check failed!! !");
                        sleep(1);
                        update_state_rollback_to_idle(1);
                        break;
                    }
                    ret = parse_ota_files_from_jcson(&g_update.ota_package);
                    if( ret < 0) {
                        log_err("parse the ota files failed, current version %s !!!", \
                                    g_update.cur_ota_ver);
                        ota_report_process_state(IOT_OTAP_CHECK_FALIED, "parse the jscon and files failed! please check the files");
                        sleep(1);
                        update_state_rollback_to_idle(1);
                        break;
                    }

                    g_update.is_ota_file_checked = 1;
                    set_ota_state(OTA_STATE_WRITTING);
                }
                else {
                    if(g_update.sign_valid && g_update.sh_valid && g_update.ver_valid) {
                        set_ota_state(OTA_STATE_WRITTING);
                    }
                    else {
                        log_err("package's check reslut sign_valid %d,shell valid %d, version valid %d ", \
                                    g_update.sign_valid,  g_update.sh_valid , g_update.ver_valid);
                        ota_report_process_state(IOT_OTAP_CHECK_FALIED, "check ota files failed!");
                        sleep(1);
                        update_state_rollback_to_idle(1);
                        break;      
                    }
                }
            break;
            case OTA_STATE_WRITTING:
                //kill the watchdog: we have 45-60S for writing the ota package,then system will reboot
                ret = call_kill_watchdog();
                if(ret < 0) {
                    log_err("kill watchdog failed!!!");
                    ota_report_process_state(IOT_OTAP_BURN_FAILED, "updating files failed!");
                    sleep(1);
                    update_state_rollback_to_idle(1);
                    break;
                }
                ota_report_process_state(70, "verify done");

                pthread_mutex_lock(&g_update.lock);
                g_update.ota_check.check_time = 0;
                g_update.ota_check.pktfwd_check_state = 0;
                g_update.ota_check.mqtt_check_state = 0;
                pthread_mutex_unlock(&g_update.lock);

                ret = call_ota_update(&g_update.ota_package);
                if(ret < 0) {
                    log_err("call update shell failed");
                    ota_report_process_state(IOT_OTAP_BURN_FAILED, "updating files failed!");
                    sleep(1);
                    update_state_rollback_to_idle(1);
                    break;
                }
                log_info("%s done, setting the state to checking, will reboot system now!!!");
                set_ota_state(OTA_STATE_CHECKING);
                system("sync");
                sleep(1);
                system("reboot");

            break;
            case OTA_STATE_CHECKING:
            #if 0
                running_check = 0;
                while(!query_major_process_running_state()) {
                    running_check ++;
                    if( running_check >  OTA_SELF_CHECKING_MAX_WAIT_TIME/10) {
                        break;
                    }
                }

                if(running_check > OTA_SELF_CHECKING_MAX_WAIT_TIME/10) {
                    log_err("major process check failed!!");
                    ota_report_process_state(IOT_OTAP_BURN_FAILED, "ota self-checking failed!");
                    ret = call_ota_rollback(&g_update.ota_package);
                    if(ret < 0) {
                        log_err("ota rollback failed!!!");
                        
                        ota_report_process_state(IOT_OTAP_BURN_FAILED, "ota rollback failed!");
                        sleep(1);
                        update_state_rollback_to_idle(1);
                    }
                    sleep(1);
                    update_state_rollback_to_idle(1);
                    log_info("ota process rollback done, will reboot systen now!!");
                    sleep(1);
                    system("reboot");

                }
                else {
                    log_info("start lora gateway self-checking!");
                }
#endif
                sleep(1);
                pthread_mutex_lock(&g_update.lock);
                g_update.ota_check.check_time ++;
#if defined(ENABLE_MONITOR) 
                if(query_major_process_running_state() && g_update.ota_check.mqtt_check_state \
                    && g_update.ota_check.pktfwd_check_state \
                        && g_update.ota_check.monitor_check_state ) 
#else
                if(query_major_process_running_state() && g_update.ota_check.mqtt_check_state \
                    && g_update.ota_check.pktfwd_check_state  ) 
#endif 
                {
                    pthread_mutex_unlock(&g_update.lock);
                    set_ota_state(OTA_STATE_DONE);
                    g_update.ota_check.check_time = 0;
                    ota_report_process_state(90, "ota self-checking done!");
                    break;
                }
                if(g_update.ota_check.check_time > OTA_SELF_CHECKING_MAX_WAIT_TIME) {
                    pthread_mutex_unlock(&g_update.lock);
#if defined(ENABLE_MONITOR) 
                    log_err("self-checking timeout!!!, pktfwd check state %d, mqtt check state %d , monitor check state %d \nwill rollback to last version", \
                                g_update.ota_check.pktfwd_check_state, g_update.ota_check.mqtt_check_state, g_update.ota_check.monitor_check_state );
#else
                    log_err("self-checking timeout!!!, pktfwd check state %d, mqtt check state %d! \nwill rollback to last version", \
                                g_update.ota_check.pktfwd_check_state, g_update.ota_check.mqtt_check_state );
#endif                                
                    ota_report_process_state(IOT_OTAP_BURN_FAILED, "ota self-checking failed!");
                    ret = call_ota_rollback(&g_update.ota_package);
                    if(ret < 0) {
                        log_err("ota rollback failed!!!");
                        ota_report_process_state(IOT_OTAP_BURN_FAILED, "ota rollback failed!");
                        sleep(1);
                        update_state_rollback_to_idle(1);
                    }
                    else {
                        sleep(1);
                        update_state_rollback_to_idle(1);
                        log_info("ota process rollback done, will reboot systen now!!");
                    }
                    sleep(1);
                    system("reboot");
                    break;
                }

                pthread_mutex_unlock(&g_update.lock);
            break;
            case OTA_STATE_DONE:
                log_info("ota done ! : store the new version to gateway %s !", g_update.ota_info.current_ver );
                ret = config_set_ota_version(g_update.ota_info.current_ver);
                if(ret < 0) {
                    log_err("failed to save current ota version!!!");
                    ota_report_process_state(IOT_OTAP_BURN_FAILED, "save new ota version failed!");
                    sleep(1);
                    call_ota_rollback(&g_update.ota_package);
                    sleep(1);
                    update_state_rollback_to_idle(1);
                    sleep(1);
                    system("reboot");
                    break;
                }
                ret = call_ota_update_done(&g_update.ota_package);
                if(ret < 0) {
                    log_err("failed to delete the backup files!!!");
                }

                g_update.cur_ota_ver = config_get_ota_version();
                
                ota_report_process_state(100, "ota done!");
                update_state_rollback_to_idle(1);
                
            break;  
            default :
                log_err("invalid state in update !!! rollbakc to IDLE state");
                update_state_rollback_to_idle(1);
            break;

        }

    }

    log_info("update-deamon exit!");

    if(g_update.ota_package.ota_file_path) {
        free((void *)g_update.ota_package.ota_file_path);
        g_update.ota_package.ota_file_path = NULL;
    }
     if(g_update.ota_package.package_path) {
        free((void *)g_update.ota_package.package_path);
        g_update.ota_package.package_path = NULL;
    }
    //free the all path in ota_package
    if(g_update.ota_package.sign_path) {
        free((void *)g_update.ota_package.sign_path);
        g_update.ota_package.sign_path = NULL;
    }
    if(g_update.ota_package.ota_update) {
        free((void *)g_update.ota_package.ota_update);
        g_update.ota_package.ota_update = NULL;
    }
    if(g_update.ota_package.ota_rollback) {
        free((void *)g_update.ota_package.ota_rollback);
        g_update.ota_package.ota_rollback = NULL;
    }
    if(g_update.ota_package.ota_update_done) {
        free((void *)g_update.ota_package.ota_update_done);
        g_update.ota_package.ota_update_done = NULL;
    }
    if(g_update.ota_package.ota_info_path) {
        free((void *)g_update.ota_package.ota_info_path);
        g_update.ota_package.ota_info_path = NULL;
    }

    //free the ota_info
    if(g_update.ota_info.current_ver) {
        free((void *)g_update.ota_info.current_ver);
        g_update.ota_info.current_ver = NULL;
    }
    if(g_update.ota_info.manufacturer) {
        free((void *)g_update.ota_info.manufacturer);
        g_update.ota_info.manufacturer = NULL;
    }
    if(g_update.ota_info.hw_version) {
        free((void *)g_update.ota_info.hw_version);
        g_update.ota_info.hw_version = NULL;
    }
    if(g_update.ota_info.depend_version) {
        free((void *)g_update.ota_info.depend_version);
        g_update.ota_info.depend_version = NULL;
    }

    //free ota download info 
    if(g_update.ota_download_info.ver) {
        free((void *)g_update.ota_download_info.ver);
        g_update.ota_download_info.ver = NULL;
    }
    if(g_update.ota_download_info.md5) {
        free((void *)g_update.ota_download_info.md5);
        g_update.ota_download_info.md5 = NULL;
    }

    pthread_mutex_destroy(&g_update.lock);
    update_dbus_exit();
#if defined(ENABLE_REMOTE_LOG)
    log_destroy();
#endif
    return 0;
}
