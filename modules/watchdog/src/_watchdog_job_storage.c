/*
 * _watchdog_job_storage.c
 *
 *  Created on: 2017年11月14日
 *      Author: Zhongyang
 */

#include "_watchdog_includes.h"

static const char *gstr_jobqueue_fd = "watchdog_job_queue.json";

static int _watchdog_cp_small_file(const char *to, const char *from);
static int _watchdog_load_process_from_json(WatchdogProcess *process, const cJSON *json_process);
static char *_watchdog_create_dump_file_name(int *created_size);
static cJSON *_watchdog_load_json(const char *file_path);

int watchdog_load_process_list(WatchdogProcess *process_list)
{
    int i;
    if (NULL == process_list) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    char *dump_file = _watchdog_create_dump_file_name(NULL);
    if (NULL == dump_file) {
        return WATCHDOG_ERROR_NO_MEM;
    }

    cJSON *root = _watchdog_load_json(dump_file);
    if (root == NULL) {
        char dump_file_backup[FILENAME_MAX];
        snprintf(dump_file_backup, FILENAME_MAX, dump_file, ".backup");
        _watchdog_cp_small_file(dump_file, dump_file_backup);
        root = _watchdog_load_json(dump_file);
        if (root == NULL) {
            free(dump_file);
            return WATCHDOG_ERROR_IO;
        }
    }
    free(dump_file);
    dump_file = NULL;

    int process_count = cJSON_GetArraySize(root);
    if (process_count <= 0) {
        cJSON_Delete(root);
        return WATCHDOG_ERROR_UNKNOWN;
    }

    INIT_LIST_HEAD(&process_list->list_node);
    for (i = 0; i < process_count; ++i) {
        const cJSON *json_process = cJSON_GetArrayItem(root, i);
        if (NULL == json_process) {
            continue;
        }
        WatchdogProcess *process = watchdog_process_create();
        if (NULL == process) {
            continue;
        }
        if (WATCHDOG_ERROR_SUCEESS == _watchdog_load_process_from_json(process, json_process)) {
            list_add_tail(&process->list_node, &process_list->list_node);
        } else {
            watchdog_process_free(process);
        }
    }

    cJSON_Delete(root);

    return WATCHDOG_ERROR_SUCEESS;
}

static int _watchdog_load_thread_from_json(const cJSON *json_thread, WatchdogThread *thread)
{
    if ((NULL == json_thread) || (NULL == thread)) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    const cJSON *json_uuid = cJSON_GetObjectItem(json_thread, "UUID");
    const cJSON *json_ettk = cJSON_GetObjectItem(json_thread, "EpochTimeToKill");

    thread->UUID = json_uuid ? json_uuid->valuestring : "";
    thread->EpochTimeToKill.tv_sec = json_ettk ? json_ettk->valuedouble : 0;

    return WATCHDOG_ERROR_SUCEESS;
}

int watchdog_dump_process_list(WatchdogProcess *process_list)
{
    if (NULL == process_list) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    cJSON *root = cJSON_CreateArray();
    if (NULL == root) {
        return WATCHDOG_ERROR_NO_MEM;
    }

    WatchdogProcess *process = process_list;
    list_for_each_entry(process, &process_list->list_node, list_node) {
        cJSON *process_root = cJSON_CreateObject();
        cJSON *bus_unique_name = cJSON_CreateString(process->BusUniqueName);
        cJSON *cmdline = cJSON_CreateString(process->Cmdline);
        cJSON *cwd = cJSON_CreateString(process->CWD);
        cJSON *pid = cJSON_CreateNumber(process->PID);
        cJSON *killing = cJSON_CreateNumber(process->Killing);
        cJSON *thread_list_head = cJSON_CreateArray();

        if ((NULL == process_root) || (NULL == bus_unique_name) || (NULL == cmdline) || (NULL == cwd) || (NULL == pid)
            || (NULL == thread_list_head)
            || (NULL == killing)) {
            if (process_root) {
                cJSON_Delete(process_root);
            }
            if (bus_unique_name) {
                cJSON_Delete(bus_unique_name);
            }
            if (cmdline) {
                cJSON_Delete(cmdline);
            }
            if (cwd) {
                cJSON_Delete(cwd);
            }
            if (pid) {
                cJSON_Delete(pid);
            }
            if (thread_list_head) {
                cJSON_Delete(thread_list_head);
            }
            if (killing) {
                cJSON_Delete(killing);
            }
            continue;
        }

        cJSON_AddItemToObject(process_root, "BusUniqueName", bus_unique_name);
        cJSON_AddItemToObject(process_root, "Cmdline", cmdline);
        cJSON_AddItemToObject(process_root, "CWD", cwd);
        cJSON_AddItemToObject(process_root, "PID", pid);
        cJSON_AddItemToObject(process_root, "ThreadListHead", thread_list_head);
        cJSON_AddItemToObject(process_root, "Killing", killing);

        WatchdogThread *thread;
        list_for_each_entry(thread, &process->ThreadListHead.list_node, list_node) {
            cJSON *thread_root = cJSON_CreateObject();
            cJSON *uuid = cJSON_CreateString(thread->UUID);
            cJSON *wkn = cJSON_CreateString(thread->WellKnownName);
            cJSON *epoch_time_to_kill = cJSON_CreateNumber(thread->EpochTimeToKill.tv_sec);

            if ((NULL == thread_root) || (NULL == uuid) || (NULL == epoch_time_to_kill) || (NULL == wkn)) {
                if (thread_root) {
                    cJSON_Delete(thread_root);
                }
                if (uuid) {
                    cJSON_Delete(uuid);
                }
                if (epoch_time_to_kill) {
                    cJSON_Delete(epoch_time_to_kill);
                }
                if (wkn) {
                    cJSON_Delete(wkn);
                }
                continue;
            }

            cJSON_AddItemToObject(thread_root, "UUID", uuid);
            cJSON_AddItemToObject(thread_root, "EpochTimeToKill", epoch_time_to_kill);
            cJSON_AddItemToObject(thread_root, "WellKnownName", wkn);

            cJSON_AddItemToArray(thread_list_head, thread_root);
        }

        if (0 == cJSON_GetArraySize(thread_list_head)) {
            cJSON_Delete(process_root);
        } else {
            cJSON_AddItemToArray(root, process_root);
        }
    }

    if (cJSON_GetArraySize(root)) {
        char *dump_file = _watchdog_create_dump_file_name(NULL);
        if (dump_file && (strlen(dump_file) < (FILENAME_MAX -12))) {
            char dump_file_bak[FILENAME_MAX + 1];
            strcpy(dump_file_bak, dump_file);
            strcat(dump_file_bak, ".backup");

            if (0 == _watchdog_cp_small_file(dump_file_bak, dump_file)) {
                char *str_root = cJSON_Print(root);
                if (str_root) {
                    FILE *fh_dump_file = fopen(dump_file, "w");
                    if (fh_dump_file) {
                        size_t written = fwrite(str_root, strlen(str_root), 1, fh_dump_file);
                        fclose(fh_dump_file);
                        if (1 != written) {
                            _watchdog_cp_small_file(dump_file, dump_file_bak);
                        }
                    }
                    free(str_root);
                }
            }
            free(dump_file);
        }
        else if(dump_file) {
            free(dump_file);
        }
    }

    cJSON_Delete(root);

    return 0;
}

static char *_watchdog_create_dump_file_name(int *created_size)
{
    char *fn = (char *) malloc(FILENAME_MAX);
    if (fn) {
        ssize_t fn_str_len = readlink("/proc/self/exe", fn, FILENAME_MAX);
        if (fn_str_len < 0) {
            free(fn);
            return NULL;
        }
        fn[fn_str_len] = '\0';
        int last_backslash_pos = fn_str_len - 1;
        for (last_backslash_pos = fn_str_len - 1; last_backslash_pos >= 0; --last_backslash_pos) {
            if ('/' == fn[last_backslash_pos]) {
                break;
            }
        }
        fn[last_backslash_pos + 1] = '\0';
        strcat(fn, gstr_jobqueue_fd);

        if (created_size) {
            *created_size = FILENAME_MAX;
        }
    }
    return fn;
}

static int _watchdog_cp_small_file(const char *to, const char *from)
{
    FILE *fh_to, *fh_from;
    fh_from = fopen(from, "r");
    if (NULL == fh_from) {
        return 1;
    }

    fseek(fh_from, 0L, SEEK_END);
    ssize_t fh_from_size = ftell(fh_from);
    if (fh_from_size <= 0) {
        fclose(fh_from);
        return 1;
    }
    fseek(fh_from, 0L, SEEK_SET);

    fh_to = fopen(to, "w");
    if (NULL == fh_to) {
        fclose(fh_from);
        return 1;
    }

    char *buff = (char *) malloc(fh_from_size);
    if (NULL == buff) {
        fclose(fh_from);
        fclose(fh_to);
        return 2; // OOM;
    }

    int err_code = 3;
    if ((1 == fread(buff, fh_from_size, 1, fh_from))
        && (1 == fwrite(buff, fh_from_size, 1, fh_to))) {
        // succeeded
        err_code = 0;
    }

    fclose(fh_from);
    fclose(fh_to);
    free(buff);
    return err_code;
}

static int _watchdog_load_process_from_json(WatchdogProcess *process, const cJSON *json_process)
{
    if ((NULL == json_process) || (NULL == process)) {
        return WATCHDOG_ERROR_INVALID_PARAM;
    }

    const cJSON *json_thread_list = cJSON_GetObjectItem(json_process, "ThreadListHead");
    int list_count = cJSON_GetArraySize(json_thread_list);
    if (list_count <= 0) {
        return WATCHDOG_ERROR_INVALID_DATA;
    }

    const cJSON *json_bus_unique_name = cJSON_GetObjectItem(json_process, "BusUniqueName");
    const cJSON *json_cwd = cJSON_GetObjectItem(json_process, "CWD");
    const cJSON *json_cmdline = cJSON_GetObjectItem(json_process, "Cmdline");
    const cJSON *json_pid = cJSON_GetObjectItem(json_process, "PID");
    const cJSON *json_killing = cJSON_GetObjectItem(json_process, "Killing");

    process->BusUniqueName = json_bus_unique_name ? strdup(json_bus_unique_name->valuestring) : strdup("");
    process->CWD = json_cwd ? strdup(json_cwd->valuestring) : strdup("");
    process->Cmdline = json_cmdline ? strdup(json_cmdline->valuestring) : strdup("");
    process->PID = json_pid ? json_pid->valueint : ~0UL;
    process->Killing = json_killing ? json_killing->valueint : 0;
    INIT_LIST_HEAD(&process->ThreadListHead.list_node);

    int i;
    for (i = 0; i < list_count; ++i) {
        const cJSON *json_thread_item = cJSON_GetArrayItem(json_thread_list, i);
        if (NULL == json_thread_item) {
            continue;
        }
        WatchdogThread *thread = watchdog_thread_create();
        if (NULL == thread) {
            continue;
        }

        if (WATCHDOG_ERROR_SUCEESS == _watchdog_load_thread_from_json(json_thread_item, thread)) {
            list_add_tail(&thread->list_node, &process->ThreadListHead.list_node);
        } else {
            watchdog_thread_free(thread);
        }
    }

    if (list_empty(&process->ThreadListHead.list_node)) {
        watchdog_process_free(process);
        return WATCHDOG_ERROR_INVALID_DATA;
    }
    return WATCHDOG_ERROR_SUCEESS;
}

static cJSON *_watchdog_load_json(const char *file_path)
{
    cJSON *root = NULL;

    FILE *fh_json = fopen(file_path, "r");
    if (fh_json) {
        fseek(fh_json, 0, SEEK_END);
        ssize_t file_size = ftell(fh_json);
        if (file_size <= 0) {
            fclose(fh_json);
            return NULL;
        }

        char *buff = (char *) malloc(file_size);
        if (NULL == buff) {
            fclose(fh_json);
            return NULL;
        }

        if (1 == fread(buff, file_size, 1, fh_json)) {
            root = cJSON_Parse(buff);
        }
        free(buff);
        fclose(fh_json);
    }

    return root;
}

