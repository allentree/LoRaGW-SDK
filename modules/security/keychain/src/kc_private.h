#ifndef _KC_PRIVATE_H_
#define _KC_PRIVATE_H_

#include <sys/types.h>
#include <sys/shm.h>

#define SEC_WELL_KNOWN_NAME     "iot.gateway.security.keychain"
#define SEC_SST_OBJECT_PATH     "/iot/gateway/security/keychain"
#define SEC_SST_INTERFACE_NAME  "iot.gateway.security.keychain.sst"

#define KC_ADD_GLOBAL_ITEM         "kcAddGlobalKey"
#define KC_GET_GLOBAL_ITEM         "kcGetGlobalKey"
#define KC_DELETE_GLOBAL_ITEM         "kcDeleteGlobalKey"

#define KC_ADD_ITEM         "kcAddKey"
#define KC_GET_ITEM         "kcGetKey"
#define KC_UPDATE_ITEM      "kcUpdateKey"
#define KC_DELETE_ITEM      "kcDeleteKey"
#define KC_ENCRYPT_DATA     "kcEncryptData"
#define KC_DECRYPT_DATA     "kcDecryptData"

#define TAG "KeyChain"

#define KC_SHM_CREATE(size, shmid) \
    do { \
        shmid = shmget(IPC_PRIVATE, size, 0666); \
    } while(0)

#define KC_SHM_DESTROY(shmid) \
    do { \
        shmctl(shmid, IPC_RMID, NULL); \
    } while(0)

#define KC_SHM_MMAP(shmid, vaddr) \
    do { \
        vaddr = shmat(shmid, NULL, 0); \
        if (vaddr == (void *)-1) { \
            vaddr = NULL; \
        } \
    } while(0)

#define KC_SHM_MUNMAP(vaddr) \
    do { \
        shmdt(vaddr); \
    } while(0)

/* dbus error check & print */
#define dbus_error_parse(error)         \
    do { \
        if (dbus_error_is_set(&(error))) { \
            printf("%s(%d) dbus error (%s)\n", __FUNCTION__, __LINE__, (error).message); \
            dbus_error_free(&(error)); \
        } \
    } while (0)

#endif /*_KC_PRIVATE_H_ */

