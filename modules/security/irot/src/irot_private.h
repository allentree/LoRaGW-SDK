#ifndef _IROT_PRIVATE_H_
#define _IROT_PRIVATE_H_

#include <sys/types.h>
#include <sys/shm.h>

#define SEC_IROT_WELL_KNOWN_NAME     "iot.gateway.security.irot"
#define SEC_IROT_OBJECT_PATH         "/iot/gateway/security/irot"
#define SEC_IROT_INTERFACE_NAME      "iot.gateway.security.irot.km"

#define KM_GEN_KEY        "kmGenKey"
#define KM_IM_KEY         "kmImKey"
#define KM_EX_KEY         "kmExKey"
#define KM_ENVE_BEGIN     "kmEnveBegin"
#define KM_ENVE_UPDATE    "kmEnveUpdate"
#define KM_ENVE_FINISH    "kmEnveFinish"
#define KM_DEL_KEY        "kmDelKey"
#define KM_DEL_ALL        "kmDelAll"
#define KM_SIGN           "kmSign"
#define KM_VERIFY         "kmVerify"
#define KM_ASYM_ENCRYPT   "kmAsymEncrypt"
#define KM_ASYM_DECRYPT   "kmAsymDecrypt"
#define KM_MAC            "kmMac"
#define KM_CIPHER         "kmCipher"
#define KM_INIT           "kmInit"
#define KM_CLEANUP        "kmCleanup"
#define KM_GET_ID2        "kmGetId2"
#define KM_SET_ID2        "kmSetId2"
#define KM_GET_ATTEST     "kmGetAttest"

#define TAG "IRot"

#define UINT32_LEN sizeof(uint32_t)

#define IROT_SHM_CREATE(size, shmid) \
    do { \
        shmid = shmget(IPC_PRIVATE, size, 0666); \
    } while(0)

#define IROT_SHM_DESTROY(shmid) \
    do { \
        shmctl(shmid, IPC_RMID, NULL); \
    } while(0)

#define IROT_SHM_MMAP(shmid, vaddr) \
    do { \
        vaddr = shmat(shmid, NULL, 0); \
        if (vaddr == (void *)-1) { \
            vaddr = NULL; \
        } \
    } while(0)

#define IROT_SHM_MUNMAP(vaddr) \
    do { \
        shmdt(vaddr); \
    } while(0)

#define UINT_TO_BIN(data, buffer) \
        do { \
            (buffer)[0] = ((data) & 0xff000000) >> 24; \
            (buffer)[1] = ((data) & 0x00ff0000) >> 16; \
            (buffer)[2] = ((data) & 0x0000ff00) >> 8; \
            (buffer)[3] = (data) & 0x000000ff;        \
        } while(0);

#define BIN_TO_UINT(buffer) ((((uint8_t *)(buffer))[0] << 24) + \
                             (((uint8_t *)(buffer))[1] << 16) + \
                             (((uint8_t *)(buffer))[2] << 8) + \
                             ((uint8_t *)(buffer))[3])

/* dbus error check & print */
#define dbus_error_parse(error)         \
    do { \
        if (dbus_error_is_set(&(error))) { \
            printf("%s(%d) dbus error (%s)\n", __FUNCTION__, __LINE__, (error).message); \
            dbus_error_free(&(error)); \
        } \
    } while (0)

#endif /* _IROT_PRIVATE_H_ */

