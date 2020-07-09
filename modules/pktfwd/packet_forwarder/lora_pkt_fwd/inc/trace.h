/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    LoRa concentrator : Packet Forwarder trace helpers

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Michael Coracin
*/


#ifndef _LORA_PKTFWD_TRACE_H
#define _LORA_PKTFWD_TRACE_H

/* Begin add for remote log */
#if defined(ENABLE_REMOTE_LOG)
#include "log.h"
#endif
/* End */

#define DEBUG_PKT_FWD   0
#define DEBUG_JIT       0
#define DEBUG_JIT_ERROR 1
#define DEBUG_TIMERSYNC 0
#define DEBUG_BEACON    1
#define DEBUG_LOG       1

/* Begin add for remote log */
#if defined(ENABLE_REMOTE_LOG)
#define MSG(args...) log_i(NULL, args)
#define MSG_DEBUG(FLAG, fmt, ...)                                                                         \
            do  {                                                                                         \
                if (FLAG)                                                                                 \
                    log_d(NULL, fmt, ##__VA_ARGS__);                                                      \
            } while (0)
#else
#define MSG(args...) printf(args) /* message that is destined to the user */
#define MSG_DEBUG(FLAG, fmt, ...)                                                                         \
            do  {                                                                                         \
                if (FLAG)                                                                                 \
                    fprintf(stdout, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
            } while (0)
#endif
/* End */

#endif
/* --- EOF ------------------------------------------------------------------ */
