/*
 * _watchdog_crc32.h
 *
 *  Created on: 2017年11月13日
 *      Author: Zhongyang
 */

#ifndef MODULES_WATCHDOG__WATCHDOG_CRC32_H_
#define MODULES_WATCHDOG__WATCHDOG_CRC32_H_

#include "_watchdog_includes.h"

#define WATCHDOG_CRC32_SEED     0xEDB88320

uint32_t _watchdog_crc32(const void *data, size_t length, uint32_t previousCrc32);
uint32_t _watchdog_crc32_u32(uint32_t data, uint32_t previousCrc32);
uint32_t _watchdog_crc32_u64(uint64_t data, uint32_t previousCrc32);
uint32_t _watchdog_crc32_ptr(ptrdiff_t data, uint32_t previousCrc32);

#endif /* MODULES_WATCHDOG__WATCHDOG_CRC32_H_ */
