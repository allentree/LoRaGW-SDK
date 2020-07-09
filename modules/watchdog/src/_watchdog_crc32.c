/*
 * _watchdog_crc32.c
 *
 * Uses CRC32 (Ethernet) .
 * Seed is Reversed (0xEDB88320)
 *
 * http://create.stephan-brumme.com/crc32/#half-byte
 *
 * half byte lookup
 *
 *  Created on: 2017年11月13日
 *      Author: Zhongyang
 */

#include "_watchdog_includes.h"

static uint32_t lut[16] = {
    0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
    0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C, 0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
};

uint32_t _watchdog_crc32(const void *data, size_t length, uint32_t previousCrc32)
{
    uint32_t crc = ~previousCrc32;
    unsigned char *current = (unsigned char *) data;
    while (length--) {
        crc = lut[(crc ^ *current) & 0x0F] ^ (crc >> 4);
        crc = lut[(crc ^ (*current >> 4)) & 0x0F] ^ (crc >> 4);
        current++;
    }
    return ~crc;
}
uint32_t _watchdog_crc32_ptr(ptrdiff_t data, uint32_t previousCrc32)
{
    return _watchdog_crc32(&data, sizeof(data) / sizeof(char), previousCrc32);
}

uint32_t _watchdog_crc32_u64(uint64_t data, uint32_t previousCrc32)
{
    return _watchdog_crc32(&data, 8, previousCrc32);

}
uint32_t _watchdog_crc32_u32(uint32_t data, uint32_t previousCrc32)
{
    return _watchdog_crc32(&data, 4, previousCrc32);
}


