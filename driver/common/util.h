//
// Created by Fazio on 2017/4/7.
//

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef WIN32
#include <windows.h>

#define z_sleep(x)		Sleep(x*1000)
#define z_msleep(x)		Sleep(x)
#else
#define z_sleep(x)		sleep(x)
#define z_msleep(x)		usleep(x*1000)
#endif

#if (!defined(WIN32) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))) \
    || (defined(WIN32) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)))
#ifndef bswap_16
#define    bswap_16(value)  \
     ((((value) & 0xff) << 8) | ((value) >> 8))
#define bswap_32 __builtin_bswap32
#define bswap_64 __builtin_bswap64
#endif
#else
#if HAVE_BYTESWAP_H
#include <byteswap.h>
#elif defined(USE_SYS_ENDIAN_H)
#include <sys/endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#else
#define bswap_16(value)  \
    ((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
    (((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
    (uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define bswap_64(value) \
    (((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
        << 32) | \
    (uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif
#endif /* !defined(__GLXBYTEORDER_H__) */

#ifndef bswap_8
extern unsigned char bit_swap_table[256];
#define bswap_8(x) (bit_swap_table[x])
#endif

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

/* This assumes htobe32 is a macro in endian.h, and if it doesn't exist, then
 * htobe64 also won't exist */
#ifndef htobe32
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htole8(x) (x)
#  define htole16(x) (x)
#  define htole32(x) (x)
#  define le32toh(x) (x)
#  define be32toh(x) bswap_32(x)
#  define be64toh(x) bswap_64(x)
#  define htobe32(x) bswap_32(x)
#  define htobe64(x) bswap_64(x)
# elif __BYTE_ORDER == __BIG_ENDIAN
#  define htole8(x) bswap_8(x)
#  define htole16(x) bswap_16(x)
#  define htole32(x) bswap_32(x)
#  define le32toh(x) bswap_32(x)
#  define be32toh(x) (x)
#  define be64toh(x) (x)
#  define htobe32(x) (x)
#  define htobe64(x) (x)
#else
#error UNKNOWN BYTE ORDER
#endif

#else

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htole8(x) (x)
# elif __BYTE_ORDER == __BIG_ENDIAN
#  define htole8(x) bswap_8(x)
#else
#error UNKNOWN BYTE ORDER
#endif

#endif

unsigned char CRC5(unsigned char *ptr, unsigned char len);
void hexdump(const unsigned char *p, unsigned int len);
//char *bin2hex(const unsigned char *p, size_t len);
int _hex2bin(unsigned char *p, const char *hexstr, size_t len);
unsigned char swap_bit(unsigned char chr);
void dump_str(FILE *fd, const char *func, unsigned char *str, int len);
unsigned char bit_read(unsigned char * y, int x);

#endif //TEST_CLIENT_UTIL_H
