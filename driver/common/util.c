//
// Created by Fazio on 2017/4/7.
//
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/time.h>
#include "logging.h"
#include "util.h"

#ifndef unlikely
#define unlikely(expr) (expr)
#endif
#ifdef likely
#define likely(expr) (expr)
#endif

void __bin2hex(char *s, const unsigned char *p, size_t len)
{
	int i;
	static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	for (i = 0; i < (int)len; i++)
	{
		*s++ = hex[p[i] >> 4];
		*s++ = hex[p[i] & 0xF];
	}
	*s++ = '\0';
}

/* Returns a malloced array string of a binary value of arbitrary length. The
* array is rounded up to a 4 byte size to appease architectures that need
* aligned array  sizes */
static char *bin2hex(const unsigned char *p, size_t len)
{
	size_t slen;
	char *s;

	slen = len * 2 + 1;
	if (slen % 4)
		slen += 4 - (slen % 4);
	s = (char *)calloc(slen, 1);
	if (unlikely(!s))
		fprintf(stderr, "%s", "Failed to calloc");

	__bin2hex(s, p, len);

	return s;
}

static const int hex2bin_tbl[256] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/* Does the reverse of bin2hex but does not allocate any ram */
int _hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	int nibble1, nibble2;
	unsigned char idx;
	int ret = 0;

	while (*hexstr && len)
	{
		if (unlikely(!hexstr[1]))
		{
			return ret;
		}

		idx = *hexstr++;
		nibble1 = hex2bin_tbl[idx];
		idx = *hexstr++;
		nibble2 = hex2bin_tbl[idx];

		if (unlikely((nibble1 < 0) || (nibble2 < 0)))
		{
			return ret;
		}

		*p++ = (((unsigned char)nibble1) << 4) | ((unsigned char)nibble2);
		--len;
	}

	if (likely(len == 0 && *hexstr == 0))
		ret = 1;
	return ret;
}

unsigned char swap_bit(unsigned char chr)
{
    unsigned char ret = 0;

    for(int i=0; i<8; i++)
    {
        if ((chr & (1 << i)) != 0) {
            ret |= 1 << (7 - i);
        }
    }

    return ret;
}

void dump_str(FILE *fd, const char *func, unsigned char *str, int len)
{
    char *hexbuff;
    hexbuff = bin2hex(str, len);
    if (func == NULL) {
        fprintf(fd, "%s\n", hexbuff);
    } else {
        fprintf(fd, "%s %s\n", func, hexbuff);
    }
    fflush(fd);
    free(hexbuff);
}

unsigned char bit_read(unsigned char * y, int x)
{
    switch (x%8)
    {
        case 0:
            return y[x/8] & 0x01 ? 1:0;
        case 1:
            return y[x/8] & 0x02 ? 1:0;
        case 2:
            return y[x/8] & 0x04 ? 1:0;
        case 3:
            return y[x/8] & 0x08 ? 1:0;
        case 4:
            return y[x/8] & 0x10 ? 1:0;
        case 5:
            return y[x/8] & 0x20 ? 1:0;
        case 6:
            return y[x/8] & 0x40 ? 1:0;
        case 7:
            return y[x/8] & 0x80 ? 1:0;
    }

    return 0;
}

