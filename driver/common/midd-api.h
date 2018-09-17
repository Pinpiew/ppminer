#ifndef __MIDD_API__
#define __MIDD_API__

#include "ringbuffer.h"
#include "platform-driver.h"
#include <stdint.h>

#define MAX_RECV_LEN_EACH_TIME        	200
#define MAX_NONCE_LEN                   2048

/* API for upper layer */
struct midd_api
{
    struct rt_ringbuffer bm_nonce_rb;
    struct rt_ringbuffer bm_reg_rb;
    struct rt_ringbuffer bm_pmonitor_rb;
    struct rt_ringbuffer bm_bist_rb;
    struct rt_ringbuffer bm_work_rb;
    struct rt_ringbuffer bm_data_rb[PLATFORM_DATAPATH_NUM];
    struct rt_ringbuffer bm_data_response_rb[PLATFORM_DATAPATH_NUM];

    uint8_t *rb_nonce;
    uint8_t *rb_pm;
    uint8_t *rb_reg;
    uint8_t *rb_bist;
    uint8_t *rb_work;
    uint8_t *rb_data;
    uint8_t *rb_data_response;

    int (*send_work)(uint8_t *str, uint32_t len);
    int (*recv_work)(uint8_t *str, uint32_t len);
    int (*recv_regdata)(uint8_t *str, uint32_t len);
    int (*recv_pmonitor)(uint8_t *str, uint32_t len);
    int (*recv_bist)(uint8_t *str, uint32_t len);
    int (*ioctl)(int fd, uint32_t oper_type, void *param);
    int (*ioctl_regtable)(uint32_t oper_type, void *param);
  int (*send_framedata)(uint8_t *str, uint32_t len, int idx);
    int (*recv_framedata)(uint8_t *str, uint32_t len, uint8_t idx);
};

struct std_chain_info
{
    int fd;
    uint8_t chain_id;

    char devname[12];
    int bandrate;

    pthread_t p_dispatch;
    pthread_t p_send_work;
    pthread_t p_data_download;
};

#if 0
#define bswap_16( value)  \
  ( ( ( ( value) & 0xff) << 8) | ( ( value) >> 8))

#define bswap_32( value) \
  ( ( ( uint32_t)bswap_16( ( uint16_t)( ( value) & 0xffff)) << 16) | \
    ( uint32_t)bswap_16( ( uint16_t)( ( value) >> 16)))

#define bswap_64( value) \
  ( ( ( uint64_t)bswap_32( ( uint32_t)( ( value) & 0xffffffff)) \
      << 32) | \
    ( uint64_t)bswap_32( ( uint32_t)( ( value) >> 32)))
#endif

int start_data_download(void *param);
int start_send_work(void *param);
void stop_send_work(void *param);

int start_dispatch_packet(void *param);
void stop_dispatch_packet(void *param);

int midd_api_init();
void midd_api_exit();

#endif
