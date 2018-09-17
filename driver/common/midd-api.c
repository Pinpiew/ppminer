#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "midd-api.h"
#include "logging.h"
#include "util.h"
#include "ringbuffer.h"
#include "chip-api.h"
#include "platform-driver.h"
#include "comm-api.h"

struct midd_api  g_midd_api;
extern struct chip_api g_chip_api;
extern struct comm_api g_comm_api;


static uint8_t g_headHash[256];
static int midd_send_work_to_rb(uint8_t *str, uint32_t len)
{
	return rt_ringbuffer_put(&g_midd_api.bm_work_rb, str, len);
}

static int midd_send_framedata_to_rb(uint8_t *str, uint32_t len, int idx)
{
	return rt_ringbuffer_put(&g_midd_api.bm_data_rb[idx], str, len);
}

static int midd_recv_framedata(uint8_t *str, uint32_t len, uint8_t idx)
{
    if (g_midd_api.bm_reg_rb.block_flag == BLOCK_TYPE) {
        return  rt_ringbuffer_get(&g_midd_api.bm_data_response_rb[idx], str, len);
    } else {
        uint32_t rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_data_response_rb[idx]);
        if (rb_len < len) {
            return rb_len;
        }

        return  rt_ringbuffer_get(&g_midd_api.bm_data_response_rb[idx], str, len);
    }
}


static int midd_recv_work(uint8_t *str, uint32_t len)
{
    if (g_midd_api.bm_nonce_rb.block_flag == BLOCK_TYPE) {
        return rt_ringbuffer_get(&g_midd_api.bm_nonce_rb, str, len);
    } else {
        uint32_t rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_nonce_rb);
        if (rb_len < len) {
            return rb_len;
        }

        return rt_ringbuffer_get(&g_midd_api.bm_nonce_rb, str, len);
    }
}

static int midd_recv_regdata(uint8_t *str, uint32_t len)
{
    if (g_midd_api.bm_reg_rb.block_flag == BLOCK_TYPE) {
        return  rt_ringbuffer_get(&g_midd_api.bm_reg_rb, str, len);
    } else {
        uint32_t rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_reg_rb);
        if (rb_len < len) {
            return rb_len;
        }

        return  rt_ringbuffer_get(&g_midd_api.bm_reg_rb, str, len);
    }
}

static int midd_recv_pmonitor(uint8_t *str, uint32_t len)
{
    if (g_midd_api.bm_reg_rb.block_flag == BLOCK_TYPE) {
        return  rt_ringbuffer_get(&g_midd_api.bm_pmonitor_rb, str, len);
    } else {
        uint32_t rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_pmonitor_rb);
        if (rb_len < len) {
            return rb_len;
        }

        return  rt_ringbuffer_get(&g_midd_api.bm_pmonitor_rb, str, len);
    }
}

/*
    mode is used for get mode. if mode=0, get from chip, else get from reg-table
*/
static int midd_ioctl(int fd, uint32_t oper_type, void *param)
{
    uint8_t str[256] = {0};
    int len = g_chip_api.pack_ioctl_pkg(str, 256, oper_type, param);
	if (len < 0)
		return len;
    return g_comm_api.bm_send(fd, str, len);
}

static int midd_ioctl_regtable(uint32_t oper_type, void *param)
{
    return g_chip_api.ioctl_regtable(oper_type, param);
}

static void *midd_dispatch_packet(void *param)
{
    uint8_t rev_buf[MAX_RECV_LEN_EACH_TIME] = {0};
    uint8_t complete_pkg[MAX_RECV_LEN_EACH_TIME] = {0};
    uint8_t *p_complete_pkg = complete_pkg;
    uint8_t out_str[MAX_NONCE_LEN] = {0};
	struct std_chain_info *chain = (struct std_chain_info *)param;
    int out_len = 0;
    int rsp_type = 0;
    int read_bytes = 1;
    int next_bytes = 1;
    int parse_stage = 0;
    int st = 0;

    pthread_detach(pthread_self());

    applog(LOG_INFO, "[%s, %d] Chain %d, dev handle:%d", __FUNCTION__, __LINE__, chain->chain_id, chain->fd);
    while(1)
    {
        z_msleep(20);
        int len = g_comm_api.bm_recv(chain->fd, rev_buf, read_bytes);
        if (len != read_bytes) {
          //applog(LOG_INFO, "[%s, %d] Chain %d, dev handle:%d, data len:%d", __FUNCTION__, __LINE__, chain->chain_id, chain->fd, len);
          continue;
        }

        parse_stage = g_chip_api.parse_respond_len(rev_buf, read_bytes, &next_bytes, &st);

        if (parse_stage == PKG_PARSE_IDLE_STATE) {
            read_bytes = 1;
            p_complete_pkg = complete_pkg;
            continue;
        } else if (parse_stage == PKG_PARSE_MIDDLE_STATE) {
            memcpy(p_complete_pkg, rev_buf, read_bytes);
            p_complete_pkg += read_bytes;
            read_bytes = next_bytes;
        } else {
            memcpy(p_complete_pkg, rev_buf, read_bytes);
            p_complete_pkg += read_bytes;

            out_len = g_chip_api.parse_respond_pkg(complete_pkg, p_complete_pkg-complete_pkg,
                                                   &rsp_type, out_str, MAX_NONCE_LEN);
            if (out_len > 0) {
                out_str[out_len] = chain->chain_id;
                out_len += 1;

                switch (rsp_type)
                {
                    case NONCE_RESPOND:
                        rt_ringbuffer_put(&g_midd_api.bm_nonce_rb, out_str, out_len);
                        break;
                    case REGISTER_RESPOND:
                        rt_ringbuffer_put(&g_midd_api.bm_reg_rb, out_str, out_len);
                        break;
                    default:
                        applog(LOG_WARNING, "unknow receive type %d\n", rsp_type);
                        break;
                }
            }

            p_complete_pkg = complete_pkg;
            read_bytes = 1;
        }
    }

    return NULL;
}


int start_dispatch_packet(void *param)
{
    struct std_chain_info *chain = (struct std_chain_info *)param;
    if (0 != pthread_create(&chain->p_dispatch, NULL, midd_dispatch_packet, param))
    {
        printf("create p_dispatch failed\n");
        return -1;
    }

    return 0;
}

void stop_dispatch_packet(void *param)
{
    struct std_chain_info *chain = (struct std_chain_info *)param;
    pthread_cancel(chain->p_dispatch);
}

static void *midd_send_work(void *param)
{
    struct std_chain_info *chain = (struct std_chain_info *)param;
    uint8_t *str = (uint8_t *)malloc(g_chip_api.chip.work_len);
    if (str == NULL) {
        printf("%s malloc failed\n", __func__);
        exit(1);
    }

    pthread_detach(pthread_self());
    while(1)
    {
        rt_ringbuffer_get(&g_midd_api.bm_work_rb, str, g_chip_api.chip.work_len);
        g_chip_api.pack_work_pkg(str);
        memcpy(g_headHash, &str[ZCASH_HEAD_OFFSET], ZCASH_HEAD_LEN);
        g_comm_api.bm_send(chain->fd, str, g_chip_api.chip.work_len);
    }

    free(str);
    return NULL;
}

static void *midd_data_download(void *param)
{
    struct std_chain_info *chain = (struct std_chain_info *)param;
    uint8_t *str = (uint8_t *)malloc(g_chip_api.chip.frame_len);
    if (str == NULL) {
        printf("%s malloc failed\n", __func__);
        exit(1);
    }

    pthread_detach(pthread_self());

    while(1)
    {
        rt_ringbuffer_get(&g_midd_api.bm_data_rb[chain->chain_id - 1], str, g_chip_api.chip.frame_len);
        g_chip_api.pack_data_frame(str);
        g_comm_api.bm_send(chain->fd, str, g_chip_api.chip.frame_len);
    }

    free(str);
    return NULL;
}


int start_send_work(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	if (0 != pthread_create(&chain->p_send_work, NULL, midd_send_work, param))
	{
		printf("create send work failed\n");
		return -1;
	}

	return 0;
}

int start_data_download(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	if (0 != pthread_create(&chain->p_data_download, NULL, midd_data_download, param))
	{
		printf("create data download failed\n");
		return -1;
	}

	return 0;
}

void stop_send_work(void *param)
{
	struct std_chain_info *chain = (struct std_chain_info *)param;
	pthread_cancel(chain->p_send_work);
}

void init_ringbuf(struct rt_ringbuffer *rb, uint32_t len, ringbuffer_type_t type) {

    len  *= 300;
    uint8_t *ptr = (uint8_t *)malloc(len);
    if (!ptr) {
        printf("%s malloc failed\n", __func__);
        exit(1);
    }

    memset(ptr, 0, len);
    rt_ringbuffer_init(rb, ptr, len, type);
}

int midd_api_init()
{
    g_midd_api.send_work        = midd_send_work_to_rb;
    g_midd_api.recv_work        = midd_recv_work;
    g_midd_api.recv_regdata     = midd_recv_regdata;
    g_midd_api.recv_pmonitor    = midd_recv_pmonitor;
    g_midd_api.ioctl            = midd_ioctl;
    g_midd_api.ioctl_regtable   = midd_ioctl_regtable;
    g_midd_api.send_framedata   = midd_send_framedata_to_rb;
    g_midd_api.recv_framedata   = midd_recv_framedata;

    init_ringbuf(&g_midd_api.bm_nonce_rb, g_chip_api.chip.nonce_len, BLOCK_TYPE);
    init_ringbuf(&g_midd_api.bm_reg_rb, g_chip_api.chip.reg_len, BLOCK_TYPE);
    init_ringbuf(&g_midd_api.bm_pmonitor_rb, g_chip_api.chip.pm_len, BLOCK_TYPE);
    init_ringbuf(&g_midd_api.bm_bist_rb, g_chip_api.chip.bist_len, BLOCK_TYPE);
    init_ringbuf(&g_midd_api.bm_work_rb, g_chip_api.chip.work_len, BLOCK_TYPE);

    for(int i=0; i<PLATFORM_DATAPATH_NUM; i++) {
        init_ringbuf(&g_midd_api.bm_data_rb[i], g_chip_api.chip.frame_len, BLOCK_TYPE);
        init_ringbuf(&g_midd_api.bm_data_response_rb[i], g_chip_api.chip.frame_len, BLOCK_TYPE);
    }
    return 0;
}

void midd_api_exit()
{
    rt_ringbuffer_lock_destory(&g_midd_api.bm_nonce_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_reg_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_pmonitor_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_bist_rb);
    rt_ringbuffer_lock_destory(&g_midd_api.bm_work_rb);
    for(int i=0; i<PLATFORM_DATAPATH_NUM; i++) {
        rt_ringbuffer_lock_destory(&g_midd_api.bm_data_rb[i]);
        rt_ringbuffer_lock_destory(&g_midd_api.bm_data_response_rb[i]);
    }

}
