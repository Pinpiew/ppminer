#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include "platform-driver.h"
#include "util.h"
#include "midd-api.h"
#include "chip-api.h"
#include "comm-api.h"
#include "logging.h"
#include "ioctl-type.h"
#include "crc.h"
#if defined(__linux__)
#include "endian.h"
#endif
#include "uart-ubuntu.h"

#define DRV_CHIP_BC           0xff
#define CHIP_DEFAULT_ADDR     0x80
#define MAX_CHAIN_NUM         1
#define UART_BAUDRATE         9600
#define UART_DEV_CMD          "ttyUSB1"


extern struct midd_api g_midd_api;
extern struct comm_api g_comm_api;

struct std_chain_info g_chain[MAX_CHAIN_NUM];

void _chip_init(int chain_idx) {

  struct cmd_header frame;
  frame.data_len  = 0;
  frame.chip_addr = DRV_CHIP_BC;
  g_midd_api.ioctl(g_chain[chain_idx].fd, CMD_INIT, &frame);
}

void _chip_setAddr(int chain_idx, uint8_t addr) {

  struct cmd_header frame;
  frame.data_len = 1;
  frame.chip_addr = CHIP_DEFAULT_ADDR;
  frame.data[0] = addr;
  g_midd_api.ioctl(g_chain[chain_idx].fd, CMD_SET_CHIP_ADDR, &frame);
}

int _open_tty(struct std_chain_info *chain)
{
  struct uart_info u;

  u.speed = chain->bandrate;
  u.flow_ctrl = 0;
  u.databits = 8;
  u.stopbits = 1;
  u.parity = 'N';
  u.cc_vtime = 0;
  u.cc_vmin = 1024;

  int fd = g_comm_api.bm_open(chain->devname, &u);
  if (fd < 0) {
    applog(LOG_ERR, "%s open %s failed\n", __func__, chain->devname);
    return -1;
  }

  chain->fd = fd;
  return 0;
}

uint8_t _get_ack(uint8_t *buf, uint8_t *chain_idx) {

  struct ack_header frame;

  g_midd_api.recv_regdata((uint8_t *)&frame, BM1940_ACK_HEADER_LEN);
  g_midd_api.recv_regdata(frame.data, frame.data_len);
  g_midd_api.recv_regdata(chain_idx, 1);

  if (buf)
    memcpy(buf, (uint8_t *)&frame, frame.data_len + BM1940_ACK_HEADER_LEN);

  return frame.data_len;
}

uint8_t _get_nonce(uint8_t *buf, uint8_t *chain_idx) {

  struct ack_header frame;

  g_midd_api.recv_work((uint8_t *)&frame, BM1940_ACK_HEADER_LEN);
  g_midd_api.recv_work(frame.data, frame.data_len);
  g_midd_api.recv_work(chain_idx, 1);

  if (buf)
    memcpy(buf, frame.data, frame.data_len);

  return frame.data_len;
}

int _chain_init(int chain_id)
{
  const char *dev[MAX_CHAIN_NUM] = {
    #ifdef UART_DEV_CMD
    UART_DEV_CMD,
    #else
    NULL,
    #endif
  };

  if (chain_id >= MAX_CHAIN_NUM) return -1;
  if (!dev[chain_id]) return -1;

  struct std_chain_info *chain = &g_chain[chain_id];
  strcpy(chain->devname, dev[chain_id]);
  applog(LOG_INFO, "open dev\'s name of the chain %d : %s", chain_id, chain->devname);
  chain->bandrate = UART_BAUDRATE;
  chain->chain_id = chain_id;

  _open_tty(chain);
  start_dispatch_packet(chain);
  start_send_work(chain);

  return 0;
}

void drv_init(void)
{
  uint32_t chip_num, rb_len;
  uint8_t tmp;

  chip_api_init(0);
  comm_api_init(COMM_TYPE_UART);
  midd_api_init();

  for(int i = 0; i < MAX_CHAIN_NUM; i++)
    _chain_init(i);

  for(int i = 0; i < MAX_CHAIN_NUM; i++) {
    _chip_init(i);
    sleep(20);
    rb_len = rt_ringbuffer_data_len(&g_midd_api.bm_reg_rb);
    chip_num = rb_len / (BM1940_ACK_HEADER_LEN + 4 + 1);
    for(int j = 0; j < chip_num; j++)
      _get_ack(NULL, &tmp);

    for(int j = 0; j < chip_num; j++)
      _chip_setAddr(i, j);
  }
}

void drv_send_work(uint8_t msg_id, uint8_t diff, uint8_t *nonce,
                    uint32_t n_len, uint8_t *msg, uint32_t m_len) {

  struct cmd_header frame;
  uint32_t m = 0;

  for (int i = 0; i < MAX_CHAIN_NUM; i++) {
    nonce[n_len - 1] += i;

    frame.chip_addr = DRV_CHIP_BC;
    frame.data[m++] = msg_id;
    frame.data[m++] = diff;
    frame.data[m++] = n_len;
    memcpy(&frame.data[m], nonce, n_len);
    m += n_len;
    frame.data[m++] = m_len;
    memcpy(&frame.data[m], msg, m_len);
    m += m_len;
    frame.data_len = m;
    g_midd_api.ioctl(g_chain[i].fd, CMD_SET_MSG, &frame);
  }
}

int drv_get_nonce(uint8_t *msg_id, uint8_t *buf) {

  uint8_t chain_idx, n_cnt = 0, len;
  uint8_t tmp[1024];
  len = _get_nonce(tmp, &chain_idx);

  if (len > 2) {
    *msg_id = tmp[0];
    n_cnt   = tmp[1];
    memcpy(buf, &tmp[2], len - 2);
  }

  return n_cnt;
}


