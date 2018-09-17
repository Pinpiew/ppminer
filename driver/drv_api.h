
#ifndef __DRV_API_H__
#define __DRV_API_H__

void drv_init(void);
void drv_send_work(uint8_t msg_id, uint8_t *nonce, uint32_t n_len,
                                   uint8_t *msg, uint32_t m_len);
int drv_get_nonce(uint8_t *msg_id, uint8_t *buf);

#endif
