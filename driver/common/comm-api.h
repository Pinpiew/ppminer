#ifndef __COMMUNICATION_H__
#define __COMMUNICATION_H__

typedef enum {
    COMM_TYPE_UART      = 0,
    COMM_TYPE_SIMU      ,
} comm_type_t;

struct comm_api
{
    int (*bm_open)(char *dev_name, void *arg);
    int (*bm_init)(int fd, void *param);
    int (*bm_send)(int fd, unsigned char *str, size_t len);
    int (*bm_recv)(int fd, unsigned char *str, size_t len);
    int (*bm_close)(int fd);
};

int comm_api_init(comm_type_t comm_type);
void uart_log(const char *str, int fd, unsigned char *send_buf, size_t data_len);

#endif
