#ifndef __SERIAL_H__
#define __SERIAL_H__

struct uart_info
{
    int speed;
    int flow_ctrl;
    int databits;
    int stopbits;
    char parity;
    int cc_vtime;
    int cc_vmin;
};

int uart_open(char* port, void *arg);
//int uart_init(int fd);
int uart_close(int fd);
int uart_recv(int fd, unsigned char *rcv_buf, size_t data_len);
int uart_recv_normal(int fd, unsigned char *rcv_buf, size_t data_len);
int uart_send(int fd, unsigned char *send_buf, size_t data_len);
#endif
