#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "uart-ubuntu.h"
#include "time.h"
#include "logging.h"
#include "comm-api.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

struct comm_api g_comm_api;
static int g_logfd = 0;

int log_open(char *dev_name, void *arg)
{
    (void)dev_name;
    (void)arg;
    int logfd;

    logfd = open("./log/uart_log.txt", O_CREAT | O_RDWR, 0777);
    if (logfd < 0) {
        printf("open log file error:%d\n", logfd);
        return -1;
    }

    return logfd;
}

int log_recv(int fd, unsigned char *rcv_buf, size_t data_len)
{
    (void)fd;
    (void)rcv_buf;
    (void)data_len;
    return 0;
}

int log_send(int fd, unsigned char *send_buf, size_t data_len)
{
    if (fd < 0) {
        printf("log file not exist:%d\n", fd);
        return -1;
    }

    char lb[1024] = {0}, tmp[5];
    for (unsigned int i=0; i<data_len; i++) {
        memset(tmp, 0, 5);
        sprintf(tmp, "%02x ", send_buf[i]);
        strcat(lb, tmp);
    }

    applog(LOG_INFO, "%s", lb);
    sprintf(tmp, "\n");
    strcat(lb, tmp);
    return write(fd, lb, strlen(lb));
}

int log_close(int fd)
{
    close(fd);
    return 0;
}

int comm_api_init(comm_type_t comm_type)
{
    switch(comm_type)
    {
        case COMM_TYPE_UART:	//uart
            g_comm_api.bm_open	= uart_open;
            g_comm_api.bm_init	= NULL;//uart_init;
            g_comm_api.bm_recv	= uart_recv;
            g_comm_api.bm_send	= uart_send;
            g_comm_api.bm_close = uart_close;
            break;
        case COMM_TYPE_SIMU:
            g_comm_api.bm_open	= log_open;
            g_comm_api.bm_init	= NULL;//uart_init;
            g_comm_api.bm_recv	= log_recv;
            g_comm_api.bm_send	= log_send;
            g_comm_api.bm_close = log_close;
            break;
        default:
            printf("unknow IO type\n");
            return -1;
    }

    g_logfd = open( "./uart_log.txt", O_CREAT | O_WRONLY | O_TRUNC , 0777);
    return 0;
}

void uart_log(const char *str, int fd, unsigned char *send_buf, size_t data_len)
{
    if(!send_buf)
        return ;

    char *lb, tmp[50] = {0};
    lb = (char *)malloc(4096);
    memset(lb, 0, 4096);

    struct timeval tv = {0, 0};
    struct tm *tm;

    gettimeofday( &tv, NULL);
    const time_t tmp_time = tv.tv_sec;
    int ms = (int)(tv.tv_usec / 1000);
    tm = localtime(&tmp_time);

    snprintf(lb, 100, "[%d-%02d-%02d %02d:%02d:%02d.%03d] ",
              tm->tm_year + 1900,
              tm->tm_mon + 1,
              tm->tm_mday,
              tm->tm_hour,
              tm->tm_min,
              tm->tm_sec, ms);

    strcat(lb, str);
    sprintf(tmp, "[%d--0x%02x]: ", fd, (int)data_len);
    strcat(lb, tmp);
    for (size_t i=0; i<data_len; i++) {
        memset(tmp, 0, 5);
        sprintf(tmp, "%02x ", send_buf[i]);
        strcat(lb, tmp);
    }

    if (g_logfd > 0) {
      strcat(lb, "\r\n");
      write(g_logfd, lb, strlen(lb));
      fsync(g_logfd);
    } else {
      applog(LOG_NOTICE, "%s", lb);
    }
    free(lb);
}
