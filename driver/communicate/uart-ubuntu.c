#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include "uart-ubuntu.h"
#include "comm-api.h"


#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__)
#include <termios.h>
#include <sys/ioctl.h>
static fd_set fs_read;

int uart_open(char* port, void *arg)
{
    unsigned int i;
    char dev_path[32] = {0};

    int speed_arr[] = {B3000000, B1500000, B921600, B460800, B115200, B57600, B38400, B19200, B9600, B4800, B2400, B1200, B300,B38400, B19200, B9600, B4800, B2400, B1200, B300};
    int name_arr[]	= { 3000000, 1500000,	921600,  460800,  115200,  57600,  38400,  19200,  9600,  4800,  2400,	1200,  300, 38400,	19200,	9600,  4800,  2400,  1200,	300};

    struct termios options;
    struct uart_info *param = (struct uart_info *)arg;

    sprintf(dev_path, "/dev/%s", port);
    int fd = open(dev_path, O_RDWR|O_NOCTTY);

    if (fd < 0)
    {
        fprintf(stderr, "Can't Open Serial Port %s", dev_path);
        return -1;
    }

    if(tcgetattr(fd, &options) != 0)
    {
        fprintf(stderr, "SetupSerial 1");
        return -1;
    }
    //设置串口输入波特率和输出波特率
    for(i=0; i<sizeof(speed_arr)/sizeof(int); i++)
    {
        if (param->speed == name_arr[i])
        {
            cfsetispeed(&options, speed_arr[i]);
            cfsetospeed(&options, speed_arr[i]);
        }
    }
    //修改控制模式，保证程序不会占用串口
    options.c_cflag |= CLOCAL;
    //修改控制模式，使得能够从串口中读取输入数据
    options.c_cflag |= CREAD;

    //close zifuyingshe
    options.c_iflag &= ~(INLCR|ICRNL);

    //close liukong zifu
    options.c_iflag &= ~(IXON);

    //使用原始模式（raw mode）
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG); /*Input*/
    options.c_oflag &= ~OPOST; /*Output*/

    //设置数据流控制
    switch(param->flow_ctrl)
    {
        case 0 : //不使用流控制
            options.c_cflag &= ~CRTSCTS;
            break;
        case 1 : //使用硬件流控制
            options.c_cflag |= CRTSCTS;
            break;
        case 2 : //使用软件流控制
            options.c_cflag |= IXON | IXOFF | IXANY;
            break;
    }


    //设置数据位
    options.c_cflag &= ~CSIZE; //屏蔽其他标志位
    switch (param->databits)
    {
        case 5 :
            options.c_cflag |= CS5;
            break;
        case 6 :
            options.c_cflag |= CS6;
            break;
        case 7 :
            options.c_cflag |= CS7;
            break;
        case 8:
            options.c_cflag |= CS8;
            break;
        default:
            fprintf(stderr,"Unsupported data size\n");
            return -1;
    }
    //设置校验位
    switch (param->parity)
    {
        case 'n':
        case 'N': //无奇偶校验位。
            options.c_cflag &= ~PARENB;
            options.c_iflag &= ~INPCK;
            break;
        case 'o':
        case 'O': //设置为奇校验
            options.c_cflag |= (PARODD | PARENB);
            options.c_iflag |= INPCK;
            break;
        case 'e':
        case 'E': //设置为偶校验
            options.c_cflag |= PARENB;
            options.c_cflag &= ~PARODD;
            options.c_iflag |= INPCK;
            break;
        case 's':
        case 'S': //设置为空格
            options.c_cflag &= ~PARENB;
            options.c_cflag &= ~CSTOPB;
            break;
        default:
            fprintf(stderr,"Unsupported parity\n");
            return -1;
    }

    // 设置停止位
    switch (param->stopbits)
    {
        case 1:
            options.c_cflag &= ~CSTOPB;
            break;
        case 2:
            options.c_cflag |= CSTOPB;
            break;
        default:
            fprintf(stderr,"Unsupported stop bits\n");
            return -1;
    }
    //修改输出模式，原始数据输出
    options.c_oflag &= ~OPOST;
    //设置等待时间和最小接收字符

    options.c_cc[VTIME] = param->cc_vtime; /* 读取一个字符等待1*(1/10)s */
    options.c_cc[VMIN] = param->cc_vmin; /* 读取字符的最少个数为1 */

    //如果发生数据溢出，接收数据，但是不再读取
    tcflush(fd,TCIFLUSH);

    //激活配置 (将修改后的termios数据设置到串口中）
    if (tcsetattr(fd,TCSANOW,&options) != 0)
    {
        fprintf(stderr, "com set error!/n");
        return -1;
    }

	if (fcntl(fd,F_SETFL,0) < 0) {
		fprintf(stderr, "fcntl failed\n");
		return -1;
	}

    return fd;
}

int uart_close(int fd)
{
    FD_CLR(fd, &fs_read);
    return close(fd);
}

/*******************************************************************
* 名称： uart_recv
* 功能： 接收串口数据
* 入口参数： fd :文件描述符
* rcv_buf :接收串口中数据存入rcv_buf缓冲区中
* data_len :一帧数据的长度
* 出口参数： 正确返回为1，错误返回为0
*******************************************************************/
int uart_recv_normal(int fd, unsigned char *rcv_buf, size_t data_len)
{
    return read(fd,rcv_buf,data_len);
}

int uart_recv(int fd, unsigned char *rcv_buf, size_t data_len)
{
#if 0 //method 1
    int fs_sel, read_ret = -1;

    struct timeval time;

    FD_ZERO(&fs_read);
    FD_SET(fd,&fs_read);

    time.tv_sec = 0;
    time.tv_usec = 50*1000;

    fs_sel = select(fd+1,&fs_read,NULL,NULL,&time);
    if (fs_sel < 0)
    {
        fprintf(stderr, "fs_sel < 0\n");
        return -1;
    }
    else if (fs_sel == 0)
    {
        // Maybe timeout, maybe other error
        return 0;
    }
    else
    {
        read_ret = read(fd,rcv_buf,data_len);
        return read_ret;
    }
#else	//method 2
    size_t nbytes = 0;
    int len = 0;
    if(ioctl(fd, FIONREAD, &nbytes) == 0)
    {
        if(nbytes < data_len)
        {
            len = 0;
        }
        else
        {
            len = read(fd, rcv_buf, data_len);
        }
    }
    else
    {
        len = 0;
    }

    if (len > 0) uart_log("Rx", fd, rcv_buf, len);
    return len;
#endif
}

/*******************************************************************
* 名称： uart_send
* 功能： 发送数据
* 入口参数： fd :文件描述符
* send_buf :存放串口发送数据
* data_len :一帧数据的个数
* 出口参数： 正确返回为1，错误返回为0
*******************************************************************/
int uart_send(int fd, unsigned char *send_buf, size_t data_len)
{
    uart_log("Tx", fd, send_buf, data_len);
    size_t ret = write(fd,send_buf,data_len);
    if (data_len == ret )
    {
        return ret;
    }
    else
    {
        tcflush(fd,TCOFLUSH);
        return -1;
    }
}

#else

#include <windows.h>
HANDLE Cport[16];

char comports[17][10]={"\\\\.\\COM0", "\\\\.\\COM1",  "\\\\.\\COM2",  "\\\\.\\COM3",  "\\\\.\\COM4",
                       "\\\\.\\COM5",  "\\\\.\\COM6",  "\\\\.\\COM7",  "\\\\.\\COM8",
                       "\\\\.\\COM9",  "\\\\.\\COM10", "\\\\.\\COM11", "\\\\.\\COM12",
                       "\\\\.\\COM13", "\\\\.\\COM14", "\\\\.\\COM15", "\\\\.\\COM16"};

char mode_str[128] = {0};

//int RS232_OpenComport(int comport_number, int baudrate, const char *mode)
int uart_open(char* port, void *arg)
{
  struct uart_info *param = (struct uart_info *)arg;

  /* input format: com1/com2... */

  int comport_number = atoi(port+3);
  if((comport_number>15)||(comport_number<0))
  {
    printf("illegal comport number %s\n", port);
    return(1);
  }

  switch(param->speed)
  {
    case     110 : strcpy(mode_str, "baud=110");
                   break;
    case     300 : strcpy(mode_str, "baud=300");
                   break;
    case     600 : strcpy(mode_str, "baud=600");
                   break;
    case    1200 : strcpy(mode_str, "baud=1200");
                   break;
    case    2400 : strcpy(mode_str, "baud=2400");
                   break;
    case    4800 : strcpy(mode_str, "baud=4800");
                   break;
    case    9600 : strcpy(mode_str, "baud=9600");
                   break;
    case   19200 : strcpy(mode_str, "baud=19200");
                   break;
    case   38400 : strcpy(mode_str, "baud=38400");
                   break;
    case   57600 : strcpy(mode_str, "baud=57600");
                   break;
    case  115200 : strcpy(mode_str, "baud=115200");
                   break;
    case  128000 : strcpy(mode_str, "baud=128000");
                   break;
    case  256000 : strcpy(mode_str, "baud=256000");
                   break;
    case  500000 : strcpy(mode_str, "baud=500000");
                   break;
    case 1000000 : strcpy(mode_str, "baud=1000000");
                   break;
    default      : printf("invalid baudrate\n");
                   return(1);
                   break;
  }

  switch(param->databits)
  {
    case 8: strcat(mode_str, " data=8");
              break;
    case 7: strcat(mode_str, " data=7");
              break;
    case 6: strcat(mode_str, " data=6");
              break;
    case 5: strcat(mode_str, " data=5");
              break;
    default : printf("invalid number of data-bits '%d'\n", param->databits);
              return(1);
              break;
  }

  switch(param->parity)
  {
    case 'N':
    case 'n': strcat(mode_str, " parity=n");
              break;
    case 'E':
    case 'e': strcat(mode_str, " parity=e");
              break;
    case 'O':
    case 'o': strcat(mode_str, " parity=o");
              break;
    default : printf("invalid parity '%c'\n", param->parity);
              return(1);
              break;
  }

  switch(param->stopbits)
  {
    case 1: strcat(mode_str, " stop=1");
              break;
    case 2: strcat(mode_str, " stop=2");
              break;
    default : printf("invalid number of stop bits '%d'\n", param->stopbits);
              return(1);
              break;
  }

  strcat(mode_str, " dtr=on rts=on");

/*
http://msdn.microsoft.com/en-us/library/windows/desktop/aa363145%28v=vs.85%29.aspx
http://technet.microsoft.com/en-us/library/cc732236.aspx
*/

  Cport[comport_number] = CreateFileA(comports[comport_number],
                      GENERIC_READ|GENERIC_WRITE,
                      0,                          /* no share  */
                      NULL,                       /* no security */
                      OPEN_EXISTING,
                      0,                          /* no threads */
                      NULL);                      /* no templates */

  if(Cport[comport_number]==INVALID_HANDLE_VALUE)
  {
    printf("unable to open comport\n");
    return(1);
  }

  DCB port_settings;
  memset(&port_settings, 0, sizeof(port_settings));  /* clear the new struct  */
  port_settings.DCBlength = sizeof(port_settings);

  if(!BuildCommDCBA(mode_str, &port_settings))
  {
    printf("unable to set comport dcb settings\n");
    CloseHandle(Cport[comport_number]);
    return(1);
  }

  if(!SetCommState(Cport[comport_number], &port_settings))
  {
    printf("unable to set comport cfg settings\n");
    CloseHandle(Cport[comport_number]);
    return(1);
  }

  COMMTIMEOUTS Cptimeouts;

  Cptimeouts.ReadIntervalTimeout         = MAXDWORD;
  Cptimeouts.ReadTotalTimeoutMultiplier  = 0;
  Cptimeouts.ReadTotalTimeoutConstant    = 0;
  Cptimeouts.WriteTotalTimeoutMultiplier = 0;
  Cptimeouts.WriteTotalTimeoutConstant   = 0;

  if(!SetCommTimeouts(Cport[comport_number], &Cptimeouts))
  {
    printf("unable to set comport time-out settings\n");
    CloseHandle(Cport[comport_number]);
    return(1);
  }

  return comport_number;
}


int uart_recv(int fd, unsigned char *rcv_buf, size_t data_len)
{
  int n;

/* added the void pointer cast, otherwise gcc will complain about */
/* "warning: dereferencing type-punned pointer will break strict aliasing rules" */

  ReadFile(Cport[fd], rcv_buf, data_len, (LPDWORD)((void *)&n), NULL);

  return(n);
}

int uart_send(int fd, unsigned char *send_buf, size_t data_len)
{
  int n;

  if(WriteFile(Cport[fd], send_buf, data_len, (LPDWORD)((void *)&n), NULL))
  {
    return(n);
  }

  return(-1);
}


int uart_close(int fd)
{
  return CloseHandle(Cport[fd]);
}

/*
http://msdn.microsoft.com/en-us/library/windows/desktop/aa363258%28v=vs.85%29.aspx
*/
#if 0
static int uart_send_byte(int fd, unsigned char byte)
{
  int n;

  WriteFile(Cport[fd], &byte, 1, (LPDWORD)((void *)&n), NULL);

  if(n<0)  return(1);

  return(0);
}

int RS232_IsDCDEnabled(int comport_number)
{
  int status;

  GetCommModemStatus(Cport[comport_number], (LPDWORD)((void *)&status));

  if(status&MS_RLSD_ON) return(1);
  else return(0);
}


int RS232_IsCTSEnabled(int comport_number)
{
  int status;

  GetCommModemStatus(Cport[comport_number], (LPDWORD)((void *)&status));

  if(status&MS_CTS_ON) return(1);
  else return(0);
}


int RS232_IsDSREnabled(int comport_number)
{
  int status;

  GetCommModemStatus(Cport[comport_number], (LPDWORD)((void *)&status));

  if(status&MS_DSR_ON) return(1);
  else return(0);
}


void RS232_enableDTR(int comport_number)
{
  EscapeCommFunction(Cport[comport_number], SETDTR);
}


void RS232_disableDTR(int comport_number)
{
  EscapeCommFunction(Cport[comport_number], CLRDTR);
}


void RS232_enableRTS(int comport_number)
{
  EscapeCommFunction(Cport[comport_number], SETRTS);
}


void RS232_disableRTS(int comport_number)
{
  EscapeCommFunction(Cport[comport_number], CLRRTS);
}
#endif

#endif
