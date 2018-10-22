#ifndef _BM_REG_OPERATION_H_
#define _BM_REG_OPERATION_H_

#include <stdint.h>

/*********************Default Value**********************/
#define BMSC_DEFAULT_BAUD	115200


/***************SPEC. Basic Definition**********************/
#define ZCASH_HEAD_LEN          80
#define DATAF_HEAD_LEN          64


#define BM_HEADER_55        0x55
#define BM_HEADER_AA        0xaa
#define BM_HEADER_5A        0x5a
#define BM_HEADER_AE        0xae
#define BM_HEADER_5D        0x5d
#define BM_HEADER_A5        0xa5



#define BM_CMD_HEADER_LEN       6
#define BM_ACK_HEADER_LEN       7

#define BM_CRC16_LEN        2
#define BM_CRC5_LEN         1
#define BM_WORK_LEN         86
#define BM_DATAFRAME_LEN    128


#define BM_RESP_NONCE_LEN           (9)
#define BM_RESP_REG_LEN             (9)


// General I2C Command.  default: 0x01000000
/***************SPEC. bm Command Definition***************/
enum input_data_type
{
    WORK_INPUT      = 0x01,
    COMMAND_INPUT   = 0x02,
    BIST_INPUT      = 0x03,
};

typedef enum {
  CMD_INIT            = 0,
  CMD_SET_NONCE_DIFF     ,
  CMD_SET_SEED           ,
  CMD_SET_MSG            ,
  CMD_RETURN_NONCE       ,
  CMD_SET_NONCE_REGION   ,
  CMD_UPDATA_FIR         ,
  CMD_UPDATA_FIR_END     ,
  CMD_TEST               ,
  CMD_GET_BOARD_TMP      ,
  CMD_GET_CHIP_TMP       ,
  CMD_READ_MEM           ,
  CMD_WRITE_MEM          ,
  CMD_SET_CHIP_ADDR      ,
} cmd_type_t;


struct cmd_header
{
    uint8_t header_55;
    uint8_t header_aa;
    uint8_t cmd;
    uint8_t chip_addr;
    uint8_t data_len;
    uint8_t chksum;
    uint8_t data[512];
} __attribute__((packed, aligned(1)));

struct ack_header
{
    uint8_t header_aa;
    uint8_t header_55;
    uint8_t cmd;
    uint8_t chip_addr;
    uint8_t ack;
    uint8_t data_len;
    uint8_t chksum;
    uint8_t data[512];
} __attribute__((packed, aligned(1)));

struct mem_data
{
    uint32_t addr;
    uint32_t data;
};


/******************function declaration******************/
int bm_soc_init(void *arg);
int bm_soc_exit();
int bm_pack_ioctl_pkg(uint8_t *str, uint32_t str_len, uint32_t oper_type, void *param);
int bm_parse_respond_pkg(uint8_t *str, uint32_t len, int *type, uint8_t *out_str, uint32_t out_len);
int bm_parse_respond_len(uint8_t *str, int len, int *read_len, int *st);
int bm_pack_cmd_frame(uint8_t *str);

#endif
