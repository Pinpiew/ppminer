#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "platform-driver.h"
#include "util.h"
#include "crc.h"
#include "logging.h"
#include "chip-api.h"
#include "ioctl-type.h"


/************* Base Function to Makeup Packets**************/
int bm_pack_cmd_frame(uint8_t *str)
{
    struct cmd_header *frame = (struct cmd_header *)str;

    frame->header_55 = BM_HEADER_55;
    frame->header_aa = BM_HEADER_AA;
    frame->chksum    = 0;
    uint16_t len = frame->data_len + BM_CMD_HEADER_LEN;
    frame->chksum    = checksum(str, len);

    return len;
}

/*
    Parse response string from UART
*/
int bm_parse_respond_len(uint8_t *str, int len, int *read_len, int *st)
{
    int state = *st == 0 ? SEARCH_0XAA : *st;
    int ret = PKG_PARSE_IDLE_STATE;

    switch(state)
    {
        case SEARCH_0XAA:
            *read_len = 1;
            if (len > 0 && str[0] == BM_HEADER_AA) {
                state = SEARCH_0X55;
                ret = PKG_PARSE_MIDDLE_STATE;
            }
            break;
        case SEARCH_0X55:
            if (len > 0 && str[0] == BM_HEADER_55) {
                state = SEARCH_PKG_TYPE;
                ret = PKG_PARSE_MIDDLE_STATE;
            } else {
                state = SEARCH_0XAA;
                ret = PKG_PARSE_IDLE_STATE;
            }
            *read_len = BM_ACK_HEADER_LEN - 2;
            break;
        case SEARCH_PKG_TYPE:
            state = SEARCH_PKG_BODY;
            ret = PKG_PARSE_MIDDLE_STATE;
            *read_len = str[3];
            break;
        case SEARCH_PKG_BODY:
            ret = PKG_PARSE_FINISHED_STATE;
            *read_len = 1;
            state = SEARCH_0XAA;
            break;
        default:
            ret = PKG_PARSE_IDLE_STATE;
            *read_len = 1;
            state = SEARCH_0XAA;
            break;
    }

    *st = state;
    return ret;
}

int bm_parse_respond_pkg(uint8_t *str, uint32_t len, int *type, uint8_t *out_str, uint32_t out_len)
{
    (void)out_len;
    struct ack_header *frame = (struct ack_header *)str;

    if ((frame->header_aa != BM_HEADER_AA) || (frame->header_55 != BM_HEADER_55))
      return 0;

    uint8_t chksum = frame->chksum;
    frame->chksum = 0;
    uint8_t getsum = checksum(str, len);
    if (chksum != getsum)
      return 0;

    frame->chksum = chksum;
    *type = frame->cmd == CMD_RETURN_NONCE ? NONCE_RESPOND : REGISTER_RESPOND;
    memcpy(out_str, str, len);
    return len;
}

int bm_pack_ioctl_pkg(uint8_t *str, uint32_t str_len, uint32_t oper_type, void *param)
{
    (void)str_len;
    struct cmd_header *frame = (struct cmd_header *)param;

    frame->cmd = oper_type;
    memcpy(str, param, frame->data_len + BM_CMD_HEADER_LEN);
    return bm_pack_cmd_frame(str);
}

int bm_soc_init(void *arg)
{
    struct chip_info *chip = (struct chip_info *)arg;
    chip->work_len  = BM_WORK_LEN;
    chip->nonce_len = BM_RESP_NONCE_LEN;
    chip->reg_len   = BM_RESP_REG_LEN;
    chip->frame_len = BM_DATAFRAME_LEN;

    return 0;
}

int bm_soc_exit()
{
    return 0;
}
