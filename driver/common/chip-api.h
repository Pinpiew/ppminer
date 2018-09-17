#ifndef __CHIP_API_H__
#define __CHIP_API_H__

struct chip_info
{
    int work_len;
    int nonce_len;
    int pm_len;
    int reg_len;
    int bist_len;
    int frame_len;
};

struct chip_api
{
	struct chip_info chip;
	int (*ioctl_regtable)(uint32_t oper_type, void *param);
    int (*pack_ioctl_pkg)(uint8_t *str, uint32_t str_len, uint32_t oper_type, void *param);
    int (*pack_work_pkg)(uint8_t *str);
    int (*pack_data_frame)(uint8_t *str);
    int (*parse_respond_len)(uint8_t *str, int len, int *read_len, int *st);
    int (*parse_respond_pkg)(uint8_t *str, int len, int *type, uint8_t *out_str, uint32_t out_len);
};

enum
{
    SEARCH_0XAA,
    SEARCH_0X55,
    SEARCH_PKG_TYPE,
    SEARCH_PKG_BODY,
};

enum
{
	NONCE_RESPOND,
	PMONITOR_RESPOND,
	REGISTER_RESPOND,
	BIST_RESPOND,
	UNKNOW_RESPOND,
	ERR_RESPONSE_FRAME,
	DATA_FRAME,
};

enum
{
	PKG_PARSE_IDLE_STATE,
	PKG_PARSE_MIDDLE_STATE,
	PKG_PARSE_FINISHED_STATE,
};

int chip_api_init(int chip_type);

#endif
