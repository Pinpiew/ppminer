#ifndef __PLATFORM_DRIVER_H__
#define __PLATFORM_DRIVER_H__

#include "driver.h"
#define PLATFORM_DATAPATH_NUM           1
#define ZCASH_HEAD_OFFSET               12

static inline int platform_soc_init(void *arg) {
  return bm_soc_init(arg);
}

static inline int platform_soc_exit(void) {
  return bm_soc_exit();
}

static inline int platform_ioctl_regtable(uint32_t oper_type, void *param) {
  (void)oper_type; (void)param;
  return 0;
}

static inline int platform_pack_ioctl_pkg(uint8_t *str,
        uint32_t str_len, uint32_t oper_type, void *param) {
  return bm_pack_ioctl_pkg(str, str_len, oper_type, param);
}

static inline int platform_parse_respond_pkg(uint8_t *str,
        int len, int *type, uint8_t *out_str, uint32_t out_len) {
  return bm_parse_respond_pkg(str, len, type, out_str, out_len);
}

static inline int platform_parse_respond_len(uint8_t *str, int len, int *read_len, int *st) {
  return bm_parse_respond_len(str, len, read_len, st);
}

static inline int platform_pack_work_pkg(uint8_t *str) {
  return bm_pack_cmd_frame(str);
}

static inline int platform_pack_data_frame(uint8_t *str) {
  return bm_pack_cmd_frame(str);
}


#endif
