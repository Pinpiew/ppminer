#include <stdio.h>
#include "platform-driver.h"
#include "chip-api.h"
#include "logging.h"

struct chip_api g_chip_api;

int chip_api_init(int chip_type)
{
    switch(chip_type)
    {
        case 0:
        {
            g_chip_api.ioctl_regtable       = platform_ioctl_regtable;
            g_chip_api.pack_ioctl_pkg       = platform_pack_ioctl_pkg;
            g_chip_api.pack_work_pkg        = platform_pack_work_pkg;
            g_chip_api.pack_data_frame      = platform_pack_data_frame;
            g_chip_api.parse_respond_len    = platform_parse_respond_len;
            g_chip_api.parse_respond_pkg    = platform_parse_respond_pkg;
            platform_soc_init(&g_chip_api.chip);
            break;
        }
        default:
            applog(LOG_ERR, "%s unknow chip_type %d\n", __func__, chip_type);
            return -1;
    }
    return 0;
}

