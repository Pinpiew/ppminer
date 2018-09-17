#ifndef __IOCTL_TYPE_H__
#define __IOCTL_TYPE_H__
enum IOCTL_IOCTL_TYPE
{
    IOCTL_GET_REG,
    IOCTL_SET_REG,
	IOCTL_SET_BAND,
	IOCTL_GET_BAND,
	IOCTL_SET_ANALOG_MUX,
	IOCTL_I2C_ENABLE,
	IOCTL_I2C_STATUS,
	IOCTL_I2C_READ,
	IOCTL_I2C_WRITE,
	IOCTL_SET_TICKET_MASK,
    IOCTL_GET_TICKET_MASK,
	IOCTL_SET_TXOK_EN,
	IOCTL_SET_NONCE_TXOK,
	IOCTL_GET_TABLE_NONCE_TXOK,

    IOCTL_SET_CORE_TIMEOUT,

    IOCTL_GET_LATCH_CI,
    IOCTL_GET_ADDRPIN,
    IOCTL_SET_INV_CLKO,
    IOCTL_SET_HASHRATE_TWS,
    IOCTL_SET_ADDRESS,
    IOCTL_CHAIN_INACTIVE,
    IOCTL_GET_CHIP_TYPE,
    IOCTL_GET_CHIP_ADDR,
    IOCTL_SET_HASHRATE,
    IOCTL_GET_HASHRATE,
    IOCTL_SET_PLL,
    IOCTL_GET_FRAME,

    
    IOCTL_GET_NONCEID,

    IOCTL_SET_IO_DRIVE_STRENGTH,
    IOCTL_CLR_CRC_ERR_COUNT,
    IOCTL_GET_CRC_ERR_COUNT,
    IOCTL_SET_NONCE_TX_TIMEOUT,
    IOCTL_SET_TMOUT,
    IOCTL_SET_VTSEL,
    IOCTL_SET_COREID,
    
    IOCTL_SET_START_NONCE_OFFSET,
    IOCTL_SET_TXN_DATA,

    IOCTL_SET_BIST_SETUP,
    IOCTL_SET_BIST_WRITE_WAIT,
    IOCTL_SET_BIST_WRITE_WAIT_READ,
    IOCTL_SET_BIST_WAIT,
    IOCTL_SET_BIST_READ,
    IOCTL_SET_BIST_DISABLE,
};

struct base_type_t
{
    uint8_t chip_addr;
    uint8_t all;
    uint8_t all_core;
	uint32_t addr;
	uint32_t data;
};

struct base_param_t
{
    uint8_t chip_addr;
    uint8_t all;
};

struct base_param8_t
{
    uint8_t chip_addr;
    uint8_t all;
    uint8_t param;
};

struct base_param32_t
{
    uint8_t chip_addr;
    uint8_t all;
    uint32_t param;
};

struct base_2param32_t
{
    uint8_t chip_addr;
    uint8_t all;
    uint32_t param1;
    uint32_t param2;
};

struct base_3param32_t
{
    uint8_t chip_addr;
    uint8_t all;
    uint32_t param1;
    uint32_t param2;
    uint32_t param3;
};

struct i2c_write_t
{
    uint8_t chip_addr;
    uint8_t all;
    uint8_t dev_addr;
    uint8_t reg_addr;
    uint8_t reg_data;
};

struct i2c_read_t
{
    uint8_t chip_addr;
    uint8_t all;
    uint8_t dev_addr;
    uint8_t reg_addr;
};


struct set_io_drive_strength_t
{
    struct base_param_t basep;
    uint8_t rf_ds;
    uint8_t tf_ds;
    uint8_t ro_ds;
    uint8_t clko_ds;
    uint8_t nrsto_ds;
    uint8_t bo_ds;
    uint8_t co_ds;
};

struct set_bist_write_wait_t
{
    struct base_param_t basep;
    uint8_t wr_data[6];
    uint8_t wr_repeat_num;
};

struct set_bist_write_wait_read_t
{
    struct base_param_t basep;
    uint8_t wr_data[6];
};

struct set_bist_wait_t
{
    struct base_param_t basep;
    uint8_t wait_cycle[5];
};
#endif
