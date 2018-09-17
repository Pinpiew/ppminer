/*
* Copyright (c) 2016 Beijing Sankuai Inc.
*
* The right to copy, distribute, modify, or otherwise make use
* of this software may be licensed only pursuant to the terms
* of an applicable Beijing Sankuai license agreement.
*/
#ifndef __MT_RINGBUFFER_H__
#define __MT_RINGBUFFER_H__

#include <pthread.h>
#include <stdint.h>
#define RT_ALIGN_DOWN(size, align)  ((size) & ~((align)-1))
#define RT_ALIGN_SIZE 4

typedef enum ringbuffer_type
{
    BLOCK_TYPE,
    POLL_TYPE
}ringbuffer_type_t;

/* ring buffer */
struct rt_ringbuffer
{
    unsigned char * buffer_ptr;
    unsigned short read_mirror : 1;
    unsigned short read_index  : 15;
    unsigned short write_mirror : 1;
    unsigned short write_index  : 15;

    int block_flag;
    
    unsigned short buffer_size;
    pthread_mutex_t  ringbuf_lock;
    pthread_cond_t notfull;
    pthread_cond_t notempty;

    ringbuffer_type_t ringbuffer_type;
};

typedef enum rt_ringbuffer_state
{
    RT_RINGBUFFER_EMPTY,
    RT_RINGBUFFER_FULL,
    /* half full is neither full nor empty */
    RT_RINGBUFFER_HALFFULL,
}RINGBUFFER_STATE;

void rt_ringbuffer_init(struct rt_ringbuffer *rb,
                        uint8_t           *pool,
                        int16_t            size,
                        ringbuffer_type_t ringbuffer_type);
void rt_ringbuffer_lock_destory(struct rt_ringbuffer *rb);

uint16_t rt_ringbuffer_data_len(struct rt_ringbuffer *rb);
unsigned rt_ringbuffer_prefetch(struct rt_ringbuffer *rb,
                            unsigned char           *ptr,
                            unsigned short         length);
uint32_t rt_ringbuffer_put(struct rt_ringbuffer *rb,
                           const uint8_t     *ptr,
                           uint16_t           length);
uint32_t rt_ringbuffer_put_force(struct rt_ringbuffer *rb,
                                 const uint8_t     *ptr,
                                 uint16_t           length);
uint32_t rt_ringbuffer_get(struct rt_ringbuffer *rb,
                           uint8_t           *ptr,
                           uint16_t          length);
uint32_t rt_ringbuffer_prefetch(struct rt_ringbuffer *rb,
                                 uint8_t           *ptr,
                                 uint16_t          length);

#endif

