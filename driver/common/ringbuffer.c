/*
* Copyright (c) 2016 Beijing Sankuai Inc.
*
* The right to copy, distribute, modify, or otherwise make use
* of this software may be licensed only pursuant to the terms
* of an applicable Beijing Sankuai license agreement.
*/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ringbuffer.h"

uint16_t rt_ringbuffer_get_size(struct rt_ringbuffer *rb)
{
    return rb->buffer_size;
}

RINGBUFFER_STATE rt_ringbuffer_status(struct rt_ringbuffer *rb)
{
    if (rb->read_index == rb->write_index)
    {
        if (rb->read_mirror == rb->write_mirror)
            return RT_RINGBUFFER_EMPTY;
        else
            return RT_RINGBUFFER_FULL;
    }
    return RT_RINGBUFFER_HALFFULL;
}

/** return the size of data in rb */
uint16_t rt_ringbuffer_data_len(struct rt_ringbuffer *rb)
{
    switch (rt_ringbuffer_status(rb))
    {
    case RT_RINGBUFFER_EMPTY:
        return 0;
    case RT_RINGBUFFER_FULL:
        return rb->buffer_size;
    case RT_RINGBUFFER_HALFFULL:
    default:
        if (rb->write_index > rb->read_index)
            return rb->write_index - rb->read_index;
        else
            return rb->buffer_size - (rb->read_index - rb->write_index);
    };
}


/** return the size of empty space in rb */
#define rt_ringbuffer_space_len(rb) ((rb)->buffer_size - rt_ringbuffer_data_len(rb))

void rt_ringbuffer_init(struct rt_ringbuffer *rb,
                        uint8_t           *pool,
                        int16_t            size,
                        ringbuffer_type_t ringbuffer_type)
{
    /* initialize read and write index */
    rb->read_mirror = rb->read_index = 0;
    rb->write_mirror = rb->write_index = 0;

    /* set buffer pool and size */
    rb->buffer_ptr = pool;
    rb->buffer_size = RT_ALIGN_DOWN(size, RT_ALIGN_SIZE);

    rb->ringbuffer_type = ringbuffer_type;
    pthread_mutex_init(&(rb->ringbuf_lock), NULL);
    if(BLOCK_TYPE == rb->ringbuffer_type)
    {
        pthread_cond_init(&rb->notfull, NULL);
        pthread_cond_init(&rb->notempty, NULL);
    }
}

void rt_ringbuffer_lock_destory(struct rt_ringbuffer *rb)
{
    pthread_mutex_destroy(&(rb->ringbuf_lock));
    if(BLOCK_TYPE == rb->ringbuffer_type)
    {
        pthread_cond_destroy(&rb->notfull);
        pthread_cond_destroy(&rb->notempty);
    }
}
/**
 * put a block of data into ring buffer
 */
uint32_t rt_ringbuffer_put(struct rt_ringbuffer *rb,
                           const uint8_t     *ptr,
                           uint16_t           length)
{
    uint16_t size;

    /* whether has enough space */

    pthread_mutex_lock(&rb->ringbuf_lock);
    size = rt_ringbuffer_space_len(rb);

    if(POLL_TYPE == rb->ringbuffer_type)
    {
        /* no space */
        if (size == 0)
        {
            pthread_mutex_unlock(&rb->ringbuf_lock);
            return 0;
        }

        /* drop some data */
        if (size < length)
            length = size;
    }else if(BLOCK_TYPE == rb->ringbuffer_type)
    {
        while(size < length)
        {
            pthread_cond_wait(&rb->notfull, &rb->ringbuf_lock);
            size = rt_ringbuffer_space_len(rb);
        }
    }

    if (rb->buffer_size - rb->write_index > length)
    {
        /* read_index - write_index = empty space */
        memcpy(&rb->buffer_ptr[rb->write_index], ptr, length);
        /* this should not cause overflow because there is enough space for
         * length of data in current mirror */
        rb->write_index += length;
        pthread_cond_signal(&rb->notempty);
        pthread_mutex_unlock(&rb->ringbuf_lock);
        return length;
    }

    memcpy(&rb->buffer_ptr[rb->write_index],
           &ptr[0],
           rb->buffer_size - rb->write_index);
    memcpy(&rb->buffer_ptr[0],
           &ptr[rb->buffer_size - rb->write_index],
           length - (rb->buffer_size - rb->write_index));

    /* we are going into the other side of the mirror */
    rb->write_mirror = ~rb->write_mirror;
    rb->write_index = length - (rb->buffer_size - rb->write_index);

    pthread_cond_signal(&rb->notempty);
    pthread_mutex_unlock(&rb->ringbuf_lock);

    return length;
}

uint32_t rt_ringbuffer_put_force(struct rt_ringbuffer *rb,
                                 const uint8_t     *ptr,
                                 uint16_t           length)
{
    uint16_t space_length;
    pthread_mutex_lock(&rb->ringbuf_lock);

    space_length = rt_ringbuffer_space_len(rb);

    if (length > space_length)
        length = rb->buffer_size;

    if (rb->buffer_size - rb->write_index > length)
    {
        /* read_index - write_index = empty space */
        memcpy(&rb->buffer_ptr[rb->write_index], ptr, length);
        /* this should not cause overflow because there is enough space for
         * length of data in current mirror */
        rb->write_index += length;

        if (length > space_length)
            rb->read_index = rb->write_index;

        pthread_cond_signal(&rb->notempty);
        pthread_mutex_unlock(&rb->ringbuf_lock);
        return length;
    }

    memcpy(&rb->buffer_ptr[rb->write_index],
           &ptr[0],
           rb->buffer_size - rb->write_index);
    memcpy(&rb->buffer_ptr[0],
           &ptr[rb->buffer_size - rb->write_index],
           length - (rb->buffer_size - rb->write_index));

    /* we are going into the other side of the mirror */
    rb->write_mirror = ~rb->write_mirror;
    rb->write_index = length - (rb->buffer_size - rb->write_index);

    if (length > space_length)
    {
        rb->read_mirror = ~rb->read_mirror;
        rb->read_index = rb->write_index;
    }

    pthread_cond_signal(&rb->notempty);
    pthread_mutex_unlock(&rb->ringbuf_lock);
    return length;
}

/**
 *  get data from ring buffer
 */
uint32_t rt_ringbuffer_get(struct rt_ringbuffer *rb,
                           uint8_t           *ptr,
                           uint16_t          length)
{
    uint32_t size;
    pthread_mutex_lock(&rb->ringbuf_lock);

    //dbg_print(PRINT_LEVEL_INFO,"write idx = %d, read idx = %d\n",rb->write_index, rb->read_index);
    /* whether has enough data  */
    size = rt_ringbuffer_data_len(rb);

    if(POLL_TYPE == rb->ringbuffer_type)
    {
        /* no data */
        if (size == 0)
        {
            pthread_mutex_unlock(&rb->ringbuf_lock);
            return 0;
        }

        /* less data */
        if (size < length)
            length = size;
    }else if(BLOCK_TYPE == rb->ringbuffer_type)
    {
        while(size < length)
        {
            pthread_cond_wait(&rb->notempty, &rb->ringbuf_lock);
            size = rt_ringbuffer_data_len(rb);
        }
    }

    if (rb->buffer_size - rb->read_index > length)
    {
        /* copy all of data */
        memcpy(ptr, &rb->buffer_ptr[rb->read_index], length);
        /* this should not cause overflow because there is enough space for
         * length of data in current mirror */
        rb->read_index += length;
        pthread_mutex_unlock(&rb->ringbuf_lock);
        pthread_cond_signal(&rb->notfull);
        return length;
    }

    memcpy(&ptr[0],
           &rb->buffer_ptr[rb->read_index],
           rb->buffer_size - rb->read_index);
    memcpy(&ptr[rb->buffer_size - rb->read_index],
           &rb->buffer_ptr[0],
           length - (rb->buffer_size - rb->read_index));

    /* we are going into the other side of the mirror */
    rb->read_mirror = ~rb->read_mirror;
    rb->read_index = length - (rb->buffer_size - rb->read_index);
    pthread_cond_signal(&rb->notfull);
    pthread_mutex_unlock(&rb->ringbuf_lock);
    return length;
}

/**
 *  get data from ring buffer
 */
uint32_t rt_ringbuffer_prefetch(struct rt_ringbuffer *rb,
                                 uint8_t           *ptr,
                                 uint16_t          length)
{
    uint32_t size;

    /* whether has enough data  */
    size = rt_ringbuffer_data_len(rb);

    /* no data */
    if (size == 0)
        return 0;

    /* less data */
    if (size < length)
        length = size;

    if (rb->buffer_size - rb->read_index > length)
    {
        /* copy all of data */
        memcpy(ptr, &rb->buffer_ptr[rb->read_index], length);
        return length;
    }
    
    memcpy(&ptr[0],
           &rb->buffer_ptr[rb->read_index],
           rb->buffer_size - rb->read_index);
    memcpy(&ptr[rb->buffer_size - rb->read_index],
           &rb->buffer_ptr[0],
           length - (rb->buffer_size - rb->read_index));

    return length;
}


