#ifndef NF_RING_QUEUE_SLOT
#define NF_RING_QUEUE_SLOT

#ifdef __KERNEL__
    #include <linux/shm.h>
    #include <linux/types.h>
    #include <linux/vmalloc.h>
#else
    #include <stdint.h>
    #include <stdlib.h>
    #include <unistd.h>
#endif

#ifndef ALIGN
    #define ALIGN(x, a)           __ALIGN_MASK((x), (__typeof__(x))(a)-1)
    #define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#endif

#ifndef PAGE_ALIGN
    #ifdef __KERNEL__
        #define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
    #else
        #define PAGE_ALIGN(addr) ALIGN(addr, getpagesize())
    #endif
#endif

#define QUEUE_MAGIC_VALUE 0x88

enum QUEUE_SLOT_STATUS {
    QUEUE_STATUS_UNINIT = 0, // 未初始化
    QUEUE_STATUS_READY = 1,  // 就绪
    QUEUE_STATUS_DELETE = 2, // 删除中
};

typedef struct queue_slot_header {
    volatile uint64_t locker;     // 锁地址 // 8 bytes
    volatile uint32_t status;     // QUEUE_SLOT_STATUS // 12 bytes
    uint32_t min_num_slots;       // slot的最小个数 // 16 bytes
    uint32_t data_max_len;        // 每个元素数据的最大长度 // 20 bytes
    uint32_t slot_max_len;        // 每个元素 slot 的最大长度 // 28 bytes
    uint64_t tot_mem;             // 整个队列内存，包括 queue_arr_header_t // 32 bytes
    volatile uint32_t front_off;  // 队列头偏移 // 36 bytes
    volatile uint32_t tail_off;   // 队列尾偏移 // 40 bytes
    volatile uint64_t tot_insert; // 插入个数 // 48 bytes
    volatile uint64_t tot_read;   // 读取个数 // 56 bytes
    char padding[4096 - 56];      // 4096 - 56 bytes
} queue_slot_header_t;

typedef struct queue_data_header {
    uint32_t slot_len;
    uint32_t data_len;
} queue_data_header_t;

static inline uint32_t queue_get_slot_size(uint32_t data_len)
{
    return ALIGN(sizeof(queue_data_header_t) + data_len + sizeof(uint16_t), sizeof(u_int64_t));
}

static inline uint32_t queue_get_next_off(queue_slot_header_t *q, uint32_t off, uint32_t data_len)
{
    uint32_t slot_size = queue_get_slot_size(data_len);

    if (q->tot_mem - (off + slot_size) < q->slot_max_len) {
        return 0;
    }
    return off + slot_size;
}

static inline uint8_t *queue_slot_get(queue_slot_header_t *q, uint32_t off)
{
    u_char *ring_slots = (u_char *)((uint8_t *)q + sizeof(queue_slot_header_t));
    return (&(ring_slots[off]));
}

static inline uint8_t *queue_front(queue_slot_header_t *q)
{
    return queue_slot_get(q, q->front_off);
}

static inline uint32_t queue_size(queue_slot_header_t *q)
{
    return (q->tot_insert - q->tot_read);
}

static inline int queue_is_empty(queue_slot_header_t *q)
{
    return (!queue_size(q));
}

// 目前分配内存的操作只在内核中做
#ifdef __KERNEL__
static inline uint64_t queue_total_mem(uint32_t data_max_len, uint32_t min_num_slots)
{
    uint64_t tot_mem;
    uint32_t the_slot_len;
    the_slot_len = queue_get_slot_size(data_max_len);
    tot_mem = sizeof(queue_slot_header_t) + (min_num_slots * the_slot_len);
    tot_mem = PAGE_ALIGN(tot_mem);
    tot_mem += SHMLBA - (tot_mem % SHMLBA);
    return tot_mem;
}

static inline void queue_slot_init_mem(queue_slot_header_t *q, uint32_t data_max_len,
                                       uint32_t min_num_slots)
{
    uint64_t tot_mem;
    uint32_t the_slot_len;

    the_slot_len = queue_get_slot_size(data_max_len);
    tot_mem = queue_total_mem(data_max_len, min_num_slots);

    q->locker = (uint64_t)vmalloc(sizeof(rwlock_t));
    rwlock_init((rwlock_t *)q->locker);

    q->status = QUEUE_STATUS_READY;
    q->min_num_slots = min_num_slots;
    q->data_max_len = data_max_len;
    q->slot_max_len = the_slot_len;
    q->front_off = 0;
    q->tail_off = 0;
    q->tot_insert = 0;
    q->tot_read = 0;
    q->tot_mem = tot_mem;
}

/* **********************************************
 *
 * *************************************
 * *                                   *
 * *        queue_slot_header_t        *
 * *                                   *
 * ************************************************* <-+
 * *        queue_data_header_t + data + magic        *|
 * ************************************************    |
 * *        queue_data_header_t + data + magic        *|
 * ************************************************   +- >= min_num_slots
 * *        queue_data_header_t + data + magic        *|
 * ************************************************    |
 * *        queue_data_header_t + data + magic        *|
 * ************************************************* <-+
 *
 * **********************************************
 */
static inline queue_slot_header_t *queue_slot_alloc_mem(uint32_t data_max_len,
                                                        uint32_t min_num_slots)
{
    uint64_t tot_mem;
    queue_slot_header_t *header;

    tot_mem = queue_total_mem(data_max_len, min_num_slots);
    header = (queue_slot_header_t *)vmalloc_user(tot_mem);

    queue_slot_init_mem(header, data_max_len, min_num_slots);

    return header;
}

static inline void queue_slot_destroy(queue_slot_header_t *q)
{
    write_lock_bh((rwlock_t *)q->locker);
    q->status = QUEUE_STATUS_DELETE;
    q->tot_insert = 0;
    q->tot_read = 0;
    write_unlock_bh((rwlock_t *)q->locker);
    vfree((void *)q->locker);
    vfree((void *)q);
}
#endif

static inline int queue_slot_is_full(queue_slot_header_t *q)
{
    if (q->front_off == q->tail_off) {
        return 0;
    } else if (q->front_off < q->tail_off) {
        if (q->tot_mem - q->tail_off > q->slot_max_len) {
            return 0;
        } else if (q->front_off > q->slot_max_len) {
            return 0;
        }
        return 1;
    } else {
        if (q->front_off - q->tail_off > q->slot_max_len) {
            return 0;
        } else {
            return 1;
        }
    }
    return 0;
}

#endif /* NF_RING_QUEUE_SLOT */
